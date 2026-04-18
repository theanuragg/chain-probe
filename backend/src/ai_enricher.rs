// Uses Groq API (free) for semantic enrichment.
// Falls back gracefully when no API key is provided.

use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use crate::types::{AiContext, AiEnrichmentResponse, AiFindingEnrichment, AiChainEnrichment, AnalysisReport};

const GROQ_API: &str = "https://api.groq.com/openai/v1/chat/completions";
const MODEL: &str = "llama-3.1-70b-versatile";

pub struct AiEnricher {
    client: Client,
    api_key: String,
}

impl AiEnricher {
    pub fn new(api_key: String) -> Self {
        AiEnricher { client: Client::new(), api_key }
    }

    pub async fn enrich(
        &self,
        report: &AnalysisReport,
        ai_context: &AiContext,
    ) -> Result<AiEnrichmentResponse> {
        let has_findings = !ai_context.findings_needing_ai.is_empty();
        let has_chains = !ai_context.chain_ids_needing_ai.is_empty();

        if !has_findings && !has_chains {
            return Ok(AiEnrichmentResponse {
                findings: vec![],
                chains: vec![],
                program_notes: vec![],
            });
        }

        let prompt = self.build_prompt(report, ai_context);
        let body = json!({
            "model": MODEL,
            "max_tokens": 2048,
            "temperature": 0.3,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": prompt }
            ]
        });

        let res = self.client
            .post(GROQ_API)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("Groq API error {}: {}", status, text);
        }

        let data: Value = res.json().await?;
        let text = data["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        self.parse_response(&text)
    }

    fn build_prompt(&self, report: &AnalysisReport, ai_context: &AiContext) -> String {
        let findings_section = if ai_context.findings_needing_ai.is_empty() {
            "None — all findings are fully deterministic.".to_string()
        } else {
            report.findings.iter()
                .filter(|f| ai_context.findings_needing_ai.contains(&f.id))
                .map(|f| format!(
                    "ID: {}\nTitle: {}\nCategory: {:?}\nSeverity (static): {:?}\n\
                    Description: {}\nCode:\n{}\n",
                    f.id, f.title, f.category, f.severity, f.description, f.snippet
                ))
                .collect::<Vec<_>>()
                .join("\n---\n")
        };

        let chains_section = if ai_context.chain_ids_needing_ai.is_empty() {
            "None.".to_string()
        } else {
            report.vuln_chains.iter()
                .filter(|c| ai_context.chain_ids_needing_ai.contains(&c.id))
                .map(|c| format!(
                    "Chain ID: {}\nSeverity: {:?}\nTitle: {}\nComponent findings: {}\n\
                    Exploit steps:\n{}\n",
                    c.id,
                    c.severity,
                    c.title,
                    c.finding_ids.join(", "),
                    c.exploit_steps.iter().enumerate()
                        .map(|(i, s)| format!("  {}. {}", i + 1, s))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
                .collect::<Vec<_>>()
                .join("\n---\n")
        };

        let notes = ai_context.business_logic_notes.join("\n");
        let source = ai_context.source_bundle.as_deref().unwrap_or("");

        format!(
            r#"## Program: {}
Anchor version: {} | Files: {} | Lines: {} | Complexity: {}

## Individual findings needing semantic context
{}

## Vulnerability chains to validate
For each chain, confirm whether the exploit path is realistic in THIS specific program.
A chain is unrealistic if business logic elsewhere prevents it — explain why.
{}

## Business logic notes
{}

## Relevant code snippets
```rust
{}
```

## Response format — reply ONLY with valid JSON
```json
{{
  "findings": [
    {{
      "id": "CP-001",
      "explanation": "2-3 sentence context-specific explanation for THIS program",
      "severity_override": null
    }}
  ],
  "chains": [
    {{
      "id": "CHAIN-01",
      "explanation": "is this chain realistic and why, specific to this codebase",
      "realistic": true
    }}
  ],
  "program_notes": []
}}
```

Rules:
- findings[] must only include IDs from the request above
- chains[] must only include IDs from the request above
- severity_override must be null or CRITICAL/HIGH/MEDIUM/LOW/INFO — only set if clearly wrong
- explanation must be specific to THIS program's business logic, never generic
- realistic=false only if you can cite specific code that prevents the chain"#,
            report.profile.program_name,
            report.profile.anchor_version,
            report.profile.files_analyzed,
            report.profile.total_lines,
            report.profile.complexity,
            findings_section,
            chains_section,
            notes,
            source,
        )
    }

    fn parse_response(&self, text: &str) -> Result<AiEnrichmentResponse> {
        let json_str = if let Some(start) = text.find("```json") {
            let s = &text[start + 7..];
            s.find("```").map(|end| &s[..end]).unwrap_or(s)
        } else if let Some(start) = text.find('{') {
            let end = text.rfind('}').map(|e| e + 1).unwrap_or(text.len());
            &text[start..end]
        } else {
            text
        };

        let val: Value = serde_json::from_str(json_str.trim())
            .map_err(|e| anyhow::anyhow!("Failed to parse AI response JSON: {}", e))?;

        let findings = val["findings"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|f| {
                let id = f["id"].as_str()?.to_string();
                let explanation = f["explanation"].as_str()?.to_string();
                let severity_override = f["severity_override"]
                    .as_str()
                    .filter(|&s| s != "null" && !s.is_empty())
                    .map(|s| s.to_string());
                Some(AiFindingEnrichment { id, explanation, severity_override })
            })
            .collect();

        let chains = val["chains"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| {
                let id = c["id"].as_str()?.to_string();
                let explanation = c["explanation"].as_str()?.to_string();
                let realistic = c["realistic"].as_bool().unwrap_or(true);
                Some(AiChainEnrichment { id, explanation, realistic })
            })
            .collect();

        let program_notes = val["program_notes"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|n| n.as_str().map(|s| s.to_string()))
            .collect();

        Ok(AiEnrichmentResponse { findings, chains, program_notes })
    }
}

const SYSTEM_PROMPT: &str = r#"You are a senior Solana/Anchor security engineer performing final semantic review.

The Rust static analyzer has already done all pattern detection. Your ONLY job is:
1. For each finding: explain why it's dangerous in THIS specific program's business logic context
2. For each chain: confirm whether the exploit path is actually reachable in this codebase
3. Suggest severity adjustments ONLY when clearly wrong given the full context

Rules you must follow:
- Never add or remove findings
- Never rewrite static descriptions — add context they couldn't know
- Keep explanations under 3 sentences
- For chains: realistic=false only when you can point to specific code preventing the exploit
- Return only valid JSON matching the requested format exactly"#;