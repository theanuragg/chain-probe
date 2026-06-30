use crate::types::{AnalysisReport, Severity};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    invocations: Vec<SarifInvocation>,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
    extensions: Vec<SarifExtension>,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    semantic_version: String,
    information_uri: String,
    rules: Vec<SarifRule>,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifConfiguration,
    help_uri: Option<String>,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    rule_id: String,
    rule_index: usize,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    partial_fingerprints: HashMap<String, String>,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    start_line: usize,
    snippet: Option<SarifSnippet>,
}

#[derive(Serialize)]
struct SarifSnippet {
    text: String,
}

#[derive(Serialize)]
struct SarifInvocation {
    execution_successful: bool,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifExtension {
    name: String,
    semantic_version: String,
    information_uri: String,
}

const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "ChainProbe";
const TOOL_VERSION: &str = "4.0.0";
const INFO_URI: &str = "https://github.com/theanuragg/chain-probe";

fn severity_to_sarif_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "note",
    }
}

pub fn report_to_sarif(report: &AnalysisReport) -> String {
    let mut rules_map: HashMap<String, usize> = HashMap::new();
    let mut rules: Vec<SarifRule> = vec![];
    let mut results: Vec<SarifResult> = vec![];

    for finding in &report.findings {
        let rule_id = format!("CP-{}", finding.cwe.replace("CWE-", ""));
        let rule_idx = *rules_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rules.len();
            rules.push(SarifRule {
                id: rule_id.clone(),
                name: finding.category.key().to_string(),
                short_description: SarifMessage {
                    text: finding.title.clone(),
                },
                full_description: SarifMessage {
                    text: format!("{}\n\nRecommendation: {}", finding.description, finding.recommendation),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&finding.severity),
                },
                help_uri: Some(format!("{}/security/{}", INFO_URI, finding.category.key())),
                properties: serde_json::json!({
                    "security-severity": match finding.severity {
                        Severity::Critical => "9.5",
                        Severity::High => "7.5",
                        Severity::Medium => "5.5",
                        Severity::Low => "3.5",
                        Severity::Info => "1.0",
                    },
                    "tags": ["security", "solana", finding.category.key()],
                }),
            });
            idx
        });

        let location = finding.file.clone();
        let line = finding.line.unwrap_or(1);

        let mut fingerprints = HashMap::new();
        fingerprints.insert(
            "matchId".into(),
            format!("{}/{}", finding.id, finding.file),
        );
        fingerprints.insert("artifactUri".into(), finding.file.clone());

        results.push(SarifResult {
            rule_id: rule_id.clone(),
            rule_index: rule_idx,
            level: severity_to_sarif_level(&finding.severity),
            message: SarifMessage {
                text: format!("{} - {}", finding.title, finding.description),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: location,
                    },
                    region: SarifRegion {
                        start_line: line,
                        snippet: if !finding.snippet.is_empty() {
                            Some(SarifSnippet { text: finding.snippet.clone() })
                        } else {
                            None
                        },
                    },
                },
            }],
            partial_fingerprints: fingerprints,
            properties: serde_json::json!({
                "exploitability": finding.exploitability,
                "confirmed_by_taint": finding.confirmed_by_taint,
                "category": finding.category.key(),
            }),
        });
    }

    let sarif = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: TOOL_NAME.into(),
                    semantic_version: TOOL_VERSION.into(),
                    information_uri: INFO_URI.into(),
                    rules,
                    properties: serde_json::json!({
                        "analysis": {
                            "security_score": report.summary.security_score,
                            "attack_surface_score": report.summary.attack_surface_score,
                            "overall_risk": report.summary.overall_risk,
                            "total_findings": report.summary.total,
                            "framework": report.profile.framework.as_str(),
                        }
                    }),
                },
                extensions: vec![SarifExtension {
                    name: "ChainProbe Solana Rules".into(),
                    semantic_version: TOOL_VERSION.into(),
                    information_uri: format!("{}/rules", INFO_URI),
                }],
            },
            results,
            invocations: vec![SarifInvocation {
                execution_successful: true,
                properties: serde_json::json!({
                    "analyzed_at": report.analyzed_at.to_rfc3339(),
                    "program_name": report.profile.program_name,
                    "files_analyzed": report.profile.files_analyzed,
                }),
            }],
            properties: serde_json::json!({
                "program_profile": {
                    "name": report.profile.program_name,
                    "framework": report.profile.framework.as_str(),
                    "complexity": report.profile.complexity,
                    "instructions": report.profile.instructions_count,
                    "cpi_calls": report.profile.cpi_calls_count,
                }
            }),
        }],
    };

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}

/// Convert a Severity to a numeric CVSS-like score for SARIF
pub fn severity_to_cvss(s: &Severity) -> f64 {
    match s {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.5,
        Severity::Low => 3.5,
        Severity::Info => 1.0,
    }
}
