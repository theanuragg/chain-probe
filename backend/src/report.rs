// backend/src/report.rs — v4
// Assembles AnalysisReport by running the full 8-stage pipeline in order.
//
// Stage sequence:
//   1. trust        → TrustMap
//   2. taint        → Vec<TaintFlow>
//   3. invariant    → Vec<ProgramInvariant>
//   4. data_flow    → DataFlowGraph
//   5. call_graph   → CallGraph
//   6. chain_detector → Vec<VulnChain>
//   7. vuln_db      → Vec<KnownVuln>
//   8. scoring      → ProgramScores
//   9. assemble     → AnalysisReport

use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;

use crate::{
    ast_visitor::ProjectVisitor,
    call_graph::build_call_graph,
    chain_detector::detect_chains,
    data_flow::build_data_flow_graph,
    invariant::mine_invariants,
    permission_model::extract_permission_matrix,
    scoring::{apply_structural_penalties, compute_scores, score_finding_exploitability},
    taint::TaintEngine,
    token_flow::build_token_flow_graph,
    trust::TrustAnalyzer,
    vuln_db::check_version,
    types::{
        AiContext, AiEnrichmentResponse, AnalysisReport, CategorySummary,
        CrossFileFlow, DataFlowGraph, Finding, InputFile, InvariantStatus,
        KnownVuln, PermissionMatrix, ProgramInvariant, ProgramProfile,
        ReportSummary, Severity, TaintFlow, TokenFlowGraph, VulnChain,
    },
};

pub fn build_report(
    mut findings: Vec<Finding>,
    profile: ProgramProfile,
    visitor: &ProjectVisitor,
    files: &[InputFile],
) -> (AnalysisReport, AiContext) {

    //   Stage 1: Trust classification                     ─
    let trust_analyzer = TrustAnalyzer::new(visitor);
    let trust_map = trust_analyzer.build_trust_map();

    //   Stage 2: Taint analysis                        ─
    let taint_engine = TaintEngine::new(visitor);
    let taint_flows: Vec<TaintFlow> = taint_engine.analyze(files);

    // Link taint flows to findings — if a taint flow's sink is in the same
    // instruction and file as a finding, mark them as connected
    let taint_flows = link_taint_to_findings(taint_flows, &findings);

    // Mark findings that are taint-confirmed — escalate confidence
    for f in findings.iter_mut() {
        let confirmed: Vec<String> = taint_flows.iter()
            .filter(|tf| {
                tf.instruction == f.function || tf.sink.file == f.file
            })
            .map(|tf| tf.id.clone())
            .collect();
        f.confirmed_by_taint = confirmed;
    }

    //   Stage 3: Invariant mining                       ─
    let invariants: Vec<ProgramInvariant> = mine_invariants(visitor, files, &taint_flows);

    //   Stage 4: Data flow graph                        
    let data_flow: DataFlowGraph = build_data_flow_graph(visitor, &trust_map);

    //   Stage 5: Call graph                          ─
    let call_graph = build_call_graph(visitor, &trust_map, files);

    //   Stage 6: Per-finding exploitability scoring              ─
    for f in findings.iter_mut() {
        f.exploitability = score_finding_exploitability(f, &call_graph);
    }

    //   Stage 7: Vulnerability chains                     
    let vuln_chains: Vec<VulnChain> = detect_chains(&findings, &data_flow);

    // Escalate findings that appear in Critical chains to at least High
    let critical_chain_ids: std::collections::HashSet<String> = vuln_chains.iter()
        .filter(|c| c.severity == Severity::Critical)
        .flat_map(|c| c.finding_ids.iter().cloned())
        .collect();
    for f in findings.iter_mut() {
        if critical_chain_ids.contains(&f.id) && f.severity > Severity::High {
            f.severity = Severity::High;
        }
    }

    //   Stage 8: Known advisories                       ─
    let known_vulns: Vec<KnownVuln> = check_version(&profile.anchor_version);

    //   Stage 9: Token flow graph                       ─
    let token_flow = build_token_flow_graph(visitor, &trust_map, files);

    //   Stage 10: Permission model                       
    let permission_matrix = extract_permission_matrix(visitor, &trust_map, files);

    //   Stage 11: Program-level scoring                    
    let mut scores = compute_scores(&findings, &vuln_chains, &call_graph, visitor);

    // Apply structural penalties from token flow anomalies and broken permissions
    // These are real economic attack surfaces that pattern matching alone doesn't see
    scores.security_score = apply_structural_penalties(
        scores.security_score,
        &token_flow,
        &permission_matrix,
    );
    scores.overall_risk = match scores.security_score {
        0..=29  => "Critical",
        30..=49 => "High",
        50..=69 => "Medium",
        70..=84 => "Low",
        _       => "Minimal",
    }.to_string();

    //   Assemble category summary                       ─
    let cat_keys = [
        "account_validation", "arithmetic_overflow", "signer_authority",
        "pda_seed_collision", "reentrancy", "access_control",
    ];
    let mut category_summary: HashMap<String, CategorySummary> = cat_keys.iter()
        .map(|&k| (k.to_string(), CategorySummary { count: 0, max_severity: "NONE".into() }))
        .collect();

    let sev_rank = |s: &str| match s {
        "CRITICAL" => 5, "HIGH" => 4, "MEDIUM" => 3, "LOW" => 2, "INFO" => 1, _ => 0,
    };

    for f in &findings {
        if let Some(entry) = category_summary.get_mut(f.category.key()) {
            entry.count += 1;
            let sev = f.severity.as_str().to_string();
            if sev_rank(&sev) > sev_rank(&entry.max_severity) {
                entry.max_severity = sev;
            }
        }
    }

    //   Summary counts                             
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high     = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium   = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low      = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info     = findings.iter().filter(|f| f.severity == Severity::Info).count();

    let bypassable = invariants.iter()
        .filter(|inv| inv.status != InvariantStatus::Holds)
        .count();

    let summary = ReportSummary {
        overall_risk: scores.overall_risk.clone(),
        security_score: scores.security_score,
        attack_surface_score: scores.attack_surface_score,
        hardening_score: scores.hardening_score,
        critical, high, medium, low, info,
        total: findings.len(),
        chain_count: vuln_chains.len(),
        taint_flow_count: taint_flows.len(),
        invariant_count: invariants.len(),
        bypassable_invariant_count: bypassable,
        known_vuln_count: known_vulns.len(),
        token_flow_anomaly_count: token_flow.anomalies.len(),
        broken_permission_count: permission_matrix.broken_permission_count,
    };

    //   Build report                              
    let report = AnalysisReport {
        id: Uuid::new_v4().to_string(),
        findings,
        category_summary,
        profile,
        summary,
        analyzed_at: Utc::now(),
        data_flow,
        vuln_chains,
        known_vulns,
        taint_flows,
        invariants,
        call_graph,
        token_flow,
        permission_matrix,
    };

    //   Extract AI context                           
    // AI only gets findings and chains that require business logic reasoning.
    // Everything else is fully deterministic.
    let findings_needing_ai: Vec<String> = report.findings.iter()
        .filter(|f| f.needs_ai_context)
        .map(|f| f.id.clone())
        .collect();

    let chain_ids_needing_ai: Vec<String> = report.vuln_chains.iter()
        .filter(|c| c.needs_ai_context)
        .map(|c| c.id.clone())
        .collect();

    let mut cross_file_flows = vec![];
    for instr in &report.profile.instructions {
        if instr.file.ends_with("lib.rs") && !instr.ctx_type.is_empty() {
            cross_file_flows.push(CrossFileFlow {
                from_file: instr.file.clone(),
                to_file: format!("instructions::{}", instr.name),
                via: instr.name.clone(),
                description: format!(
                    "`{}` delegates to module impl — Anchor constraints live in the module, not lib.rs.",
                    instr.name
                ),
            });
        }
    }

    let mut notes = vec![];
    if report.profile.uses_token_2022 {
        notes.push("Program uses Token-2022 / TokenInterface. Transfer hooks execute \
            arbitrary code mid-CPI — reentrancy risk that static analysis cannot fully trace.".into());
    }
    if !report.invariants.iter().filter(|i| i.status != InvariantStatus::Holds).collect::<Vec<_>>().is_empty() {
        let bypassable: Vec<&str> = report.invariants.iter()
            .filter(|i| i.status == InvariantStatus::Bypassable || i.status == InvariantStatus::Incomplete)
            .map(|i| i.condition.as_str())
            .take(3)
            .collect();
        if !bypassable.is_empty() {
            notes.push(format!(
                "Bypassable invariants detected: [{}]. Taint analysis confirms attacker influence.",
                bypassable.join(" | ")
            ));
        }
    }

    // Send only the top 5 most exploitable finding snippets to AI
    let mut sorted_for_ai = report.findings.iter()
        .filter(|f| f.needs_ai_context)
        .collect::<Vec<_>>();
    sorted_for_ai.sort_by(|a, b| b.exploitability.cmp(&a.exploitability));

    let source_bundle: String = sorted_for_ai.iter()
        .take(5)
        .map(|f| format!("// {} — {} (exploitability: {})\n// {}\n{}", f.id, f.title, f.exploitability, f.file, f.snippet))
        .collect::<Vec<_>>()
        .join("\n\n---\n\n");

    let ai_context = AiContext {
        findings_needing_ai,
        chain_ids_needing_ai,
        cross_file_flows,
        business_logic_notes: notes,
        source_bundle: Some(source_bundle),
    };

    (report, ai_context)
}

//   Link taint flows to findings                        

fn link_taint_to_findings(
    mut flows: Vec<TaintFlow>,
    findings: &[Finding],
) -> Vec<TaintFlow> {
    for flow in flows.iter_mut() {
        // Match by instruction name and severity overlap
        for finding in findings {
            if flow.instruction == finding.function
                && flow.sink.file == finding.file
            {
                // Taint flow in same instruction/file — link it
                flow.finding_id = Some(finding.id.clone());
                break;
            }
        }
    }
    flows
}

//   Apply AI enrichment                            ─

pub fn apply_ai_enrichment(
    mut report: AnalysisReport,
    enrichment: AiEnrichmentResponse,
) -> AnalysisReport {
    for ai_f in &enrichment.findings {
        if let Some(f) = report.findings.iter_mut().find(|f| f.id == ai_f.id) {
            f.ai_explanation = Some(ai_f.explanation.clone());
            if let Some(ref sev_str) = ai_f.severity_override {
                if let Some(sev) = Severity::from_str(sev_str) {
                    f.ai_severity = Some(sev.clone());
                    if sev < f.severity { f.severity = sev; }
                }
            }
        }
    }

    for ai_c in &enrichment.chains {
        if let Some(c) = report.vuln_chains.iter_mut().find(|c| c.id == ai_c.id) {
            c.ai_explanation = Some(ai_c.explanation.clone());
            if !ai_c.realistic {
                c.severity = match &c.severity {
                    Severity::Critical => Severity::High,
                    Severity::High     => Severity::Medium,
                    Severity::Medium   => Severity::Low,
                    other              => other.clone(),
                };
            }
        }
    }

    // Recompute scores after AI adjustments
    let critical = report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high     = report.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium   = report.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low      = report.findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info     = report.findings.iter().filter(|f| f.severity == Severity::Info).count();

    let base_penalty = (critical as u32 * 20).saturating_add(high as u32 * 10)
        .saturating_add(medium as u32 * 4).saturating_add(low as u32 * 1);
    let chain_penalty: u32 = report.vuln_chains.iter()
        .map(|c| c.severity.score_penalty() / 2).sum();
    let advisory_penalty: u32 = report.known_vulns.iter()
        .map(|v| v.severity.score_penalty() / 3).sum();

    let new_score = 100u32.saturating_sub(
        (base_penalty + chain_penalty + advisory_penalty).min(100)
    );

    report.summary.security_score = new_score;
    report.summary.critical = critical;
    report.summary.high = high;
    report.summary.medium = medium;
    report.summary.low = low;
    report.summary.info = info;
    report.summary.total = report.findings.len();
    report.summary.overall_risk = match new_score {
        0..=29  => "Critical",
        30..=49 => "High",
        50..=69 => "Medium",
        70..=84 => "Low",
        _       => "Minimal",
    }.to_string();

    report
}
