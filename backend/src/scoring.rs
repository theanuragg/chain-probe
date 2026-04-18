// backend/src/scoring.rs
// Per-finding exploitability scoring and program-level security scores.
// v4: factors in taint confirmation, token flow anomalies, broken permissions.

use crate::{
    ast_visitor::ProjectVisitor,
    types::{
        CallGraph, ExploitComplexity, Finding, PermissionMatrix,
        PermissionStatus, ProgramScores, Severity, TokenFlowGraph, VulnChain,
    },
};

pub fn compute_scores(
    findings: &[Finding],
    chains: &[VulnChain],
    call_graph: &CallGraph,
    visitor: &ProjectVisitor,
) -> ProgramScores {
    let security_score = compute_security_score(findings, chains);
    let attack_surface = compute_attack_surface_score(call_graph, visitor);
    let hardening      = compute_hardening_score(visitor);
    let overall_risk   = match security_score {
        0..=29  => "Critical",
        30..=49 => "High",
        50..=69 => "Medium",
        70..=84 => "Low",
        _       => "Minimal",
    }.to_string();
    ProgramScores { security_score, attack_surface_score: attack_surface, hardening_score: hardening, overall_risk }
}

/// Call after token_flow and permission_matrix are available to apply their penalties.
pub fn apply_structural_penalties(
    base_score: u32,
    token_flow: &TokenFlowGraph,
    permission_matrix: &PermissionMatrix,
) -> u32 {
    let anomaly_penalty: u32 = token_flow.anomalies.iter().map(|a| match a.severity.as_str() {
        "CRITICAL" => 15,
        "HIGH"     => 8,
        "MEDIUM"   => 3,
        _          => 1,
    }).sum::<u32>().min(30);

    let perm_penalty: u32 = permission_matrix.entries.iter().map(|e| match e.status {
        PermissionStatus::IntendedButBroken => 12, // tried and failed = worse than forgot
        PermissionStatus::Missing           => 8,
        _                                   => 0,
    }).sum::<u32>().min(40);

    base_score.saturating_sub(anomaly_penalty).saturating_sub(perm_penalty)
}

pub fn score_finding_exploitability(finding: &Finding, call_graph: &CallGraph) -> u8 {
    let base: u32 = match finding.severity {
        Severity::Critical => 80,
        Severity::High     => 60,
        Severity::Medium   => 40,
        Severity::Low      => 20,
        Severity::Info     => 5,
    };

    let surface_bonus: u32 = call_graph.nodes.iter()
        .find(|n| n.name == finding.function)
        .map(|n| (n.attack_surface_score / 10).min(15) as u32)
        .unwrap_or(0);

    let complexity_bonus: u32 = call_graph.nodes.iter()
        .find(|n| n.name == finding.function)
        .map(|n| match n.attacker_footprint.complexity {
            ExploitComplexity::Trivial => 15,
            ExploitComplexity::Low     => 10,
            ExploitComplexity::Medium  => 5,
            ExploitComplexity::High    => 0,
        })
        .unwrap_or(5);

    // Taint-confirmed = verified exploit path, not just inferred
    let taint_bonus: u32 = if !finding.confirmed_by_taint.is_empty() { 10 } else { 0 };

    let setup_penalty: u32 = call_graph.nodes.iter()
        .find(|n| n.name == finding.function)
        .map(|n| if n.attacker_footprint.on_chain_setup { 20 } else { 0 })
        .unwrap_or(0);

    ((base + surface_bonus + complexity_bonus + taint_bonus)
        .saturating_sub(setup_penalty))
        .min(100) as u8
}

fn compute_security_score(findings: &[Finding], chains: &[VulnChain]) -> u32 {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high     = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium   = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low      = findings.iter().filter(|f| f.severity == Severity::Low).count();

    // Taint-confirmed findings are weighted heavier
    let taint_extra: u32 = findings.iter()
        .filter(|f| !f.confirmed_by_taint.is_empty())
        .map(|f| match f.severity {
            Severity::Critical => 5,
            Severity::High     => 3,
            _                  => 1,
        })
        .sum::<u32>().min(20);

    let finding_penalty = (critical as u32 * 20)
        .saturating_add(high as u32 * 10)
        .saturating_add(medium as u32 * 4)
        .saturating_add(low as u32 * 1)
        .saturating_add(taint_extra);

    let chain_penalty: u32 = chains.iter().map(|c| match c.severity {
        Severity::Critical => 15,
        Severity::High     => 8,
        Severity::Medium   => 3,
        _                  => 1,
    }).sum();

    100u32.saturating_sub((finding_penalty + chain_penalty).min(100))
}

fn compute_attack_surface_score(call_graph: &CallGraph, visitor: &ProjectVisitor) -> u32 {
    if visitor.instructions.is_empty() { return 50; }
    let total: u32 = call_graph.nodes.iter()
        .filter(|n| n.node_type == "instruction")
        .map(|n| n.attack_surface_score)
        .sum();
    (total / visitor.instructions.len() as u32).min(100)
}

fn compute_hardening_score(visitor: &ProjectVisitor) -> u32 {
    let total: u32 = visitor.account_structs.iter().map(|s| s.fields.len() as u32).sum();
    if total == 0 { return 50; }
    let hardened: u32 = visitor.account_structs.iter().flat_map(|s| s.fields.iter())
        .map(|f| {
            let mut s = 0u32;
            if f.is_signer         { s += 30; }
            if !f.seeds.is_empty() { s += 30; }
            if f.has_has_one       { s += 20; }
            if f.has_constraint    { s += 15; }
            if f.bump_stored       { s += 5;  }
            s.min(100)
        }).sum();
    let bonus = if visitor.overflow_checks_enabled { 10 } else { 0 };
    ((hardened / total) + bonus).min(100)
}
