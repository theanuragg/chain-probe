// backend/src/diff.rs
// Compares two AnalysisReports and produces a structured DiffReport.
// Used by: CLI --compare-to flag, POST /api/diff endpoint.
//
// Matching strategy:
//   Findings matched by: category + function + file (NOT by generated ID,
//   which changes every run). This is the stable identity of a finding.
//   If two findings share those three fields, they are the "same" finding.
//
// Status categories:
//   fixed      — in baseline, not in current
//   new        — in current, not in baseline
//   regressed  — same finding, severity is worse in current
//   improved   — same finding, severity is better in current
//   unchanged  — same finding, same severity
//
// Also diffs: chains (resolved vs new), invariants (fixed vs new bypassable),
// token flow anomalies (resolved vs new), permission entries (fixed vs broken).

use serde::{Deserialize, Serialize};
use crate::types::{
    AnalysisReport, Finding, PermissionEntry, ProgramInvariant,
    Severity, TokenFlowAnomaly, VulnChain,
};

//   DiffReport                                 

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffReport {
    pub baseline_id: String,
    pub current_id: String,
    pub baseline_program: String,
    pub current_program: String,

    // Score delta
    pub score_before: u32,
    pub score_after: u32,
    pub score_delta: i32,  // positive = improved, negative = regressed
    pub risk_before: String,
    pub risk_after: String,

    // Finding changes
    pub findings_fixed: Vec<DiffFinding>,
    pub findings_new: Vec<DiffFinding>,
    pub findings_regressed: Vec<DiffFinding>,
    pub findings_improved: Vec<DiffFinding>,
    pub findings_unchanged: usize,

    // Chain changes
    pub chains_resolved: Vec<String>,
    pub chains_new: Vec<DiffChain>,

    // Invariant changes
    pub invariants_fixed: Vec<String>,
    pub invariants_newly_bypassable: Vec<DiffInvariant>,

    // Token flow changes
    pub anomalies_resolved: Vec<String>,
    pub anomalies_new: Vec<DiffAnomaly>,

    // Permission changes
    pub permissions_fixed: Vec<String>,
    pub permissions_newly_broken: Vec<DiffPermission>,

    // Summary
    pub summary: DiffSummary,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffFinding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub function: String,
    pub file: String,
    pub severity_before: Option<String>,
    pub severity_after: Option<String>,
    pub change: DiffChange,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum DiffChange {
    Fixed,
    New,
    Regressed,
    Improved,
    Unchanged,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffChain {
    pub id: String,
    pub title: String,
    pub severity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffInvariant {
    pub id: String,
    pub condition: String,
    pub instruction: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffAnomaly {
    pub id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffPermission {
    pub id: String,
    pub instruction: String,
    pub operation: String,
    pub status: String,
    pub evidence: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffSummary {
    pub total_fixed: usize,
    pub total_new: usize,
    pub total_regressed: usize,
    pub total_improved: usize,
    pub net_change: i32,   // new - fixed (positive = getting worse)
    pub verdict: DiffVerdict,
    pub verdict_reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum DiffVerdict {
    Improved,
    Neutral,
    Regressed,
    CriticalRegression,
}

//   Main diff function                             

pub fn diff_reports(baseline: &AnalysisReport, current: &AnalysisReport) -> DiffReport {
    //   Finding diff                              
    let finding_diffs = diff_findings(&baseline.findings, &current.findings);

    let findings_fixed: Vec<DiffFinding> = finding_diffs.iter()
        .filter(|d| matches!(d.change, DiffChange::Fixed))
        .cloned().collect();
    let findings_new: Vec<DiffFinding> = finding_diffs.iter()
        .filter(|d| matches!(d.change, DiffChange::New))
        .cloned().collect();
    let findings_regressed: Vec<DiffFinding> = finding_diffs.iter()
        .filter(|d| matches!(d.change, DiffChange::Regressed))
        .cloned().collect();
    let findings_improved: Vec<DiffFinding> = finding_diffs.iter()
        .filter(|d| matches!(d.change, DiffChange::Improved))
        .cloned().collect();
    let findings_unchanged = finding_diffs.iter()
        .filter(|d| matches!(d.change, DiffChange::Unchanged))
        .count();

    //   Chain diff                               
    let chains_resolved: Vec<String> = baseline.vuln_chains.iter()
        .filter(|bc| !current.vuln_chains.iter().any(|cc| chain_matches(bc, cc)))
        .map(|c| c.title.clone())
        .collect();

    let chains_new: Vec<DiffChain> = current.vuln_chains.iter()
        .filter(|cc| !baseline.vuln_chains.iter().any(|bc| chain_matches(cc, bc)))
        .map(|c| DiffChain {
            id: c.id.clone(),
            title: c.title.clone(),
            severity: format!("{:?}", c.severity),
        })
        .collect();

    //   Invariant diff                             
    let invariants_fixed: Vec<String> = baseline.invariants.iter()
        .filter(|bi| bi.status != crate::types::InvariantStatus::Holds)
        .filter(|bi| !current.invariants.iter().any(|ci| {
            invariant_matches(bi, ci) && ci.status != crate::types::InvariantStatus::Holds
        }))
        .map(|i| i.condition.clone())
        .collect();

    let invariants_newly_bypassable: Vec<DiffInvariant> = current.invariants.iter()
        .filter(|ci| ci.status != crate::types::InvariantStatus::Holds)
        .filter(|ci| !baseline.invariants.iter().any(|bi| {
            invariant_matches(ci, bi) && bi.status != crate::types::InvariantStatus::Holds
        }))
        .map(|i| DiffInvariant {
            id: i.id.clone(),
            condition: i.condition.clone(),
            instruction: i.instruction.clone(),
            status: format!("{:?}", i.status),
        })
        .collect();

    //   Token flow anomaly diff                        ─
    let anomalies_resolved: Vec<String> = baseline.token_flow.anomalies.iter()
        .filter(|ba| !current.token_flow.anomalies.iter().any(|ca| ca.anomaly_type == ba.anomaly_type))
        .map(|a| a.anomaly_type.clone())
        .collect();

    let anomalies_new: Vec<DiffAnomaly> = current.token_flow.anomalies.iter()
        .filter(|ca| !baseline.token_flow.anomalies.iter().any(|ba| ba.anomaly_type == ca.anomaly_type))
        .map(|a| DiffAnomaly {
            id: a.id.clone(),
            anomaly_type: a.anomaly_type.clone(),
            severity: a.severity.clone(),
            description: a.description.clone(),
        })
        .collect();

    //   Permission diff                            ─
    let permissions_fixed: Vec<String> = baseline.permission_matrix.entries.iter()
        .filter(|be| matches!(be.status,
            crate::types::PermissionStatus::IntendedButBroken |
            crate::types::PermissionStatus::Missing))
        .filter(|be| current.permission_matrix.entries.iter().any(|ce| {
            permission_matches(be, ce)
                && ce.status == crate::types::PermissionStatus::Allowed
        }))
        .map(|e| format!("{} → {:?}", e.instruction, e.operation))
        .collect();

    let permissions_newly_broken: Vec<DiffPermission> = current.permission_matrix.entries.iter()
        .filter(|ce| matches!(ce.status,
            crate::types::PermissionStatus::IntendedButBroken |
            crate::types::PermissionStatus::Missing))
        .filter(|ce| !baseline.permission_matrix.entries.iter().any(|be| {
            permission_matches(ce, be)
                && matches!(be.status,
                    crate::types::PermissionStatus::IntendedButBroken |
                    crate::types::PermissionStatus::Missing)
        }))
        .map(|e| DiffPermission {
            id: e.id.clone(),
            instruction: e.instruction.clone(),
            operation: format!("{:?}", e.operation),
            status: format!("{:?}", e.status),
            evidence: e.evidence.clone(),
        })
        .collect();

    //   Score delta                              ─
    let score_before = baseline.summary.security_score;
    let score_after  = current.summary.security_score;
    let score_delta  = score_after as i32 - score_before as i32;

    //   Summary + verdict                           ─
    let total_fixed     = findings_fixed.len();
    let total_new       = findings_new.len();
    let total_regressed = findings_regressed.len();
    let total_improved  = findings_improved.len();
    let net_change      = total_new as i32 - total_fixed as i32;

    let has_new_critical = findings_new.iter()
        .any(|f| f.severity_after.as_deref() == Some("CRITICAL"));
    let has_regression = !findings_regressed.is_empty()
        || !chains_new.is_empty()
        || !permissions_newly_broken.is_empty();

    let (verdict, verdict_reason) = if has_new_critical || score_delta <= -20 {
        (DiffVerdict::CriticalRegression,
         format!("Score dropped by {} points{}",
             score_delta.abs(),
             if has_new_critical { " and new CRITICAL findings introduced" } else { "" }))
    } else if has_regression || score_delta < -5 {
        (DiffVerdict::Regressed,
         format!("{} new findings, {} regressed, score {}",
             total_new, total_regressed,
             if score_delta < 0 { format!("↓{}", score_delta.abs()) }
             else { format!("↑{}", score_delta) }))
    } else if total_fixed > total_new && score_delta >= 0 {
        (DiffVerdict::Improved,
         format!("{} findings fixed, {} new, score ↑{}",
             total_fixed, total_new, score_delta))
    } else {
        (DiffVerdict::Neutral,
         format!("{} fixed, {} new, score delta {}",
             total_fixed, total_new, score_delta))
    };

    DiffReport {
        baseline_id: baseline.id.clone(),
        current_id: current.id.clone(),
        baseline_program: baseline.profile.program_name.clone(),
        current_program: current.profile.program_name.clone(),
        score_before,
        score_after,
        score_delta,
        risk_before: baseline.summary.overall_risk.clone(),
        risk_after: current.summary.overall_risk.clone(),
        findings_fixed,
        findings_new,
        findings_regressed,
        findings_improved,
        findings_unchanged,
        chains_resolved,
        chains_new,
        invariants_fixed,
        invariants_newly_bypassable,
        anomalies_resolved,
        anomalies_new,
        permissions_fixed,
        permissions_newly_broken,
        summary: DiffSummary {
            total_fixed,
            total_new,
            total_regressed,
            total_improved,
            net_change,
            verdict,
            verdict_reason,
        },
    }
}

//   Finding diff logic                             

fn diff_findings(baseline: &[Finding], current: &[Finding]) -> Vec<DiffFinding> {
    let mut diffs = vec![];

    // Check every baseline finding for matches in current
    for bf in baseline {
        match current.iter().find(|cf| finding_matches(bf, cf)) {
            None => {
                // In baseline but not current → fixed
                diffs.push(DiffFinding {
                    id: bf.id.clone(),
                    title: bf.title.clone(),
                    category: bf.category.key().to_string(),
                    function: bf.function.clone(),
                    file: bf.file.clone(),
                    severity_before: Some(format!("{:?}", bf.severity)),
                    severity_after: None,
                    change: DiffChange::Fixed,
                });
            }
            Some(cf) => {
                let change = compare_severity(&bf.severity, &cf.severity);
                diffs.push(DiffFinding {
                    id: cf.id.clone(),
                    title: cf.title.clone(),
                    category: cf.category.key().to_string(),
                    function: cf.function.clone(),
                    file: cf.file.clone(),
                    severity_before: Some(format!("{:?}", bf.severity)),
                    severity_after: Some(format!("{:?}", cf.severity)),
                    change,
                });
            }
        }
    }

    // Check for new findings (in current but not baseline)
    for cf in current {
        if !baseline.iter().any(|bf| finding_matches(bf, cf)) {
            diffs.push(DiffFinding {
                id: cf.id.clone(),
                title: cf.title.clone(),
                category: cf.category.key().to_string(),
                function: cf.function.clone(),
                file: cf.file.clone(),
                severity_before: None,
                severity_after: Some(format!("{:?}", cf.severity)),
                change: DiffChange::New,
            });
        }
    }

    // Sort: regressions first, then new, then fixed, then improved, then unchanged
    diffs.sort_by_key(|d| match d.change {
        DiffChange::Regressed  => 0,
        DiffChange::New        => 1,
        DiffChange::Fixed      => 2,
        DiffChange::Improved   => 3,
        DiffChange::Unchanged  => 4,
    });

    diffs
}

//   Matching predicates                            ─
// Stable identity = category + function + file (not the generated ID)

fn finding_matches(a: &Finding, b: &Finding) -> bool {
    a.category.key() == b.category.key()
        && a.function == b.function
        && filename(&a.file) == filename(&b.file)
}

fn chain_matches(a: &VulnChain, b: &VulnChain) -> bool {
    // Chains matched by title prefix (IDs are regenerated every run)
    a.title.len() > 20
        && b.title.len() > 20
        && a.title[..20] == b.title[..20]
}

fn invariant_matches(a: &ProgramInvariant, b: &ProgramInvariant) -> bool {
    a.instruction == b.instruction
        && a.condition.trim() == b.condition.trim()
}

fn permission_matches(a: &PermissionEntry, b: &PermissionEntry) -> bool {
    a.instruction == b.instruction
        && format!("{:?}", a.operation) == format!("{:?}", b.operation)
}

fn filename(path: &str) -> &str {
    path.split('/').last().unwrap_or(path)
}

fn compare_severity(before: &Severity, after: &Severity) -> DiffChange {
    use std::cmp::Ordering;
    match before.cmp(after) {
        Ordering::Equal   => DiffChange::Unchanged,
        Ordering::Less    => DiffChange::Regressed,  // Severity enum: Critical < High < Medium...
        Ordering::Greater => DiffChange::Improved,
    }
}
