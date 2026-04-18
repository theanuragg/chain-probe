// backend/src/bin/chainprobe_cli.rs
// TODO: ChainProbe CLI — standalone analysis for CI/CD pipelines.
// Runs the full analysis pipeline directly (no HTTP server required).
//
// Usage:
//   chainprobe-cli --project-path ./programs
//   chainprobe-cli --project-path . --min-severity MEDIUM --min-score 70
//   chainprobe-cli --project-path . --fail-on-chains --output-json report.json
//   chainprobe-cli --project-path . --compare-to baseline.json
//
// Exit codes:
//   0 — passed
//   1 — failed (findings above threshold, regression, etc.)
//   2 — error  (bad path, no .rs files, parse failure)

use std::{path::{Path, PathBuf}, process, time::Instant};
use clap::Parser;

use chainprobe_lib::{
    ast_visitor::ProjectVisitor,
    diff::diff_reports,
    patterns,
    profiler::compute_profile,
    report::build_report,
    types::{AnalysisReport, InputFile},
};

#[derive(Parser, Debug)]
#[command(name = "chainprobe-cli", version = "4.0.0",
          about = "ChainProbe v4 — Solana Anchor security analysis for CI/CD")]
struct Args {
    #[arg(long, short = 'p', default_value = ".")]
    project_path: PathBuf,

    /// Minimum severity that causes exit 1: CRITICAL | HIGH | MEDIUM | LOW
    #[arg(long, default_value = "HIGH")]
    min_severity: String,

    /// Minimum acceptable security score (0–100)
    #[arg(long, default_value = "0")]
    min_score: u32,

    /// Fail if any vulnerability chains detected
    #[arg(long)]
    fail_on_chains: bool,

    /// Fail if any bypassable invariants
    #[arg(long)]
    fail_on_broken_invariants: bool,

    /// Fail if any broken permissions
    #[arg(long)]
    fail_on_broken_permissions: bool,

    /// Compare against a baseline report JSON (regression mode)
    #[arg(long)]
    compare_to: Option<PathBuf>,

    /// Only fail on NEW findings vs baseline
    #[arg(long)]
    only_new: bool,

    /// Write full JSON report to file
    #[arg(long)]
    output_json: Option<PathBuf>,

    /// Output format: text | json | github
    #[arg(long, default_value = "text")]
    format: String,

    /// Suppress output (exit code only)
    #[arg(long, short)]
    quiet: bool,

    /// Show all severity levels
    #[arg(long, short)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    let t0 = Instant::now();

    let files = match load_project(&args.project_path) {
        Ok(f) => f,
        Err(e) => { eprintln!("error: {}", e); process::exit(2); }
    };

    let rs_count = files.iter().filter(|f| f.path.ends_with(".rs")).count();
    if rs_count == 0 {
        eprintln!("error: no .rs files in {:?}", args.project_path);
        process::exit(2);
    }

    if !args.quiet && args.format != "json" {
        eprintln!("ChainProbe v4 — {} files ({} .rs)", files.len(), rs_count);
    }

    let report = match run_pipeline(files) {
        Ok(r) => r,
        Err(e) => { eprintln!("error: {}", e); process::exit(2); }
    };

    if let Some(ref path) = args.output_json {
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(path, json);
            if !args.quiet { eprintln!("report → {}", path.display()); }
        }
    }

    let baseline: Option<AnalysisReport> = args.compare_to.as_ref().and_then(|p| {
        std::fs::read_to_string(p).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    });

    let sev_thresh = sev_rank(&args.min_severity.to_uppercase());
    let mut failures: Vec<String> = vec![];

    let failing: Vec<_> = report.findings.iter()
        .filter(|f| sev_rank(f.severity.as_str()) <= sev_thresh)
        .filter(|f| {
            if args.only_new {
                if let Some(ref base) = baseline {
                    let in_base = base.findings.iter().any(|bf|
                        bf.category.key() == f.category.key()
                        && bf.function == f.function
                        && fname(&bf.file) == fname(&f.file)
                    );
                    return !in_base;
                }
            }
            true
        })
        .collect();

    if !failing.is_empty() {
        failures.push(format!("{} finding(s) >= {} severity", failing.len(), args.min_severity.to_uppercase()));
    }
    if report.summary.security_score < args.min_score {
        failures.push(format!("score {} < minimum {}", report.summary.security_score, args.min_score));
    }
    if args.fail_on_chains && !report.vuln_chains.is_empty() {
        failures.push(format!("{} chain(s) detected", report.vuln_chains.len()));
    }
    if args.fail_on_broken_invariants && report.summary.bypassable_invariant_count > 0 {
        failures.push(format!("{} bypassable invariant(s)", report.summary.bypassable_invariant_count));
    }
    if args.fail_on_broken_permissions && report.summary.broken_permission_count > 0 {
        failures.push(format!("{} broken permission(s)", report.summary.broken_permission_count));
    }

    if let Some(ref base) = baseline {
        let d = diff_reports(base, &report);
        if d.score_delta < -5 {
            failures.push(format!("score regressed {:+} ({} → {})", d.score_delta, d.score_before, d.score_after));
        }
        let new_crit = d.findings_new.iter()
            .filter(|f| f.severity_after.as_deref() == Some("Critical"))
            .count();
        if new_crit > 0 {
            failures.push(format!("{} new CRITICAL vs baseline", new_crit));
        }
        if !args.quiet && args.format != "json" {
            eprintln!("baseline: {} fixed, {} new, {} regressed (score {:+})",
                d.summary.total_fixed, d.summary.total_new, d.summary.total_regressed, d.score_delta);
        }
    }

    let exit_code = if failures.is_empty() { 0 } else { 1 };

    // Output
    match args.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default()),
        "github" => {
            github_annotations(&report);
            github_step_summary(&report, &failures, t0.elapsed().as_secs());
            if !args.quiet { print_summary(&report, &failures, t0.elapsed().as_secs(), args.verbose); }
        }
        _ => if !args.quiet { print_summary(&report, &failures, t0.elapsed().as_secs(), args.verbose); }
    }

    process::exit(exit_code);
}

// Pipeline

fn run_pipeline(files: Vec<InputFile>) -> Result<AnalysisReport, String> {
    let mut visitor = ProjectVisitor::new();
    for file in &files {
        if file.path.ends_with(".rs")   { visitor.visit_rs_file(&file.path, &file.content); }
        if file.path.ends_with(".toml") { visitor.visit_toml_file(&file.path, &file.content); }
    }
    let findings = patterns::detect_all(&visitor, &files);
    let profile  = compute_profile(&visitor, &files);
    let (report, _) = build_report(findings, profile, &visitor, &files);
    Ok(report)
}

// File loading

fn load_project(root: &Path) -> Result<Vec<InputFile>, String> {
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    const BD: &[&str] = &["node_modules","target",".git",".anchor","migrations",".cargo"];
    const BF: &[&str] = &["Cargo.lock","yarn.lock","package-lock.json","pnpm-lock.yaml"];
    let mut files = vec![];
    walk(root, &mut files, BD, BF).map_err(|e| e.to_string())?;
    if files.is_empty() {
        return Err(format!("no .rs or .toml files in {}", root.display()));
    }
    files.sort_by_key(|f| {
        if f.path.ends_with("lib.rs")          { 0u8 }
        else if f.path.contains("instructions") { 1 }
        else if f.path.contains("state")        { 2 }
        else if f.path.ends_with(".toml")       { 3 }
        else                                    { 4 }
    });
    Ok(files)
}

fn walk(path: &Path, out: &mut Vec<InputFile>, bd: &[&str], bf: &[&str]) -> std::io::Result<()> {
    for entry in std::fs::read_dir(path)?.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if !bd.contains(&name) && !name.starts_with('.') { walk(&p, out, bd, bf)?; }
        } else if p.is_file() {
            if bf.contains(&name) || name.starts_with('.') { continue; }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "rs" || ext == "toml" {
                if let Ok(content) = std::fs::read_to_string(&p) {
                    out.push(InputFile { path: p.to_string_lossy().to_string(), content });
                }
            }
        }
    }
    Ok(())
}

// Text output

fn print_summary(report: &AnalysisReport, failures: &[String], secs: u64, verbose: bool) {
    let s = report.summary.security_score;
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════╗");
    eprintln!("║       ChainProbe v4 · Security Report        ║");
    eprintln!("╠══════════════════════════════════════════════╣");
    eprintln!("║  Program  : {:<33}║", trunc(&report.profile.program_name, 33));
    eprintln!("║  Score    : {:>3}/100   Risk: {:<18}║", s, report.summary.overall_risk);
    eprintln!("║  Findings : {:>3}  Chains: {:>3}  ({:.1}s)       ║",
        report.summary.total, report.summary.chain_count, secs);
    eprintln!("║  Taint    : {:>3}  Invariants: {:>3} ({:>3} bypass)║",
        report.summary.taint_flow_count, report.summary.invariant_count,
        report.summary.bypassable_invariant_count);
    eprintln!("║  Perms broken: {:>3}  Token anomalies: {:>3}   ║",
        report.summary.broken_permission_count, report.summary.token_flow_anomaly_count);
    eprintln!("╚══════════════════════════════════════════════╝");
    eprintln!();
    if failures.is_empty() {
        eprintln!("✓ PASSED");
    } else {
        eprintln!("✗ FAILED:");
        for f in failures { eprintln!("  • {}", f); }
    }
    eprintln!();

    let max_sev = if verbose { 4 } else { 1 };
    let notable: Vec<_> = report.findings.iter()
        .filter(|f| sev_rank(f.severity.as_str()) <= max_sev)
        .take(if verbose { 30 } else { 10 })
        .collect();

    for f in &notable {
        let t = if !f.confirmed_by_taint.is_empty() { "⚡" } else { "  " };
        eprintln!("  {t}[{:8} e:{:3}] {} ({}:{})",
            f.severity.as_str(), f.exploitability,
            trunc(&f.title, 50), fname(&f.file), f.line.unwrap_or(0));
    }
    if report.findings.len() > notable.len() && !notable.is_empty() {
        eprintln!("  … {} more (--verbose or --output-json for full list)",
            report.findings.len() - notable.len());
    }

    for c in &report.vuln_chains {
        eprintln!("  ⛓ [CHAIN {:?}] {}", c.severity, c.title);
    }
    eprintln!();
}

fn github_annotations(report: &AnalysisReport) {
    if std::env::var("GITHUB_ACTIONS").is_err() { return; }
    for f in &report.findings {
        let level = match f.severity.as_str() {
            "CRITICAL" | "HIGH" => "error",
            "MEDIUM"            => "warning",
            _                   => continue,
        };
        let taint = if !f.confirmed_by_taint.is_empty() { " [taint-confirmed]" } else { "" };
        println!("::{}  file={},line={}::[ChainProbe {}{}] {}",
            level, f.file, f.line.unwrap_or(1), f.severity.as_str(), taint, f.title);
    }
    for c in &report.vuln_chains {
        println!("::error ::[ChainProbe CHAIN] {}", c.title);
    }
}

fn github_step_summary(report: &AnalysisReport, failures: &[String], secs: u64) {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else { return; };
    let sc   = report.summary.security_score;
    let icon = if failures.is_empty() { "✅" } else { "❌" };
    let bar  = "█".repeat((sc/10) as usize) + &"░".repeat(10-(sc/10) as usize);

    let mut md = format!(
        "## {icon} ChainProbe v4 — {prog}\n\n\
        | Metric | Value |\n|---|---|\n\
        | Score | `{sc}/100` `{bar}` |\n\
        | Risk | **{risk}** |\n\
        | Findings | {tot} ({crit} CRITICAL, {high} HIGH) |\n\
        | Chains | {chains} | Taint flows | {taint} |\n\
        | Broken permissions | {perms} | Bypassable invariants | {inv} |\n\
        | Analyzed in | {secs}s |\n\n",
        prog=report.profile.program_name, risk=report.summary.overall_risk,
        tot=report.summary.total, crit=report.summary.critical, high=report.summary.high,
        chains=report.summary.chain_count, taint=report.summary.taint_flow_count,
        perms=report.summary.broken_permission_count,
        inv=report.summary.bypassable_invariant_count,
    );

    if !failures.is_empty() {
        md += "### ❌ Failures\n\n";
        for f in failures { md += &format!("- {}\n", f); }
        md.push('\n');
    }

    let crit_high: Vec<_> = report.findings.iter()
        .filter(|f| matches!(f.severity.as_str(), "CRITICAL"|"HIGH"))
        .take(10).collect();

    if !crit_high.is_empty() {
        md += "### Critical & High Findings\n\n| ID | Sev | Expl | Taint | Title |\n|---|---|---|---|---|\n";
        for f in crit_high {
            md += &format!("| `{}` | **{}** | {} | {} | {} |\n",
                f.id, f.severity.as_str(), f.exploitability,
                if f.confirmed_by_taint.is_empty() { "" } else { "✓" },
                f.title);
        }
    }

    let _ = std::fs::write(path, md);
}

// Helpers

fn sev_rank(s: &str) -> usize {
    match s { "CRITICAL"=>0, "HIGH"=>1, "MEDIUM"=>2, "LOW"=>3, "INFO"=>4, _=>5 }
}
fn fname(p: &str) -> &str { p.split('/').last().unwrap_or(p) }
fn trunc(s: &str, n: usize) -> &str { if s.len()<=n { s } else { &s[..n] } }
