// backend/src/profiler.rs
// Computes all profiling metrics from extracted AST data. Zero AI.

use std::collections::HashMap;
use crate::{ast_visitor::ProjectVisitor, types::{Framework, InputFile, InstructionCuEstimate, ProgramProfile}};
use crate::framework;

fn estimate_instruction_cu(name: &str, visitor: &ProjectVisitor, budget: u64) -> InstructionCuEstimate {
    let cpi_calls_for_instr: Vec<_> = visitor.cpi_calls.iter()
        .filter(|c| c.function_name == name)
        .collect();
    let cpi_cu = cpi_calls_for_instr.len() as u64 * 20_000;

    let ops_for_instr: Vec<_> = visitor.arithmetic_ops.iter()
        .filter(|o| o.in_function == name)
        .collect();
    let compute_cu = ops_for_instr.len() as u64 * 500 + 10_000;

    let total_cu = cpi_cu + compute_cu + 15_000;
    let budget_pct = if budget > 0 { (total_cu as f64 / budget as f64) * 100.0 } else { 0.0 };

    InstructionCuEstimate {
        name: name.to_string(),
        total_cu,
        cpi_cu,
        compute_cu,
        account_cu: 15_000,
        budget,
        budget_pct,
    }
}

pub fn compute_profile(visitor: &ProjectVisitor, files: &[InputFile]) -> ProgramProfile {
    let rs_files: Vec<_> = files.iter().filter(|f| f.path.ends_with(".rs")).collect();
    let total_lines: usize = files.iter().map(|f| f.content.lines().count()).sum();
    let rs_lines: usize = rs_files.iter().map(|f| f.content.lines().count()).sum();

    let signer_count = visitor.account_structs.iter()
        .flat_map(|s| &s.fields)
        .filter(|f| f.is_signer)
        .count();

    let fr = framework::detect_framework(visitor, files);

    // Framework patterns — detected from AST
    let mut patterns = vec![];

    match fr {
        Framework::Anchor => patterns.push("Anchor".into()),
        Framework::Pinocchio => {
            patterns.push("Pinocchio (no_std)".into());
            if visitor.is_no_std { patterns.push("no_std".into()); }
            if visitor.uses_pinocchio_log { patterns.push("Pinocchio log".into()); }
            if visitor.uses_pinocchio_cpi { patterns.push("Pinocchio CPI".into()); }
            if !visitor.pinocchio_manual_accounts.is_empty() {
                patterns.push("manual account parsing".into());
            }
        }
        Framework::Native => patterns.push("Native Solana".into()),
        Framework::Unknown => patterns.push("Unknown framework".into()),
    }

    if visitor.uses_init_if_needed { patterns.push("init_if_needed".into()); }
    if visitor.uses_token_2022 { patterns.push("Token-2022 / TokenInterface".into()); }
    if visitor.uses_token_program { patterns.push("SPL Token".into()); }
    if !visitor.pda_derivations.is_empty() { patterns.push("PDA derivation".into()); }
    if visitor.pda_derivations.iter().any(|p| p.bump_stored) {
        patterns.push("canonical bump storage".into());
    }
    if visitor.account_structs.iter().any(|s| s.has_close) {
        patterns.push("account close".into());
    }
    if visitor.account_structs.iter().any(|s| s.fields.iter().any(|f| f.has_has_one)) {
        patterns.push("has_one constraint".into());
    }
    if visitor.overflow_checks_enabled {
        patterns.push("overflow-checks = true".into());
    }

    // Complexity score
    let complexity_score = visitor.instructions.len() * 3
        + visitor.cpi_calls.len() * 5
        + visitor.pda_derivations.len() * 2
        + rs_lines / 100;
    let complexity = match complexity_score {
        0..=10 => "Low", 11..=30 => "Medium", 31..=60 => "High", _ => "Very High",
    }.to_string();

    // Per-instruction CU estimates
    let per_instruction_cu: Vec<InstructionCuEstimate> = visitor.instructions.iter()
        .map(|i| estimate_instruction_cu(&i.name, visitor, 200_000))
        .collect();

    let total_cu: u64 = per_instruction_cu.iter().map(|i| i.total_cu).sum();
    let total_budget: u64 = per_instruction_cu.iter().map(|i| i.budget).sum();

    // Performance score: 100 minus penalty based on CU budget usage
    let avg_budget_pct = if total_budget > 0 {
        per_instruction_cu.iter().map(|i| i.budget_pct).sum::<f64>() / per_instruction_cu.len() as f64
    } else { 0.0 };

    let perf_penalty = if avg_budget_pct > 90.0 { 40 }
        else if avg_budget_pct > 75.0 { 25 }
        else if avg_budget_pct > 50.0 { 15 }
        else if avg_budget_pct > 30.0 { 5 }
        else { 0 };

    let performance_score = (100u32).saturating_sub(perf_penalty);

    // Top CU consumers
    let mut sorted: Vec<_> = per_instruction_cu.iter().collect();
    sorted.sort_by(|a, b| b.total_cu.cmp(&a.total_cu));
    let top_cu_consumers: Vec<String> = sorted.iter()
        .take(3)
        .map(|i| format!("{} ({} CU)", i.name, i.total_cu))
        .collect();

    // Module tree
    let module_tree: Vec<String> = visitor.modules.iter().map(|m| {
        let parts: Vec<&str> = m.split('/').collect();
        let src = parts.iter().position(|&p| p == "src").unwrap_or(0);
        parts[src + 1..].join("::").replace(".rs", "")
    }).filter(|m| !m.is_empty()).collect();

    ProgramProfile {
        program_name: visitor.program_name.clone().unwrap_or_else(|| "unknown".into()),
        framework: fr,
        anchor_version: visitor.anchor_version.clone().unwrap_or_else(|| "unknown".into()),
        files_analyzed: rs_files.len(),
        total_lines,
        rs_lines,
        instructions: visitor.instructions.clone(),
        instructions_count: visitor.instructions.len(),
        account_structs: visitor.account_structs.clone(),
        account_structs_count: visitor.account_structs.len(),
        state_accounts: visitor.state_accounts.clone(),
        state_accounts_count: visitor.state_accounts.len(),
        cpi_calls: visitor.cpi_calls.clone(),
        cpi_calls_count: visitor.cpi_calls.len(),
        pda_derivations: visitor.pda_derivations.clone(),
        pda_count: visitor.pda_derivations.len(),
        signer_count,
        estimated_compute_units: total_cu,
        complexity,
        uses_token_program: visitor.uses_token_program,
        uses_token_2022: visitor.uses_token_2022,
        uses_init_if_needed: visitor.uses_init_if_needed,
        overflow_checks_enabled: visitor.overflow_checks_enabled,
        framework_patterns: patterns,
        module_tree,
        dependency_count: visitor.dependency_count,
        per_instruction_cu,
        performance_score,
        top_cu_consumers,
    }
}
