// backend/src/profiler.rs
// Computes all profiling metrics from extracted AST data. Zero AI.

use crate::{ast_visitor::ProjectVisitor, types::{InputFile, ProgramProfile}};

pub fn compute_profile(visitor: &ProjectVisitor, files: &[InputFile]) -> ProgramProfile {
    let rs_files: Vec<_> = files.iter().filter(|f| f.path.ends_with(".rs")).collect();
    let total_lines: usize = files.iter().map(|f| f.content.lines().count()).sum();
    let rs_lines: usize = rs_files.iter().map(|f| f.content.lines().count()).sum();

    let signer_count = visitor.account_structs.iter()
        .flat_map(|s| &s.fields)
        .filter(|f| f.is_signer)
        .count();

    // Framework patterns — detected from AST
    let mut patterns = vec![];
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

    // Compute units estimate
    let cu = (visitor.instructions.len() as u64 * 5_000)
        + (visitor.cpi_calls.len() as u64 * 20_000)
        + (visitor.pda_derivations.len() as u64 * 3_000)
        + 25_000;

    // Module tree
    let module_tree: Vec<String> = visitor.modules.iter().map(|m| {
        let parts: Vec<&str> = m.split('/').collect();
        let src = parts.iter().position(|&p| p == "src").unwrap_or(0);
        parts[src + 1..].join("::").replace(".rs", "")
    }).filter(|m| !m.is_empty()).collect();

    ProgramProfile {
        program_name: visitor.program_name.clone().unwrap_or_else(|| "unknown".into()),
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
        estimated_compute_units: cu,
        complexity,
        uses_token_program: visitor.uses_token_program,
        uses_token_2022: visitor.uses_token_2022,
        uses_init_if_needed: visitor.uses_init_if_needed,
        overflow_checks_enabled: visitor.overflow_checks_enabled,
        framework_patterns: patterns,
        module_tree,
        dependency_count: visitor.dependency_count,
    }
}
