// backend/src/call_graph.rs
// Builds a directed call graph: instruction → CPI → external program.
// For each entry point (instruction), computes:
//   - What external programs are called
//   - What accounts flow into each CPI
//   - The minimum attacker-controlled footprint to reach each sink
//   - An attack surface score per instruction
//
// This answers: "How many steps and what resources does an attacker need
// to reach each security-sensitive operation?"

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{
        AccountTrust, AttackerFootprint, CallGraph, CallGraphEdge,
        CallGraphNode, CpiAccountBinding, ExploitComplexity, InputFile,
    },
};

pub fn build_call_graph(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    files: &[InputFile],
) -> CallGraph {
    let mut nodes: Vec<CallGraphNode> = vec![];
    let mut edges: Vec<CallGraphEdge> = vec![];

    // Create a node for each instruction
    for instr in &visitor.instructions {
        let instr_trust = trust_map.get(&instr.name).cloned().unwrap_or_default();

        let attack_surface = compute_attack_surface(&instr_trust);
        let footprint = compute_attacker_footprint(&instr_trust, visitor, &instr.ctx_type);

        nodes.push(CallGraphNode {
            id: instr.name.clone(),
            node_type: "instruction".to_string(),
            name: instr.name.clone(),
            file: instr.file.clone(),
            line: instr.line,
            attack_surface_score: attack_surface,
            attacker_footprint: footprint,
        });
    }

    // Build edges from CPI calls detected in source
    let cpi_calls_by_function = group_cpis_by_function(visitor);

    for (fn_name, cpis) in &cpi_calls_by_function {
        // Find the instruction that contains or calls this function
        let instr_name = find_instruction_for_fn(fn_name, visitor)
            .unwrap_or_else(|| fn_name.clone());

        for cpi in cpis {
            let cpi_node_id = format!("{}::{}", cpi.program, cpi.function_name);

            // Add CPI target node if not present
            if !nodes.iter().any(|n| n.id == cpi_node_id) {
                nodes.push(CallGraphNode {
                    id: cpi_node_id.clone(),
                    node_type: "cpi_target".to_string(),
                    name: format!("{}::{}", cpi.program, cpi.function_name),
                    file: cpi.file.clone(),
                    line: cpi.line,
                    attack_surface_score: 0, // external program
                    attacker_footprint: AttackerFootprint {
                        required_keypairs: 0,
                        required_sol: 0.0,
                        on_chain_setup: false,
                        complexity: ExploitComplexity::Trivial,
                    },
                });
            }

            // Get the accounts passed to this CPI
            let accounts_passed = get_cpi_accounts(&instr_name, &cpi.function_name, visitor, trust_map, files);
            let uses_pda_signer = detect_pda_signer(&cpi.function_name, &instr_name, files);

            edges.push(CallGraphEdge {
                from: instr_name.clone(),
                to: cpi_node_id,
                accounts_passed,
                uses_pda_signer,
                cpi_type: classify_cpi_type(&cpi.function_name),
            });
        }
    }

    // Add inter-instruction edges (same instruction calling impl methods)
    add_impl_method_edges(visitor, trust_map, files, &mut edges);

    // Sort nodes: highest attack surface first
    nodes.sort_by(|a, b| b.attack_surface_score.cmp(&a.attack_surface_score));

    CallGraph { nodes, edges }
}

//   Attack surface computation                         

/// Sum of trust risk scores for all non-infrastructure accounts
fn compute_attack_surface(trust: &HashMap<String, AccountTrust>) -> u32 {
    trust.values()
        .filter(|t| **t != AccountTrust::ProgramControlled)
        .map(|t| t.risk_score() as u32)
        .sum()
}

/// Compute minimum attacker resources needed to trigger this instruction
fn compute_attacker_footprint(
    trust: &HashMap<String, AccountTrust>,
    visitor: &ProjectVisitor,
    ctx_type: &str,
) -> AttackerFootprint {
    let unverified_count = trust.values()
        .filter(|t| **t == AccountTrust::UserSuppliedUnverified)
        .count();

    let signer_count = trust.values()
        .filter(|t| **t == AccountTrust::SignerRequired)
        .count();

    // Does this instruction require deploying a malicious program (for reentrancy)?
    let needs_program = visitor.cpi_calls.iter().any(|c| {
        c.function_name.contains("transfer") && unverified_count > 0
    });

    // Required keypairs = number of Signer<> accounts + 1 for the attacker's wallet
    let required_keypairs = (signer_count as u8).saturating_add(1);

    // Estimate SOL needed (rough: 0.002 per account + 0.001 per tx + 0.1 if program deploy)
    let required_sol = 0.001
        + (trust.len() as f64 * 0.002)
        + if needs_program { 0.1 } else { 0.0 };

    let complexity = match (unverified_count, signer_count, needs_program) {
        (0, 0, false) => ExploitComplexity::Trivial,
        (_, 0, false) => ExploitComplexity::Low,
        (_, _, false) => ExploitComplexity::Medium,
        (_, _, true)  => ExploitComplexity::High,
    };

    AttackerFootprint {
        required_keypairs,
        required_sol,
        on_chain_setup: needs_program,
        complexity,
    }
}

//   CPI account binding                            ─

/// Get accounts passed to a specific CPI call, with their trust levels
fn get_cpi_accounts(
    instr_name: &str,
    cpi_fn: &str,
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    files: &[InputFile],
) -> Vec<CpiAccountBinding> {
    let mut bindings = vec![];
    let instr_trust = trust_map.get(instr_name).cloned().unwrap_or_default();

    // For known CPI patterns, we can infer the account bindings
    match cpi_fn {
        "transfer" | "transfer_checked" => {
            // SPL token transfer: from, to, authority
            for (name, trust) in &instr_trust {
                if name.contains("token") || name.contains("ata") || name.contains("vault") {
                    bindings.push(CpiAccountBinding {
                        parameter_name: name.clone(),
                        account_name: name.clone(),
                        trust: trust.clone(),
                        is_writable: true,
                    });
                }
            }
        }
        "close_account" => {
            for (name, trust) in &instr_trust {
                if name.contains("vault") || name.contains("account") {
                    bindings.push(CpiAccountBinding {
                        parameter_name: name.clone(),
                        account_name: name.clone(),
                        trust: trust.clone(),
                        is_writable: true,
                    });
                }
            }
        }
        _ => {
            // Generic: include all accounts from the instruction's context
            for (name, trust) in &instr_trust {
                bindings.push(CpiAccountBinding {
                    parameter_name: name.clone(),
                    account_name: name.clone(),
                    trust: trust.clone(),
                    is_writable: false,
                });
            }
        }
    }

    bindings
}

/// Detect whether a CPI uses new_with_signer (PDA authority) vs new (user authority)
fn detect_pda_signer(cpi_fn: &str, instr_name: &str, files: &[InputFile]) -> bool {
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        for line in file.content.lines() {
            let t = line.trim();
            if t.contains(cpi_fn) && t.contains("new_with_signer") {
                return true;
            }
        }
    }
    false
}

/// Classify what kind of CPI this is
fn classify_cpi_type(fn_name: &str) -> String {
    if fn_name.contains("transfer") { "transfer".into() }
    else if fn_name.contains("close") { "close".into() }
    else if fn_name.contains("mint") { "mint".into() }
    else if fn_name.contains("burn") { "burn".into() }
    else if fn_name.contains("invoke") { "invoke".into() }
    else { "custom".into() }
}

//   Impl method edge detection                         

/// Add edges for instruction → impl method calls (e.g. take → deposit, withdraw_and_close)
fn add_impl_method_edges(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    files: &[InputFile],
    edges: &mut Vec<CallGraphEdge>,
) {
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();

        // Find pub fn handlers in #[program] mod
        let mut in_program = false;
        for (i, &line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.contains("#[program]") { in_program = true; }
            if in_program && t.starts_with("pub fn ") && t.contains("Context<") {
                let fn_name = t.split('(').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("").to_string();

                // Look for ctx.accounts.method() calls in this function body
                let body_end = find_fn_end(&lines, i);
                for j in i..body_end.min(lines.len()) {
                    let bl = lines[j].trim();
                    if bl.contains("ctx.accounts.") && bl.contains("()") && !bl.starts_with("//") {
                        let method = bl.split("ctx.accounts.").nth(1)
                            .and_then(|s| s.split('(').next())
                            .unwrap_or("").trim().to_string();

                        if !method.is_empty() && method != fn_name {
                            let instr_trust = trust_map.get(&fn_name).cloned().unwrap_or_default();
                            edges.push(CallGraphEdge {
                                from: fn_name.clone(),
                                to: method.clone(),
                                accounts_passed: instr_trust.iter().map(|(k, v)| CpiAccountBinding {
                                    parameter_name: k.clone(),
                                    account_name: k.clone(),
                                    trust: v.clone(),
                                    is_writable: false,
                                }).collect(),
                                uses_pda_signer: false,
                                cpi_type: "impl_method".into(),
                            });
                        }
                    }
                }
            }
        }
    }
}

//   Helpers                                  ─

fn group_cpis_by_function(
    visitor: &ProjectVisitor,
) -> HashMap<String, Vec<crate::types::CpiCallInfo>> {
    let mut map: HashMap<String, Vec<crate::types::CpiCallInfo>> = HashMap::new();
    for cpi in &visitor.cpi_calls {
        // Use the file path to guess the function — crude but workable
        // without full AST span tracking
        let fn_name = visitor.instructions.iter()
            .find(|i| i.file == cpi.file)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        map.entry(fn_name).or_default().push(cpi.clone());
    }
    map
}

fn find_instruction_for_fn(fn_name: &str, visitor: &ProjectVisitor) -> Option<String> {
    // Direct match
    if visitor.instructions.iter().any(|i| i.name == fn_name) {
        return Some(fn_name.to_string());
    }
    // Check if fn_name is called from a known instruction
    None
}

fn find_fn_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    for (i, &line) in lines.iter().enumerate().skip(start) {
        depth += line.chars().filter(|&c| c == '{').count() as i32;
        depth -= line.chars().filter(|&c| c == '}').count() as i32;
        if depth <= 0 && i > start { return i; }
    }
    lines.len()
}
