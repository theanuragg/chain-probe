// backend/src/invariant.rs
// Mines every require!() call in the program into a structured invariant.
// Then checks each invariant for bypass paths using taint results.
//
// A program invariant is a condition the author asserts must always hold.
// Invariant bypass = a path exists where an attacker makes it evaluate incorrectly.
//
// What we check:
//   1. Is any variable in the condition reachable by attacker-controlled taint?
//   2. Is this invariant enforced in ALL instructions that operate on the same state?
//   3. Can the state the invariant reads be modified by a prior instruction (ordering risk)?

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{InputFile, ProgramInvariant, InvariantStatus, TaintFlow},
};

pub fn mine_invariants(
    visitor: &ProjectVisitor,
    files: &[InputFile],
    taint_flows: &[TaintFlow],
) -> Vec<ProgramInvariant> {
    let mut invariants = vec![];
    let mut id = 0u32;

    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();

        for (i, &line) in lines.iter().enumerate() {
            let t = line.trim();

            // Match require!(...) macro calls
            if !t.starts_with("require!") && !t.starts_with("require_eq!")
                && !t.starts_with("require_gte!") && !t.starts_with("require_keys_eq!")
            {
                continue;
            }

            id += 1;
            let instr_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "unknown".to_string());

            // Extract the condition text
            let condition = extract_condition(t);

            // Infer what this invariant is protecting
            let protects = infer_protection(&condition);

            // Check if any taint flow reaches a variable in this condition
            let taint_confirmed = taint_flows.iter().any(|tf| {
                tf.instruction == instr_name
                    && tf.sink.file == file.path
                    && (tf.sink.line == i + 1 || tf.sink.description.contains(&condition))
            });

            // Check if this invariant is enforced in all relevant instructions
            // "relevant" = instructions that operate on the same state account
            let status = determine_status(
                &condition,
                &instr_name,
                &file.path,
                visitor,
                taint_confirmed,
                files,
            );

            let bypass_path = if status != InvariantStatus::Holds {
                Some(describe_bypass(&condition, &status, &instr_name))
            } else {
                None
            };

            let snippet = get_snippet(&lines, i, 2);

            invariants.push(ProgramInvariant {
                id: format!("INV-{id:03}"),
                condition: condition.clone(),
                instruction: instr_name,
                file: file.path.clone(),
                line: i + 1,
                snippet,
                protects,
                status,
                bypass_path,
                taint_confirmed,
            });
        }
    }

    invariants
}

//   Status determination                            

fn determine_status(
    condition: &str,
    instr_name: &str,
    file: &str,
    visitor: &ProjectVisitor,
    taint_confirmed: bool,
    files: &[InputFile],
) -> InvariantStatus {
    if taint_confirmed {
        return InvariantStatus::Bypassable;
    }

    // Check whether all instructions that write the same state fields
    // also enforce this condition
    let state_fields = extract_state_fields(condition);
    if !state_fields.is_empty() {
        let writing_instrs = find_writing_instructions(&state_fields, visitor, files);
        let enforcing_instrs = find_enforcing_instructions(condition, files);

        let unenforced: Vec<String> = writing_instrs.into_iter()
            .filter(|w| w != instr_name && !enforcing_instrs.contains(w))
            .collect();

        if !unenforced.is_empty() {
            return InvariantStatus::Incomplete;
        }
    }

    // Check for ordering risk: does this condition read state that could be
    // manipulated by calling a different instruction first?
    if has_ordering_risk(condition, instr_name, visitor) {
        return InvariantStatus::OrderingRisk;
    }

    InvariantStatus::Holds
}

/// Find all instructions that write to the state fields mentioned in a condition
fn find_writing_instructions(
    state_fields: &[String],
    visitor: &ProjectVisitor,
    files: &[InputFile],
) -> Vec<String> {
    let mut writers = vec![];

    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        let mut current_fn = String::new();

        for (i, &line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.starts_with("pub fn ") || t.starts_with("fn ") {
                current_fn = t.split('(').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("").to_string();
            }

            // Look for writes to the state fields
            let is_write = t.contains("+=") || t.contains("-=") || t.contains("*=")
                || (t.contains('=') && !t.contains("==") && !t.starts_with("let ")
                    && !t.starts_with("//"));

            if is_write && state_fields.iter().any(|f| t.contains(f.as_str())) {
                if !current_fn.is_empty() && !writers.contains(&current_fn) {
                    writers.push(current_fn.clone());
                }
            }
        }
    }

    writers
}

/// Find all instructions that enforce a given condition (contain the same require!)
fn find_enforcing_instructions(condition: &str, files: &[InputFile]) -> Vec<String> {
    let mut enforcers = vec![];
    let keywords = extract_key_identifiers(condition);

    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();

        for (i, &line) in lines.iter().enumerate() {
            let t = line.trim();
            if (t.starts_with("require!") || t.starts_with("require_eq!"))
                && keywords.iter().all(|k| t.contains(k.as_str()))
            {
                if let Some(fn_name) = find_enclosing_function(&lines, i) {
                    if !enforcers.contains(&fn_name) {
                        enforcers.push(fn_name);
                    }
                }
            }
        }
    }

    enforcers
}

/// Check if state read in condition can be modified by another instruction first
fn has_ordering_risk(
    condition: &str,
    instr_name: &str,
    visitor: &ProjectVisitor,
) -> bool {
    let state_fields = extract_state_fields(condition);
    if state_fields.is_empty() { return false; }

    // If another instruction has a mutable reference to the same state type
    // and no constraint protecting ordering, there's a risk
    for acct_struct in &visitor.account_structs {
        let struct_instr = visitor.instructions.iter()
            .find(|i| i.ctx_type == acct_struct.name)
            .map(|i| i.name.clone())
            .unwrap_or_default();

        if struct_instr == instr_name { continue; }

        for field in &acct_struct.fields {
            if field.is_mut && state_fields.iter().any(|sf| {
                field.name.contains(sf.as_str()) || sf.contains(field.name.as_str())
            }) {
                return true;
            }
        }
    }

    false
}

//   Parsing helpers                              ─

/// Extract the condition from require!(condition, error) or require_eq!(a, b, error)
fn extract_condition(line: &str) -> String {
    // require!(condition, ErrorCode::Something) → "condition"
    if let Some(start) = line.find('(') {
        let inner = &line[start + 1..];
        // Find matching close paren
        let mut depth = 1;
        let mut end = 0;
        for (i, c) in inner.chars().enumerate() {
            match c { '(' => depth += 1, ')' => { depth -= 1; if depth == 0 { end = i; break; } } _ => {} }
        }
        let full = &inner[..end];
        // Remove the error code (last comma-separated part)
        let parts: Vec<&str> = full.rsplitn(2, ',').collect();
        if parts.len() == 2 {
            return parts[1].trim().to_string();
        }
        return full.trim().to_string();
    }
    line.to_string()
}

/// Infer what this invariant is designed to protect
fn infer_protection(condition: &str) -> String {
    let c = condition.to_lowercase();
    if c.contains("balance") || c.contains("amount") || c.contains(">= ") {
        "Prevents over-withdrawal or insufficient balance"
    } else if c.contains("authority") || c.contains("owner") || c.contains("admin") {
        "Access control — restricts operation to authorized account"
    } else if c.contains("key()") || c.contains("pubkey") {
        "Account identity verification — ensures correct account is used"
    } else if c.contains("reserve") || c.contains("supply") || c.contains("liquidity") {
        "Pool/reserve integrity — prevents economic manipulation"
    } else if c.contains("paused") || c.contains("frozen") || c.contains("enabled") {
        "Protocol state gate — enforces operational mode"
    } else if c.contains("bump") || c.contains("seeds") {
        "PDA integrity — validates canonical derivation"
    } else {
        "General state invariant"
    }.to_string()
}

/// Extract state field references from a condition (e.g. "vault.balance" → ["balance"])
fn extract_state_fields(condition: &str) -> Vec<String> {
    let mut fields = vec![];
    // Match patterns like "self.vault.balance", "ctx.accounts.pool.reserve_a", "vault.amount"
    for part in condition.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '_') {
        if part.contains('.') {
            let field = part.split('.').last().unwrap_or("").to_string();
            if !field.is_empty() && field.len() > 2 {
                fields.push(field);
            }
        }
    }
    fields.dedup();
    fields
}

/// Extract key identifier names from a condition for matching
fn extract_key_identifiers(condition: &str) -> Vec<String> {
    condition.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|s| s.len() > 3 && !["self", "ctx", "accounts"].contains(s))
        .map(|s| s.to_string())
        .collect()
}

fn describe_bypass(condition: &str, status: &InvariantStatus, instr: &str) -> String {
    match status {
        InvariantStatus::Bypassable =>
            format!("Taint analysis shows an attacker-controlled value reaches the condition `{}` in `{}`. The invariant can be made to evaluate in attacker's favor.", condition, instr),
        InvariantStatus::Incomplete =>
            format!("The invariant `{}` is enforced in `{}` but not in all instructions that modify the same state. Another instruction can bypass this protection.", condition, instr),
        InvariantStatus::OrderingRisk =>
            format!("The state read in `{}` can be modified by calling another instruction first. If the attacker controls instruction ordering, this invariant is bypassable.", condition),
        InvariantStatus::Holds => String::new(),
    }
}

fn find_enclosing_function(lines: &[&str], from_line: usize) -> Option<String> {
    for i in (0..=from_line).rev() {
        let t = lines[i].trim();
        if t.starts_with("pub fn ") || t.starts_with("fn ") {
            return Some(
                t.split('(').next()?
                    .split_whitespace().last()?.to_string()
            );
        }
    }
    None
}

fn get_snippet(lines: &[&str], center: usize, ctx: usize) -> String {
    let start = center.saturating_sub(ctx);
    let end = (center + ctx + 1).min(lines.len());
    lines[start..end].join("\n")
}
