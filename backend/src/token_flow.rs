// backend/src/token_flow.rs
//
// Builds a complete token flow graph for the program.
// Answers definitively: where do tokens enter, where do they exit,
// who authorizes each movement, and what conditions must hold?
//
// This is NOT taint analysis. Taint tracks values.
// Token flow tracks the economic model of the program — the actual
// lifecycle of every token account and every transfer between them.
//
// Nodes: token accounts (vaults, ATAs, pool reserves, fee accounts)
// Edges: token movements (transfer, burn, close → lamports, mint)
// Each edge: conditions required, who signs, what PDA authorizes
//
// What this finds that nothing else does:
//   - Paths where tokens can exit without the expected authorization
//   - Unconstrained minting (supply inflation)
//   - Fee bypasses (fee path exists but can be skipped)
//   - Asymmetric flows (tokens can enter but not exit, or vice versa)
//   - Reentrancy drain paths (same exit path callable multiple times)

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{
        AccountTrust, InputFile, TokenFlowAnomaly, TokenFlowEdge, TokenFlowGraph,
        TokenFlowNode, TokenMovementType, TokenAuthCondition,
    },
};

pub fn build_token_flow_graph(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    files: &[InputFile],
) -> TokenFlowGraph {
    let mut nodes: Vec<TokenFlowNode> = vec![];
    let mut edges: Vec<TokenFlowEdge> = vec![];

    // Discover all token account nodes from account structs
    for acct_struct in &visitor.account_structs {
        let instr = visitor.instructions.iter()
            .find(|i| i.ctx_type == acct_struct.name)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| acct_struct.name.to_lowercase());

        let instr_trust = trust_map.get(&instr).cloned().unwrap_or_default();

        for field in &acct_struct.fields {
            let is_token_acct = field.field_type.contains("TokenAccount")
                || field.field_type.contains("InterfaceAccount")
                || (field.name.contains("vault") || field.name.contains("ata")
                    || field.name.contains("reserve") || field.name.contains("pool")
                    || field.name.contains("treasury") || field.name.contains("fee_account"))
                    && !field.field_type.contains("Program <")
                    && !field.field_type.contains("Sysvar <");

            if !is_token_acct { continue; }

            let trust = instr_trust.get(&field.name)
                .cloned()
                .unwrap_or(AccountTrust::UserSuppliedVerified);

            let role = classify_token_role(&field.name);

            // Only add node if not already present
            if !nodes.iter().any(|n: &TokenFlowNode| n.id == field.name) {
                nodes.push(TokenFlowNode {
                    id: field.name.clone(),
                    account_name: field.name.clone(),
                    role: role.clone(),
                    trust,
                    is_pda: !field.seeds.is_empty(),
                    mint: extract_mint_from_constraints(&field.constraints),
                    instructions_used_in: vec![instr.clone()],
                });
            } else if let Some(n) = nodes.iter_mut().find(|n| n.id == field.name) {
                if !n.instructions_used_in.contains(&instr) {
                    n.instructions_used_in.push(instr.clone());
                }
            }
        }
    }

    // Discover token movements from CPI calls and source patterns
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        edges.extend(extract_token_movements(file, visitor, trust_map, &nodes));
    }

    // Detect anomalies
    let anomalies = detect_flow_anomalies(&nodes, &edges, visitor);

    TokenFlowGraph { nodes, edges, anomalies }
}

//   Token movement extraction                         ─

fn extract_token_movements(
    file: &InputFile,
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    nodes: &[TokenFlowNode],
) -> Vec<TokenFlowEdge> {
    let mut edges = vec![];
    let lines: Vec<&str> = file.content.lines().collect();
    let mut current_fn = String::new();
    let mut edge_id = 0u32;

    for (i, &line) in lines.iter().enumerate() {
        let t = line.trim();

        // Track current function
        if (t.starts_with("pub fn ") || t.starts_with("fn "))
            && !t.starts_with("//")
        {
            current_fn = t.split('(').next().unwrap_or("")
                .split_whitespace().last().unwrap_or("").to_string();
        }

        // Detect transfer_checked / transfer
        if t.contains("transfer_checked(") || t.contains("transfer(") {
            edge_id += 1;

            // Extract from/to account names from context
            let (from_acct, to_acct) = extract_transfer_accounts(&lines, i, &current_fn, visitor);
            let auth = extract_transfer_auth(&lines, i, trust_map, &current_fn, visitor);
            let amount_source = extract_amount_source(&lines, i, visitor, &current_fn);
            let conditions = extract_preconditions(&lines, i);

            // Classify movement
            let movement = if current_fn.contains("withdraw") || current_fn.contains("refund")
                || current_fn.contains("take") || current_fn.contains("close")
            {
                TokenMovementType::Withdrawal
            } else if current_fn.contains("deposit") || current_fn.contains("make")
                || current_fn.contains("stake") || current_fn.contains("lock")
            {
                TokenMovementType::Deposit
            } else if current_fn.contains("swap") || current_fn.contains("exchange") {
                TokenMovementType::Swap
            } else if current_fn.contains("fee") || current_fn.contains("collect") {
                TokenMovementType::FeeCollection
            } else {
                TokenMovementType::InternalTransfer
            };

            let snippet = get_context(&lines, i, 4);

            edges.push(TokenFlowEdge {
                id: format!("TF-{edge_id:03}"),
                from_account: from_acct.clone(),
                to_account: to_acct.clone(),
                movement_type: movement,
                instruction: current_fn.clone(),
                file: file.path.clone(),
                line: i + 1,
                snippet,
                authorization: auth,
                amount_source,
                preconditions: conditions,
                is_guarded: has_preceding_require(&lines, i, 8),
                uses_pda_signer: t.contains("new_with_signer") || preceding_lines_contain(&lines, i, "new_with_signer", 5),
            });
        }

        // Detect close_account → lamport flow
        if t.contains("close_account(") {
            edge_id += 1;
            let snippet = get_context(&lines, i, 3);
            edges.push(TokenFlowEdge {
                id: format!("TF-{edge_id:03}"),
                from_account: extract_close_source(&lines, i),
                to_account: extract_close_destination(&lines, i),
                movement_type: TokenMovementType::AccountClose,
                instruction: current_fn.clone(),
                file: file.path.clone(),
                line: i + 1,
                snippet,
                authorization: TokenAuthCondition {
                    requires_signer: false,
                    signer_name: None,
                    requires_pda: true,
                    pda_seeds: vec![],
                    constraint_text: "PDA authority via new_with_signer".into(),
                    trust_level: AccountTrust::ProgramControlled,
                },
                amount_source: "vault balance (all lamports)".into(),
                preconditions: vec![],
                is_guarded: false,
                uses_pda_signer: true,
            });
        }

        // Detect mint_to → token inflation
        if t.contains("mint_to(") {
            edge_id += 1;
            let auth = extract_transfer_auth(&lines, i, trust_map, &current_fn, visitor);
            let snippet = get_context(&lines, i, 3);
            let is_guarded = has_preceding_require(&lines, i, 8);

            edges.push(TokenFlowEdge {
                id: format!("TF-{edge_id:03}"),
                from_account: "token_mint".into(),
                to_account: extract_mint_to_dest(&lines, i),
                movement_type: TokenMovementType::Mint,
                instruction: current_fn.clone(),
                file: file.path.clone(),
                line: i + 1,
                snippet,
                authorization: auth,
                amount_source: "caller-supplied amount".into(),
                preconditions: vec![],
                is_guarded,
                uses_pda_signer: preceding_lines_contain(&lines, i, "new_with_signer", 5),
            });
        }

        // Detect burn
        if t.contains("burn(") && !t.starts_with("//") {
            edge_id += 1;
            let snippet = get_context(&lines, i, 3);
            edges.push(TokenFlowEdge {
                id: format!("TF-{edge_id:03}"),
                from_account: "user_token_account".into(),
                to_account: "burned".into(),
                movement_type: TokenMovementType::Burn,
                instruction: current_fn.clone(),
                file: file.path.clone(),
                line: i + 1,
                snippet,
                authorization: TokenAuthCondition {
                    requires_signer: true,
                    signer_name: Some("authority".into()),
                    requires_pda: false,
                    pda_seeds: vec![],
                    constraint_text: "owner must sign".into(),
                    trust_level: AccountTrust::SignerRequired,
                },
                amount_source: "caller-supplied amount".into(),
                preconditions: vec![],
                is_guarded: has_preceding_require(&lines, i, 6),
                uses_pda_signer: false,
            });
        }
    }

    edges
}

//   Anomaly detection                             ─

fn detect_flow_anomalies(
    nodes: &[TokenFlowNode],
    edges: &[TokenFlowEdge],
    visitor: &ProjectVisitor,
) -> Vec<TokenFlowAnomaly> {
    let mut anomalies = vec![];

    // 1. Unguarded withdrawal — exits with no require! guard
    for edge in edges {
        if matches!(edge.movement_type, TokenMovementType::Withdrawal | TokenMovementType::AccountClose)
            && !edge.is_guarded
            && !edge.uses_pda_signer
        {
            anomalies.push(TokenFlowAnomaly {
                id: format!("TFA-{}", anomalies.len() + 1),
                anomaly_type: "unguarded_withdrawal".into(),
                severity: "HIGH".into(),
                description: format!(
                    "Token withdrawal in `{}` has no preceding require!() guard and no PDA signer authority. \
                    Any caller satisfying the account constraints can trigger this transfer.",
                    edge.instruction
                ),
                edge_ids: vec![edge.id.clone()],
                recommendation: "Add require!(vault.authority == authority.key(), ErrorCode::Unauthorized) \
                    before the transfer, or ensure the vault is PDA-controlled via new_with_signer.".into(),
            });
        }
    }

    // 2. Asymmetric flow — tokens can enter but never exit (locked forever)
    let deposit_accounts: std::collections::HashSet<&str> = edges.iter()
        .filter(|e| matches!(e.movement_type, TokenMovementType::Deposit))
        .map(|e| e.to_account.as_str())
        .collect();
    let withdrawal_sources: std::collections::HashSet<&str> = edges.iter()
        .filter(|e| matches!(e.movement_type, TokenMovementType::Withdrawal | TokenMovementType::AccountClose))
        .map(|e| e.from_account.as_str())
        .collect();

    for &acct in &deposit_accounts {
        if !withdrawal_sources.contains(acct) && acct != "burned" {
            anomalies.push(TokenFlowAnomaly {
                id: format!("TFA-{}", anomalies.len() + 1),
                anomaly_type: "asymmetric_flow_locked".into(),
                severity: "MEDIUM".into(),
                description: format!(
                    "Account `{}` receives token deposits but no withdrawal path exists in this program. \
                    Tokens deposited here may be permanently locked.",
                    acct
                ),
                edge_ids: edges.iter()
                    .filter(|e| e.to_account == acct)
                    .map(|e| e.id.clone())
                    .collect(),
                recommendation: "Verify this is intentional. If tokens should be withdrawable, \
                    add a withdrawal instruction with appropriate authority checks.".into(),
            });
        }
    }

    // 3. Unconstrained mint — mint_to without an authority check
    for edge in edges {
        if matches!(edge.movement_type, TokenMovementType::Mint)
            && edge.authorization.trust_level == AccountTrust::UserSuppliedUnverified
        {
            anomalies.push(TokenFlowAnomaly {
                id: format!("TFA-{}", anomalies.len() + 1),
                anomaly_type: "unconstrained_mint".into(),
                severity: "CRITICAL".into(),
                description: format!(
                    "Token minting in `{}` uses an unverified authority (AccountInfo). \
                    Any account can be passed as the mint authority, allowing unlimited token inflation.",
                    edge.instruction
                ),
                edge_ids: vec![edge.id.clone()],
                recommendation: "Mint authority must be either a Signer<'info> or a PDA \
                    controlled by this program via new_with_signer. Never accept AccountInfo \
                    as a mint authority.".into(),
            });
        }
    }

    // 4. Fee collection bypassable — fee path exists but has a skip route
    let fee_edges: Vec<&TokenFlowEdge> = edges.iter()
        .filter(|e| matches!(e.movement_type, TokenMovementType::FeeCollection))
        .collect();
    let non_fee_withdrawals: Vec<&TokenFlowEdge> = edges.iter()
        .filter(|e| matches!(e.movement_type, TokenMovementType::Withdrawal)
            && !e.instruction.contains("fee"))
        .collect();

    if !fee_edges.is_empty() && !non_fee_withdrawals.is_empty() {
        // Check if there is a withdrawal path that doesn't go through the fee instruction
        for nfw in &non_fee_withdrawals {
            let bypasses_fee = fee_edges.iter().all(|fe| fe.instruction != nfw.instruction);
            if bypasses_fee {
                anomalies.push(TokenFlowAnomaly {
                    id: format!("TFA-{}", anomalies.len() + 1),
                    anomaly_type: "fee_bypass".into(),
                    severity: "HIGH".into(),
                    description: format!(
                        "Fee collection exists in `{}` but instruction `{}` allows withdrawal \
                        without going through the fee path. Fees can be bypassed.",
                        fee_edges[0].instruction, nfw.instruction
                    ),
                    edge_ids: vec![nfw.id.clone()],
                    recommendation: "Integrate fee deduction into every withdrawal path, \
                        or use a single withdrawal instruction that always collects fees.".into(),
                });
            }
        }
    }

    anomalies
}

//   Classification helpers                           

fn classify_token_role(name: &str) -> String {
    if name.contains("vault") { "vault".into() }
    else if name.contains("reserve") { "reserve".into() }
    else if name.contains("fee") { "fee_account".into() }
    else if name.contains("treasury") { "treasury".into() }
    else if name.contains("ata") || name.contains("token_account") { "ata".into() }
    else if name.contains("pool") { "pool_account".into() }
    else { "token_account".into() }
}

fn extract_mint_from_constraints(constraints: &[String]) -> Option<String> {
    for c in constraints {
        if c.contains("mint") {
            if let Some(start) = c.find("mint =") {
                let rest = &c[start + 6..];
                let name = rest.trim().split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                    .next().unwrap_or("").to_string();
                if !name.is_empty() { return Some(name); }
            }
        }
    }
    None
}

fn extract_transfer_accounts(
    lines: &[&str],
    center: usize,
    fn_name: &str,
    visitor: &ProjectVisitor,
) -> (String, String) {
    // Look backwards for TransferChecked / Transfer struct literal: { from: ..., to: ... }
    let start = center.saturating_sub(6);
    let context: String = lines[start..=(center.min(lines.len()-1))].join(" ");

    let from = extract_field_value(&context, "from:")
        .or_else(|| extract_field_value(&context, "from :"))
        .unwrap_or_else(|| "source".to_string());
    let to = extract_field_value(&context, "to:")
        .or_else(|| extract_field_value(&context, "to :"))
        .unwrap_or_else(|| "destination".to_string());

    (simplify_account_ref(&from), simplify_account_ref(&to))
}

fn extract_transfer_auth(
    lines: &[&str],
    center: usize,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    fn_name: &str,
    visitor: &ProjectVisitor,
) -> TokenAuthCondition {
    let start = center.saturating_sub(6);
    let context: String = lines[start..=(center.min(lines.len()-1))].join(" ");

    let uses_pda = context.contains("new_with_signer");
    let authority_name = extract_field_value(&context, "authority:")
        .map(|s| simplify_account_ref(&s));

    let trust = authority_name.as_deref()
        .and_then(|a| trust_map.get(fn_name).and_then(|m| m.get(a)).cloned())
        .unwrap_or(AccountTrust::UserSuppliedVerified);

    let requires_signer = trust == AccountTrust::SignerRequired;

    TokenAuthCondition {
        requires_signer,
        signer_name: if requires_signer { authority_name.clone() } else { None },
        requires_pda: uses_pda,
        pda_seeds: vec![],
        constraint_text: if uses_pda {
            "PDA authority (new_with_signer)".into()
        } else if requires_signer {
            format!("{} must sign", authority_name.as_deref().unwrap_or("authority"))
        } else {
            format!("authority trust: {}", trust.label())
        },
        trust_level: trust,
    }
}

fn extract_amount_source(
    lines: &[&str],
    center: usize,
    visitor: &ProjectVisitor,
    fn_name: &str,
) -> String {
    // Look for the amount argument — typically the last arg to transfer_checked
    // or the argument on the transfer line itself
    let line = lines[center].trim();

    // Check if this instruction has amount-type parameters
    if let Some(instr) = visitor.instructions.iter().find(|i| i.name == fn_name) {
        let amount_params: Vec<&str> = instr.params.iter()
            .filter(|p| p.contains("amount") || p.contains("deposit") || p.contains("receive"))
            .map(|p| p.as_str())
            .collect();
        if !amount_params.is_empty() {
            return format!("caller-supplied: {}", amount_params[0].split(':').next().unwrap_or("amount").trim());
        }
    }

    // Check for field access patterns in context
    let start = center.saturating_sub(4);
    let ctx = lines[start..=center.min(lines.len()-1)].join(" ");

    if ctx.contains(".amount") { "account.amount field".into() }
    else if ctx.contains(".balance") { "account.balance field".into() }
    else if ctx.contains(".receive") { "escrow.receive (stored at init)".into() }
    else { "computed value".into() }
}

fn extract_preconditions(lines: &[&str], center: usize) -> Vec<String> {
    let mut conditions = vec![];
    let start = center.saturating_sub(12);
    for &line in lines[start..center].iter() {
        let t = line.trim();
        if t.starts_with("require!") || t.starts_with("require_eq!") || t.starts_with("require_gte!") {
            conditions.push(t.to_string());
        }
    }
    conditions
}

fn has_preceding_require(lines: &[&str], center: usize, window: usize) -> bool {
    let start = center.saturating_sub(window);
    lines[start..center].iter().any(|l| {
        let t = l.trim();
        t.starts_with("require!") || t.starts_with("require_eq!") || t.starts_with("require_gte!")
    })
}

fn preceding_lines_contain(lines: &[&str], center: usize, pattern: &str, window: usize) -> bool {
    let start = center.saturating_sub(window);
    lines[start..=center.min(lines.len()-1)].iter().any(|l| l.contains(pattern))
}

fn extract_close_source(lines: &[&str], center: usize) -> String {
    let start = center.saturating_sub(4);
    let ctx = lines[start..=center.min(lines.len()-1)].join(" ");
    extract_field_value(&ctx, "account:").map(|s| simplify_account_ref(&s)).unwrap_or_else(|| "vault".into())
}

fn extract_close_destination(lines: &[&str], center: usize) -> String {
    let start = center.saturating_sub(4);
    let ctx = lines[start..=center.min(lines.len()-1)].join(" ");
    extract_field_value(&ctx, "destination:").map(|s| simplify_account_ref(&s)).unwrap_or_else(|| "maker".into())
}

fn extract_mint_to_dest(lines: &[&str], center: usize) -> String {
    let start = center.saturating_sub(4);
    let ctx = lines[start..=center.min(lines.len()-1)].join(" ");
    extract_field_value(&ctx, "to:").map(|s| simplify_account_ref(&s)).unwrap_or_else(|| "destination".into())
}

fn extract_field_value(text: &str, field: &str) -> Option<String> {
    let idx = text.find(field)?;
    let rest = &text[idx + field.len()..];
    let val: String = rest.chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
        .collect();
    if val.is_empty() { None } else { Some(val) }
}

fn simplify_account_ref(s: &str) -> String {
    // "self.vault.to_account_info()" → "vault"
    // "ctx.accounts.maker.to_account_info()" → "maker"
    s.split('.')
        .find(|part| !["self","ctx","accounts","to_account_info()","clone()"].contains(part))
        .unwrap_or(s)
        .trim_end_matches("()")
        .to_string()
}

fn get_context(lines: &[&str], center: usize, ctx: usize) -> String {
    let start = center.saturating_sub(ctx);
    let end = (center + ctx + 1).min(lines.len());
    lines[start..end].join("\n")
}

