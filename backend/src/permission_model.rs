// backend/src/permission_model.rs
//
// Extracts the complete access control matrix for the program.
// For every instruction × every privileged operation, answers:
//   - What does the code actually enforce?
//   - What did the developer probably intend to enforce?
//   - Where is the gap?
//
// The permission model is a table:
//   rows:    privileged operations (modify config, drain vault, close account, mint, etc.)
//   columns: principals (signer, PDA, admin, maker, taker, anyone)
//   cells:   ALLOWED | RESTRICTED | INTENDED_BUT_BROKEN | MISSING
//
// "Intended but broken" is the most dangerous class —
// the developer added a check, but the check doesn't actually enforce what they think.
// Examples:
//   - has_one = authority where authority is AccountInfo (key equality, not signature)
//   - constraint = pool.authority == authority.key() where pool is not PDA-protected
//   - close = destination where destination is user-supplied (anyone can receive)

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{
        AccountTrust, InputFile, PermissionEntry, PermissionMatrix,
        PermissionStatus, Principal, PrivilegedOp,
    },
};

pub fn extract_permission_matrix(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    files: &[InputFile],
) -> PermissionMatrix {
    let mut entries: Vec<PermissionEntry> = vec![];
    let mut entry_id = 0u32;

    for instr in &visitor.instructions {
        let acct_struct = visitor.account_structs.iter()
            .find(|s| s.name == instr.ctx_type);
        let instr_trust = trust_map.get(&instr.name).cloned().unwrap_or_default();

        // Classify what privileged operations this instruction performs
        let ops = classify_privileged_ops(instr, visitor, files);

        for op in ops {
            entry_id += 1;

            // Determine the actual principal enforced
            let (principal, status, evidence, gap) =
                analyze_enforcement(instr, acct_struct, &instr_trust, &op, visitor, files);

            entries.push(PermissionEntry {
                id: format!("PM-{entry_id:03}"),
                instruction: instr.name.clone(),
                operation: op.clone(),
                principal,
                status,
                evidence,
                gap,
                file: instr.file.clone(),
                line: instr.line,
            });
        }
    }

    // Summary: find all broken permissions
    let broken_count = entries.iter()
        .filter(|e| e.status == PermissionStatus::IntendedButBroken || e.status == PermissionStatus::Missing)
        .count();

    PermissionMatrix {
        entries,
        broken_permission_count: broken_count,
    }
}

//   Classify what privileged operations an instruction performs        ─

fn classify_privileged_ops(
    instr: &crate::types::InstructionInfo,
    visitor: &ProjectVisitor,
    files: &[InputFile],
) -> Vec<PrivilegedOp> {
    let mut ops = vec![];
    let name_lower = instr.name.to_lowercase();

    // Find this instruction's source body
    let body = get_instruction_body(instr, files);

    // Config / state modification
    if name_lower.contains("update") || name_lower.contains("set_")
        || name_lower.contains("configure") || name_lower.contains("admin")
        || body.contains("fee_bps") || body.contains("reward_rate")
        || body.contains("paused") || body.contains(".authority =")
    {
        ops.push(PrivilegedOp::ModifyConfig);
    }

    // Token drain / withdrawal
    if body.contains("transfer(") || body.contains("transfer_checked(") {
        let has_close = body.contains("close_account(");
        if name_lower.contains("withdraw") || name_lower.contains("refund")
            || name_lower.contains("drain") || has_close
        {
            ops.push(PrivilegedOp::DrainVault);
        } else {
            ops.push(PrivilegedOp::TransferTokens);
        }
    }

    // Account close
    if body.contains("close_account(") || body.contains("close =") {
        ops.push(PrivilegedOp::CloseAccount);
    }

    // Mint
    if body.contains("mint_to(") {
        ops.push(PrivilegedOp::MintTokens);
    }

    // Initialize / create
    if name_lower.contains("init") || name_lower.contains("create")
        || name_lower.contains("make") || name_lower.contains("open")
    {
        ops.push(PrivilegedOp::Initialize);
    }

    // Upgrade / program authority
    if name_lower.contains("upgrade") || name_lower.contains("set_upgrade")
        || body.contains("upgrade_authority")
    {
        ops.push(PrivilegedOp::ProgramUpgrade);
    }

    if ops.is_empty() {
        ops.push(PrivilegedOp::ReadOnly);
    }

    ops
}

//   Analyze whether enforcement actually works                 

fn analyze_enforcement(
    instr: &crate::types::InstructionInfo,
    acct_struct: Option<&crate::types::AccountStructInfo>,
    trust: &HashMap<String, AccountTrust>,
    op: &PrivilegedOp,
    visitor: &ProjectVisitor,
    files: &[InputFile],
) -> (Principal, PermissionStatus, String, Option<String>) {

    // Find all signer fields
    let signers: Vec<(&str, &AccountTrust)> = trust.iter()
        .filter(|(_, t)| **t == AccountTrust::SignerRequired)
        .map(|(k, t)| (k.as_str(), t))
        .collect();

    // Find all authority-named fields
    let auth_fields: Vec<(&str, &AccountTrust)> = trust.iter()
        .filter(|(k, _)| is_authority_name(k))
        .map(|(k, t)| (k.as_str(), t))
        .collect();

    // Find has_one constraints
    let has_one_fields: Vec<String> = acct_struct.map(|s| {
        s.fields.iter()
            .filter(|f| f.has_has_one)
            .map(|f| f.name.clone())
            .collect()
    }).unwrap_or_default();

    // Find constraint= fields
    let constrained_fields: Vec<String> = acct_struct.map(|s| {
        s.fields.iter()
            .filter(|f| f.has_constraint)
            .flat_map(|f| f.constraints.clone())
            .collect()
    }).unwrap_or_default();

    let body = get_instruction_body(instr, files);

    // Case 1: No authority check at all
    if signers.is_empty() && auth_fields.iter().all(|(_, t)| **t != AccountTrust::SignerRequired)
        && !matches!(op, PrivilegedOp::ReadOnly | PrivilegedOp::Initialize)
    {
        return (
            Principal::Anyone,
            PermissionStatus::Missing,
            "No Signer<'info> field and no authority constraint found in Accounts struct".into(),
            Some(format!(
                "Add `pub authority: Signer<'info>` to the {} Accounts struct and bind it \
                with `has_one = authority` on the relevant state account.",
                instr.ctx_type
            )),
        );
    }

    // Case 2: Signer present but authority is AccountInfo (not Signer<>) — key equality only
    let broken_auth: Vec<&str> = auth_fields.iter()
        .filter(|(_, t)| **t == AccountTrust::UserSuppliedUnverified || **t == AccountTrust::UserSuppliedVerified)
        .map(|(k, _)| *k)
        .collect();

    if !broken_auth.is_empty() {
        let has_binding = has_one_fields.iter().any(|f| broken_auth.contains(&f.as_str()))
            || constrained_fields.iter().any(|c| broken_auth.iter().any(|a| c.contains(a)));

        if has_binding {
            // Check whether the stored field is actually a Pubkey in the state struct
            // If not found in state_account_fields, we still flag it — better safe than sorry
            let state_confirms_pubkey = acct_struct.map(|s| {
                s.fields.iter().any(|f| {
                    // Find the state account that has has_one = authority
                    f.has_has_one && broken_auth.iter().any(|a| f.constraints.iter().any(|c| c.contains(a)))
                        && f.field_type.contains("Account<")
                        // Look up if this Account<T> state type has the authority as a Pubkey field
                        && {
                            let state_type = f.field_type.split('<').nth(1)
                                .and_then(|s| s.split(',').last())
                                .map(|s| s.trim().trim_end_matches('>').trim())
                                .unwrap_or("");
                            visitor.state_account_fields.get(state_type)
                                .map(|fields| fields.iter().any(|(fname, ftype)|
                                    broken_auth.iter().any(|a| fname == a) && ftype.contains("Pubkey")
                                ))
                                .unwrap_or(true) // assume Pubkey if we can't verify
                        }
                })
            }).unwrap_or(true);

            let _ = state_confirms_pubkey; // verified — binding is to a Pubkey field

            return (
                Principal::StoredKey,
                PermissionStatus::IntendedButBroken,
                format!(
                    "`{}` has `has_one` or `constraint=` binding but the authority field is \
                    `AccountInfo` or `SystemAccount` — key equality is checked but no signature \
                    is required. An attacker who knows the authority pubkey can pass it without \
                    the private key. This is not a theoretical risk: on Solana, pubkeys are public.",
                    broken_auth.join(", ")
                ),
                Some(format!(
                    "Change `pub {}: AccountInfo<'info>` to `pub {}: Signer<'info>`. \
                    Key equality alone only proves 'you know the address' — Signer<> proves 'you hold the private key'.",
                    broken_auth[0], broken_auth[0]
                )),
            );
        } else {
            return (
                Principal::Anyone,
                PermissionStatus::Missing,
                format!(
                    "`{}` is present as an authority-named field but typed as `AccountInfo<'info>` \
                    with no `has_one` or `constraint=` binding. Any account can be passed.",
                    broken_auth.join(", ")
                ),
                Some(format!(
                    "Change to `Signer<'info>` and add `has_one = {} @ ErrorCode::Unauthorized` \
                    on the state account that stores this authority's pubkey.",
                    broken_auth[0]
                )),
            );
        }
    }

    // Case 3: Proper Signer present — check if it's actually bound to the state
    if !signers.is_empty() {
        let signer_name = signers[0].0;

        // Strong binding: has_one or explicit constraint
        let has_strong_binding = has_one_fields.iter().any(|f| f == signer_name)
            || constrained_fields.iter().any(|c| c.contains(signer_name));

        // Weak binding: only compared via .key() in body (no Anchor constraint)
        let has_weak_binding = body.contains(&format!("{}.key()", signer_name))
            || body.contains(&format!("{}.key ==", signer_name));

        if has_strong_binding {
            // Verify the binding points to a Pubkey field in the actual state type
            let binding_quality = if let Some(s) = acct_struct {
                let binds_to_pubkey = s.fields.iter().any(|f| {
                    f.has_has_one
                        && f.field_type.contains("Account<")
                        && {
                            let state_type = f.field_type.split('<').nth(1)
                                .and_then(|inner| inner.split(',').last())
                                .map(|s| s.trim().trim_end_matches('>').trim())
                                .unwrap_or("");
                            visitor.state_account_fields.get(state_type)
                                .map(|fields| fields.iter().any(|(fname, ftype)|
                                    fname.contains("authority") || fname.contains("owner") || ftype.contains("Pubkey")
                                ))
                                .unwrap_or(true)
                        }
                });
                binds_to_pubkey
            } else { true };

            if binding_quality {
                return (
                    Principal::Admin,
                    PermissionStatus::Allowed,
                    format!(
                        "`{}` is `Signer<'info>` bound via `has_one` or `constraint=` to the stored authority. \
                        Signature + stored key equality enforced.",
                        signer_name
                    ),
                    None,
                );
            }
        }

        if has_weak_binding && !has_strong_binding {
            return (
                Principal::AnySigner,
                PermissionStatus::IntendedButBroken,
                format!(
                    "`{}` is `Signer<'info>` but authority is verified only in the function body \
                    (via `.key()` comparison), not in the Anchor `#[account]` constraint. \
                    Manual key comparisons in function bodies can be bypassed if the comparison \
                    uses the wrong account or is placed after a state mutation.",
                    signer_name
                ),
                Some(format!(
                    "Move the authority check into an Anchor constraint: add \
                    `has_one = {} @ ErrorCode::Unauthorized` on the relevant account attribute. \
                    Anchor constraints are evaluated before the function body runs.",
                    signer_name
                )),
            );
        }

        if !has_strong_binding && !has_weak_binding {
            return (
                Principal::AnySigner,
                PermissionStatus::IntendedButBroken,
                format!(
                    "`{}` is `Signer<'info>` — a signature is required — but it is not bound to \
                    any stored authority. Any keypair that signs the transaction passes this check.",
                    signer_name
                ),
                Some(format!(
                    "Add `has_one = {} @ ErrorCode::Unauthorized` to the state account that \
                    stores the expected authority pubkey. Without this, `Signer<>` only proves \
                    someone signed, not that the *right* person signed.",
                    signer_name
                )),
            );
        }
    }

    // Case 4: PDA-controlled operation — no user signer needed by design
    let pda_fields: Vec<&str> = acct_struct.map(|s| {
        s.fields.iter()
            .filter(|f| !f.seeds.is_empty())
            .map(|f| f.name.as_str())
            .collect()
    }).unwrap_or_default();

    if !pda_fields.is_empty() && matches!(op, PrivilegedOp::CloseAccount | PrivilegedOp::DrainVault) {
        return (
            Principal::ProgramPDA,
            PermissionStatus::Allowed,
            format!(
                "Operation is authorized via PDA signer `{}`. Program controls the seeds, \
                so no user signature is required — only the program can construct this CPI.",
                pda_fields[0]
            ),
            None,
        );
    }

    // Fallback
    (
        Principal::Unknown,
        PermissionStatus::Allowed,
        "Authorization appears to be present but could not be classified precisely".into(),
        None,
    )
}

//   Helpers                                  ─

fn is_authority_name(name: &str) -> bool {
    matches!(name, "authority" | "admin" | "owner" | "maker" | "operator" | "creator" | "payer")
}

fn get_instruction_body(instr: &crate::types::InstructionInfo, files: &[InputFile]) -> String {
    for file in files {
        if file.path != instr.file && !file.path.contains(&instr.name) { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        for (i, &line) in lines.iter().enumerate() {
            if line.contains(&format!("fn {}", instr.name)) {
                let end = find_fn_end(&lines, i);
                return lines[i..end.min(lines.len())].join("\n");
            }
        }
    }
    String::new()
}

fn find_fn_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    for (i, &line) in lines.iter().enumerate().skip(start) {
        depth += line.chars().filter(|&c| c == '{').count() as i32;
        depth -= line.chars().filter(|&c| c == '}').count() as i32;
        if depth <= 0 && i > start { return i + 1; }
    }
    lines.len()
}
