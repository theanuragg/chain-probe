// backend/src/chain_detector.rs
// Finds combinations of findings that together form an exploitable attack chain.
// Fully deterministic — uses data flow graph + finding metadata, no AI.
//
// Five chain patterns:
//   A) Unverified authority + mutable state  → account takeover
//   B) Missing signer + admin mutation       → privilege escalation
//   C) Arithmetic overflow + transfer path   → economic exploit
//   D) Reentrancy + mutable balance          → double-spend / drain
//   E) PDA collision + init_if_needed        → state overwrite

use crate::types::{
    AccountTrust, Category, DataFlowGraph, Finding, FlowLinkType,
    Severity, VulnChain,
};

pub fn detect_chains(
    findings: &[Finding],
    flow_graph: &DataFlowGraph,
) -> Vec<VulnChain> {
    let mut chains = vec![];
    let mut id: u32 = 0;
    let mut next_id = || { id += 1; format!("CHAIN-{id:02}") };

    chains.extend(pattern_a_account_takeover(findings, flow_graph, &mut next_id));
    chains.extend(pattern_b_privilege_escalation(findings, flow_graph, &mut next_id));
    chains.extend(pattern_c_arithmetic_to_transfer(findings, flow_graph, &mut next_id));
    chains.extend(pattern_d_reentrancy_drain(findings, flow_graph, &mut next_id));
    chains.extend(pattern_e_pda_overwrite(findings, &mut next_id));

    chains
}

//   Pattern A: Unverified authority + mutable state              ─
// Both findings in same instruction, or connected via data flow edge where
// the shared account has risk_score >= UserSuppliedVerified

fn pattern_a_account_takeover(
    findings: &[Finding],
    flow_graph: &DataFlowGraph,
    next_id: &mut impl FnMut() -> String,
) -> Vec<VulnChain> {
    let mut chains = vec![];

    let auth_findings: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::SignerAuthority | Category::AccountValidation)
            && (f.title.to_lowercase().contains("accountinfo")
                || f.title.to_lowercase().contains("authority"))
    }).collect();

    let mut_findings: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::AccountValidation)
            && f.title.to_lowercase().contains("mutable")
    }).collect();

    for af in &auth_findings {
        for mf in &mut_findings {
            if af.id == mf.id { continue; }

            let same_fn = af.function == mf.function;
            let flow_connected = flow_graph.edges.iter().any(|e| {
                let touches_af = e.from_instruction == af.function
                    || e.to_instruction == af.function;
                let touches_mf = e.from_instruction == mf.function
                    || e.to_instruction == mf.function;
                touches_af && touches_mf
                    && e.trust_at_destination.risk_score()
                        >= AccountTrust::UserSuppliedVerified.risk_score()
            });

            if !(same_fn || flow_connected) { continue; }

            chains.push(VulnChain {
                id: next_id(),
                severity: Severity::Critical,
                title: format!(
                    "Account takeover: unverified authority + unconstrained mutable state [{}+{}]",
                    af.id, mf.id
                ),
                finding_ids: vec![af.id.clone(), mf.id.clone()],
                description: format!(
                    "{} establishes an unverified authority account. {} exposes mutable state \
                    with no ownership binding. Because both are reachable in the same transaction \
                    context, an attacker can supply a forged authority AND a substituted mutable \
                    account simultaneously, achieving arbitrary write access to program state.",
                    af.id, mf.id
                ),
                exploit_steps: vec![
                    format!("Attacker creates an account that passes the type check for the authority field in `{}`", af.function),
                    "Attacker crafts a transaction passing their controlled account as authority — no signature required".into(),
                    format!("Because `{}` is mutable with no ownership binding, attacker supplies their own account", mf.function),
                    "Program writes to attacker-controlled state — full account takeover".into(),
                ],
                instructions_involved: unique_instrs(&[&af.function, &mf.function]),
                needs_ai_context: true,
                ai_explanation: None,
            });
        }
    }

    chains
}

//   Pattern B: Missing signer + admin mutation connected by flow        ─

fn pattern_b_privilege_escalation(
    findings: &[Finding],
    flow_graph: &DataFlowGraph,
    next_id: &mut impl FnMut() -> String,
) -> Vec<VulnChain> {
    let mut chains = vec![];

    let signer_missing: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::SignerAuthority)
    }).collect();

    let admin_unprotected: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::AccessControl)
            && f.title.to_lowercase().contains("admin")
    }).collect();

    for sf in &signer_missing {
        for af in &admin_unprotected {
            if sf.id == af.id || sf.function == af.function { continue; }

            // They must be connected by a flow edge
            let connected = flow_graph.edges.iter().any(|e| {
                (e.from_instruction == sf.function && e.to_instruction == af.function)
                || (e.from_instruction == af.function && e.to_instruction == sf.function)
            });

            if !connected { continue; }

            chains.push(VulnChain {
                id: next_id(),
                severity: Severity::Critical,
                title: format!(
                    "Privilege escalation: unsigned `{}` unlocks admin `{}` [{}+{}]",
                    sf.function, af.function, sf.id, af.id
                ),
                finding_ids: vec![sf.id.clone(), af.id.clone()],
                description: format!(
                    "{} shows `{}` lacks a proper signer check. {} shows `{}` has no access \
                    control. A shared account flows between these two instructions. An attacker \
                    who exploits the first gains state that satisfies the second instruction's \
                    inputs — escalating from no privilege to full admin control.",
                    sf.id, sf.function, af.id, af.function
                ),
                exploit_steps: vec![
                    format!("Attacker calls `{}` — signer check is missing, any account accepted", sf.function),
                    "Attacker now controls state shared with the admin instruction".into(),
                    format!("Attacker calls `{}` — no access control, anyone can invoke", af.function),
                    "Critical program parameters (fees, rates, authority) are now attacker-set".into(),
                ],
                instructions_involved: unique_instrs(&[&sf.function, &af.function]),
                needs_ai_context: true,
                ai_explanation: None,
            });
        }
    }

    chains
}

//   Pattern C: Arithmetic overflow feeding a token transfer          ─

fn pattern_c_arithmetic_to_transfer(
    findings: &[Finding],
    flow_graph: &DataFlowGraph,
    next_id: &mut impl FnMut() -> String,
) -> Vec<VulnChain> {
    let mut chains = vec![];

    let arith: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::ArithmeticOverflow)
    }).collect();

    for af in &arith {
        // This instruction has outgoing StoredPubkey or HasOne edges → it touches token accounts
        let feeds_transfer = flow_graph.edges.iter().any(|e| {
            e.from_instruction == af.function
                && matches!(e.link_type, FlowLinkType::StoredPubkey | FlowLinkType::HasOne)
        });

        // OR the function itself has CPI calls (from profile data via shared accounts)
        let has_shared_token = flow_graph.shared_accounts.iter().any(|sa| {
            sa.used_in.contains(&af.function)
                && (sa.account_name.contains("vault")
                    || sa.account_name.contains("token")
                    || sa.account_name.contains("ata")
                    || sa.account_name.contains("pool"))
        });

        if !(feeds_transfer || has_shared_token) { continue; }

        chains.push(VulnChain {
            id: next_id(),
            severity: Severity::Critical,
            title: format!(
                "Economic exploit: overflow in `{}` feeds token transfer [{}]",
                af.function, af.id
            ),
            finding_ids: vec![af.id.clone()],
            description: format!(
                "{} identifies arithmetic overflow in `{}` on a value that is passed directly \
                into a token transfer CPI. An attacker crafting input to trigger the overflow \
                will cause the program to transfer an incorrect amount — enabling fund drainage \
                or inflated reward extraction.",
                af.id, af.function
            ),
            exploit_steps: vec![
                format!("Attacker identifies inputs that cause overflow in `{}`", af.function),
                "u64 arithmetic wraps to attacker-favorable value (near-zero or near-max)".into(),
                "Wrapped value is passed as amount to token transfer CPI".into(),
                "Attacker receives inflated tokens or drains the vault with a dust payment".into(),
            ],
            instructions_involved: unique_instrs(&[&af.function]),
            needs_ai_context: false,
            ai_explanation: None,
        });
    }

    chains
}

//   Pattern D: Reentrancy + mutable balance → drain              

fn pattern_d_reentrancy_drain(
    findings: &[Finding],
    flow_graph: &DataFlowGraph,
    next_id: &mut impl FnMut() -> String,
) -> Vec<VulnChain> {
    let mut chains = vec![];

    let reentrant: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::Reentrancy)
    }).collect();

    let stale_or_arith: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(
            f.category,
            Category::ArithmeticOverflow | Category::AccountValidation
        ) && (f.title.to_lowercase().contains("mutable")
            || f.title.to_lowercase().contains("stale"))
    }).collect();

    for rf in &reentrant {
        for sf in &stale_or_arith {
            if rf.id == sf.id { continue; }

            let same_fn = rf.function == sf.function;
            let connected = flow_graph.edges.iter().any(|e| {
                (e.from_instruction == rf.function && e.to_instruction == sf.function)
                || (e.from_instruction == sf.function && e.to_instruction == rf.function)
            });

            if !(same_fn || connected) { continue; }

            chains.push(VulnChain {
                id: next_id(),
                severity: Severity::Critical,
                title: format!(
                    "Double-spend chain: reentrancy + stale balance in `{}` [{}+{}]",
                    rf.function, rf.id, sf.id
                ),
                finding_ids: vec![rf.id.clone(), sf.id.clone()],
                description: format!(
                    "{} shows a reentrancy vector in `{}` (state not updated before CPI). \
                    {} shows a stale or unchecked balance in the same or connected instruction. \
                    Combined, an attacker using a Token-2022 transfer hook can re-enter before \
                    state is committed and claim the same funds multiple times.",
                    rf.id, rf.function, sf.id
                ),
                exploit_steps: vec![
                    "Attacker deploys a malicious Token-2022 program that fires a transfer hook".into(),
                    format!("Attacker calls `{}` — CPI is made before state update", rf.function),
                    "Transfer hook fires mid-CPI, re-entering the same instruction".into(),
                    "Balance still shows pre-withdrawal value — second withdrawal succeeds".into(),
                    "Attacker repeats until vault is drained".into(),
                ],
                instructions_involved: unique_instrs(&[&rf.function, &sf.function]),
                needs_ai_context: true,
                ai_explanation: None,
            });
            break; // one chain per reentrancy finding
        }
    }

    chains
}

//   Pattern E: PDA seed collision + init_if_needed → state overwrite      

fn pattern_e_pda_overwrite(
    findings: &[Finding],
    next_id: &mut impl FnMut() -> String,
) -> Vec<VulnChain> {
    let mut chains = vec![];

    let pda_findings: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::PdaSeedCollision)
    }).collect();

    let init_findings: Vec<&Finding> = findings.iter().filter(|f| {
        matches!(f.category, Category::AccountValidation)
            && f.title.to_lowercase().contains("init_if_needed")
    }).collect();

    for pf in &pda_findings {
        for inf in &init_findings {
            chains.push(VulnChain {
                id: next_id(),
                severity: Severity::High,
                title: format!(
                    "State overwrite: predictable PDA + init_if_needed reinit [{}+{}]",
                    pf.id, inf.id
                ),
                finding_ids: vec![pf.id.clone(), inf.id.clone()],
                description: format!(
                    "{} identifies a PDA with static/predictable seeds. {} shows init_if_needed \
                    without a reinitialization guard. An attacker can pre-derive the PDA address, \
                    initialize it with forged data before the legitimate user, then the victim's \
                    init_if_needed call silently skips init and operates on attacker data.",
                    pf.id, inf.id
                ),
                exploit_steps: vec![
                    "Attacker observes PDA seeds — static seeds are fully predictable".into(),
                    "Attacker derives the same PDA address as a target user would".into(),
                    "Attacker pre-initializes the account with forged authority/state".into(),
                    "Victim calls init_if_needed — Anchor sees account exists, skips initialization".into(),
                    "Program operates on attacker-controlled state for the victim's session".into(),
                ],
                instructions_involved: unique_instrs(&[&pf.function, &inf.function]),
                needs_ai_context: false,
                ai_explanation: None,
            });
        }
    }

    chains
}

//   Helpers                                  ─

fn unique_instrs(fns: &[&str]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    fns.iter()
        .filter(|&&f| !f.is_empty() && seen.insert(f.to_string()))
        .map(|&f| f.to_string())
        .collect()
}
