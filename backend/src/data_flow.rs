// backend/src/data_flow.rs
// Builds a cross-instruction data flow graph.
// Answers: which accounts flow between instructions, and at what trust level?
//
// Three link types detected:
//   PdaSeeds    — same seeds across two structs → same physical account
//   HasOne      — has_one constraint binds account across instructions
//   StoredPubkey— state account stores a Pubkey field matching another account name
//
// SharedAccount detection identifies accounts reused across instructions,
// and flags trust_inconsistent where trust level degrades between uses.

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{AccountTrust, DataFlowEdge, DataFlowGraph, FlowLinkType, SharedAccount},
};

pub fn build_data_flow_graph(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
) -> DataFlowGraph {
    let edges = find_edges(visitor, trust_map);
    let shared_accounts = find_shared_accounts(visitor, trust_map);

    DataFlowGraph {
        edges,
        trust_map: trust_map.clone(),
        shared_accounts,
    }
}

//   Edge detection                               

fn find_edges(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
) -> Vec<DataFlowEdge> {
    let mut edges: Vec<DataFlowEdge> = vec![];
    let structs = &visitor.account_structs;

    for i in 0..structs.len() {
        for j in 0..structs.len() {
            if i == j { continue; }

            let src = &structs[i];
            let dst = &structs[j];

            let src_instr = instr_for_struct(visitor, &src.name);
            let dst_instr = instr_for_struct(visitor, &dst.name);

            //   Link type 1: matching PDA seeds                ─
            for sf in &src.fields {
                if sf.seeds.is_empty() { continue; }
                for df in &dst.fields {
                    if df.seeds.is_empty() { continue; }
                    if sf.seeds == df.seeds && sf.name == df.name {
                        let trust = trust_at(trust_map, &dst_instr, &df.name);
                        push_edge(&mut edges, DataFlowEdge {
                            from_instruction: src_instr.clone(),
                            to_instruction: dst_instr.clone(),
                            account_name: sf.name.clone(),
                            link_type: FlowLinkType::PdaSeeds,
                            trust_at_destination: trust,
                        });
                    }
                }
            }

            //   Link type 2: has_one binding                  
            for sf in &src.fields {
                for df in &dst.fields {
                    if sf.name == df.name
                        && !sf.field_type.is_empty()
                        && type_base(&sf.field_type) == type_base(&df.field_type)
                        && df.has_has_one
                    {
                        let trust = trust_at(trust_map, &dst_instr, &df.name);
                        push_edge(&mut edges, DataFlowEdge {
                            from_instruction: src_instr.clone(),
                            to_instruction: dst_instr.clone(),
                            account_name: sf.name.clone(),
                            link_type: FlowLinkType::HasOne,
                            trust_at_destination: trust,
                        });
                    }
                }
            }

            //   Link type 3: stored pubkey                   
            // src has a state account whose struct has a Pubkey field named X,
            // and dst also has a field named X.
            for sf in &src.fields {
                let inner_type = type_base(&sf.field_type);
                if inner_type.is_empty() { continue; }

                // Find the state struct for this field's type
                if let Some(state_struct) = visitor.account_structs.iter()
                    .find(|s| s.name == inner_type)
                {
                    for state_field in &state_struct.fields {
                        if !state_field.field_type.contains("Pubkey") { continue; }
                        for df in &dst.fields {
                            if df.name == state_field.name {
                                let trust = trust_at(trust_map, &dst_instr, &df.name);
                                push_edge(&mut edges, DataFlowEdge {
                                    from_instruction: src_instr.clone(),
                                    to_instruction: dst_instr.clone(),
                                    account_name: df.name.clone(),
                                    link_type: FlowLinkType::StoredPubkey,
                                    trust_at_destination: trust,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    edges
}

//   Shared account detection                          

fn find_shared_accounts(
    visitor: &ProjectVisitor,
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
) -> Vec<SharedAccount> {
    // account_name → Vec<(instruction_name, trust, account_type)>
    let mut uses: HashMap<String, Vec<(String, AccountTrust, String)>> = HashMap::new();

    let skip_names = ["system_program", "token_program", "associated_token_program",
                      "rent", "clock", "metadata_program"];

    for s in &visitor.account_structs {
        let instr = instr_for_struct(visitor, &s.name);
        for f in &s.fields {
            if skip_names.contains(&f.name.as_str()) { continue; }
            if f.field_type.contains("Program <") || f.field_type.contains("Sysvar <") {
                continue;
            }

            let trust = trust_at(trust_map, &instr, &f.name);
            uses.entry(f.name.clone())
                .or_default()
                .push((instr.clone(), trust, f.field_type.clone()));
        }
    }

    let mut shared: Vec<SharedAccount> = uses
        .into_iter()
        .filter(|(_, v)| v.len() >= 2)
        .map(|(account_name, v)| {
            let used_in: Vec<String> = v.iter().map(|(i, _, _)| i.clone()).collect();
            let account_type = v.first().map(|(_, _, t)| t.clone()).unwrap_or_default();

            let max_trust_risk = v.iter()
                .max_by_key(|(_, t, _)| t.risk_score())
                .map(|(_, t, _)| t.clone())
                .unwrap_or(AccountTrust::UserSuppliedUnverified);

            // Inconsistent if any two instructions have different trust discriminants
            let trust_inconsistent = v.windows(2).any(|w| {
                std::mem::discriminant(&w[0].1) != std::mem::discriminant(&w[1].1)
            });

            SharedAccount {
                account_name,
                account_type,
                used_in,
                max_trust_risk,
                trust_inconsistent,
            }
        })
        .collect();

    // Sort by highest risk first, then inconsistent ones to the top
    shared.sort_by(|a, b| {
        b.trust_inconsistent.cmp(&a.trust_inconsistent)
            .then(b.max_trust_risk.risk_score().cmp(&a.max_trust_risk.risk_score()))
    });

    shared
}

//   Helpers                                  ─

fn instr_for_struct(visitor: &ProjectVisitor, struct_name: &str) -> String {
    visitor.instructions.iter()
        .find(|i| i.ctx_type == struct_name)
        .map(|i| i.name.clone())
        .unwrap_or_else(|| struct_name.to_lowercase())
}

fn trust_at(
    trust_map: &HashMap<String, HashMap<String, AccountTrust>>,
    instr: &str,
    account: &str,
) -> AccountTrust {
    trust_map
        .get(instr)
        .and_then(|m| m.get(account))
        .cloned()
        .unwrap_or(AccountTrust::UserSuppliedUnverified)
}

/// Deduplicate by (from, to, account_name) — keep first occurrence
fn push_edge(edges: &mut Vec<DataFlowEdge>, new: DataFlowEdge) {
    let dup = edges.iter().any(|e| {
        e.from_instruction == new.from_instruction
            && e.to_instruction == new.to_instruction
            && e.account_name == new.account_name
    });
    if !dup { edges.push(new); }
}

/// Extract the base type from a generic string e.g. "Account < 'info , Vault >" → "Vault"
fn type_base(t: &str) -> String {
    if let Some(start) = t.find('<') {
        let inner = &t[start + 1..];
        if let Some(end) = inner.rfind('>') {
            return inner[..end]
                .split(',')
                .last()
                .unwrap_or("")
                .trim()
                .trim_start_matches('\'')
                .split_whitespace()
                .last()
                .unwrap_or("")
                .to_string();
        }
    }
    t.trim().to_string()
}
