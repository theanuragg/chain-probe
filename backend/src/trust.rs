// backend/src/trust.rs
// Classifies every account field in every Accounts struct by trust level.
// Fully deterministic — derived from Anchor constraint attributes only, no AI.
//
// Classification rules (priority order):
//   1. seeds = [...]        → ProgramControlled
//   2. Signer<'info>        → SignerRequired
//   3. Program<> / Sysvar<> → ProgramControlled
//   4. has_one = X where X is SignerRequired / ProgramControlled → IndirectlyVerified
//   5. constraint = ...     → UserSuppliedVerified
//   6. Account<T> typed     → UserSuppliedVerified  (discriminator checked)
//   7. SystemAccount        → UserSuppliedVerified  (owned by system, not signed)
//   8. AccountInfo          → UserSuppliedUnverified

use std::collections::HashMap;
use crate::{
    ast_visitor::ProjectVisitor,
    types::{AccountField, AccountTrust},
};

pub struct TrustAnalyzer<'a> {
    visitor: &'a ProjectVisitor,
}

impl<'a> TrustAnalyzer<'a> {
    pub fn new(visitor: &'a ProjectVisitor) -> Self {
        TrustAnalyzer { visitor }
    }

    /// Returns: instruction_name -> account_name -> AccountTrust
    pub fn build_trust_map(&self) -> HashMap<String, HashMap<String, AccountTrust>> {
        let mut map: HashMap<String, HashMap<String, AccountTrust>> = HashMap::new();

        for acct_struct in &self.visitor.account_structs {
            let instr_name = self.visitor.instructions.iter()
                .find(|i| i.ctx_type == acct_struct.name)
                .map(|i| i.name.clone())
                .unwrap_or_else(|| acct_struct.name.clone());

            // Pass 1: classify each field independently
            let mut field_trust: HashMap<String, AccountTrust> = acct_struct.fields.iter()
                .map(|f| (f.name.clone(), classify_field(f)))
                .collect();

            // Pass 2: propagate trust through has_one chains
            // If field A has `has_one = B` and B is SignerRequired/ProgramControlled,
            // then A is IndirectlyVerified (if it wasn't already more trusted)
            for field in &acct_struct.fields {
                if !field.has_has_one { continue; }

                let has_one_targets = extract_has_one_targets(&field.constraints);
                for target in &has_one_targets {
                    let target_trust = field_trust.get(target.as_str()).cloned();
                    if matches!(
                        target_trust,
                        Some(AccountTrust::SignerRequired) | Some(AccountTrust::ProgramControlled)
                    ) {
                        let current_risk = field_trust
                            .get(&field.name)
                            .map(|t| t.risk_score())
                            .unwrap_or(10);
                        if current_risk > AccountTrust::IndirectlyVerified.risk_score() {
                            field_trust.insert(
                                field.name.clone(),
                                AccountTrust::IndirectlyVerified,
                            );
                        }
                    }
                }
            }

            map.insert(instr_name, field_trust);
        }

        map
    }
}

/// Classify a single account field from its Anchor attributes
fn classify_field(field: &AccountField) -> AccountTrust {
    // Rule 1: PDA seeds → program-controlled
    if !field.seeds.is_empty() {
        return AccountTrust::ProgramControlled;
    }

    // Rule 2: Signer<'info>
    if field.is_signer || field.field_type.contains("Signer") {
        return AccountTrust::SignerRequired;
    }

    // Rule 3: Program<> / Sysvar<> — infrastructure accounts
    if field.field_type.contains("Program <")
        || field.field_type.contains("Sysvar <")
    {
        return AccountTrust::ProgramControlled;
    }

    // Rule 4: SystemAccount — owned by System Program but caller-chosen
    if field.field_type.contains("SystemAccount") {
        return AccountTrust::UserSuppliedVerified;
    }

    // Rule 5: Raw AccountInfo — no runtime checks at all
    if field.field_type.contains("AccountInfo") {
        return AccountTrust::UserSuppliedUnverified;
    }

    // Rule 6: Typed account with additional constraints
    if field.has_constraint || field.has_has_one {
        return AccountTrust::UserSuppliedVerified;
    }

    // Rule 7: Typed account — only discriminator is checked
    AccountTrust::UserSuppliedVerified
}

/// Parse `has_one = target` / `has_one = target @ Err` from constraint strings
pub fn extract_has_one_targets(constraints: &[String]) -> Vec<String> {
    let mut targets = vec![];
    for c in constraints {
        // Constraint strings look like: "# [account (has_one = authority)]"
        let mut remaining = c.as_str();
        while let Some(idx) = remaining.find("has_one") {
            remaining = &remaining[idx + 7..];
            // Skip whitespace and '='
            let value = remaining
                .trim_start_matches(|ch: char| ch == ' ' || ch == '=' || ch == '_')
                .trim_start();
            // Read until non-identifier char
            let end = value
                .find(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .unwrap_or(value.len());
            let target = value[..end].trim().to_string();
            if !target.is_empty() {
                targets.push(target);
            }
        }
    }
    targets
}
