// backend/src/taint.rs
// Taint analysis: tracks attacker-controlled values from sources to security sinks.
// This is what pattern matching cannot do — it follows values through the program,
// not just looks at surface syntax.
//
// Sources (attacker-influenced values):
//   • Instruction parameters (user supplies directly)
//   • Account fields with trust = UserSuppliedUnverified
//   • Values derived from tainted sources via arithmetic / assignment
//
// Sinks (security-sensitive operations):
//   • token::transfer amount argument
//   • Authority key comparisons
//   • PDA seed components
//   • require!() condition variables
//   • Persistent state field writes
//
// Algorithm:
//   For each instruction, walk the function body AST.
//   Build a taint set: Set<variable_name>.
//   On each statement, check:
//     - Is the RHS tainted? → mark LHS as tainted.
//     - Does a tainted value reach a sink? → emit TaintFlow.

use std::collections::{HashMap, HashSet};
use crate::{
    ast_visitor::ProjectVisitor,
    types::{
        AccountTrust, Finding, InputFile, Severity, TaintFlow,
        TaintHop, TaintSink, TaintSource,
    },
};

pub struct TaintEngine<'a> {
    visitor: &'a ProjectVisitor,
}

impl<'a> TaintEngine<'a> {
    pub fn new(visitor: &'a ProjectVisitor) -> Self {
        TaintEngine { visitor }
    }

    pub fn analyze(&self, files: &[InputFile]) -> Vec<TaintFlow> {
        let mut flows = vec![];
        let mut flow_id = 0u32;

        for file in files {
            if !file.path.ends_with(".rs") { continue; }
            flows.extend(self.analyze_file(
                &file.path,
                &file.content,
                &mut flow_id,
            ));
        }

        flows
    }

    fn analyze_file(
        &self,
        path: &str,
        content: &str,
        flow_id: &mut u32,
    ) -> Vec<TaintFlow> {
        let mut flows = vec![];
        let lines: Vec<&str> = content.lines().collect();

        // Find each instruction handler in this file
        for instr in &self.visitor.instructions {
            if instr.file != path { continue; }

            // Build initial taint set from instruction parameters
            let mut tainted: HashSet<String> = HashSet::new();
            let mut taint_hops: HashMap<String, Vec<TaintHop>> = HashMap::new();

            // All instruction params are tainted (user-supplied)
            for param in &instr.params {
                // param looks like "amount : u64" or "seed : u64"
                let name = param.split(':').next()
                    .unwrap_or("")
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !name.is_empty() {
                    tainted.insert(name.clone());
                    taint_hops.insert(name.clone(), vec![TaintHop {
                        operation: "instruction_parameter".into(),
                        description: format!("User supplies `{}` directly", param.trim()),
                        file: path.to_string(),
                        line: instr.line,
                        snippet: format!("pub fn {}(..., {}, ...)", instr.name, param.trim()),
                    }]);
                }
            }

            // Account fields with UserSuppliedUnverified trust are tainted
            if let Some(acct_struct) = self.visitor.account_structs.iter()
                .find(|s| s.name == instr.ctx_type)
            {
                let trust_map = self.trust_for_struct(&acct_struct.name);
                for field in &acct_struct.fields {
                    let trust = trust_map.get(&field.name)
                        .cloned()
                        .unwrap_or(AccountTrust::UserSuppliedUnverified);
                    if trust == AccountTrust::UserSuppliedUnverified {
                        tainted.insert(field.name.clone());
                        taint_hops.insert(field.name.clone(), vec![TaintHop {
                            operation: "unverified_account".into(),
                            description: format!(
                                "`{}` is AccountInfo<'info> — zero runtime verification",
                                field.name
                            ),
                            file: acct_struct.file.clone(),
                            line: acct_struct.line,
                            snippet: format!("pub {}: AccountInfo<'info>", field.name),
                        }]);
                    }
                }
            }

            // Walk instruction body in the file
            self.trace_function_body(
                &instr.name,
                path,
                &lines,
                &mut tainted,
                &mut taint_hops,
                &mut flows,
                flow_id,
            );
        }

        flows
    }

    /// Line-level taint propagation through a function body
    fn trace_function_body(
        &self,
        fn_name: &str,
        path: &str,
        lines: &[&str],
        tainted: &mut HashSet<String>,
        hops: &mut HashMap<String, Vec<TaintHop>>,
        flows: &mut Vec<TaintFlow>,
        flow_id: &mut u32,
    ) {
        let mut in_fn = false;
        let mut fn_start = 0usize;
        let mut brace_depth = 0i32;

        for (i, &line) in lines.iter().enumerate() {
            let t = line.trim();

            // Find function start
            if (t.starts_with("pub fn ") || t.starts_with("fn "))
                && t.contains(fn_name)
            {
                in_fn = true;
                fn_start = i;
                brace_depth = 0;
            }

            if !in_fn { continue; }

            brace_depth += line.chars().filter(|&c| c == '{').count() as i32;
            brace_depth -= line.chars().filter(|&c| c == '}').count() as i32;
            if brace_depth <= 0 && i > fn_start + 1 { in_fn = false; continue; }

            //   Assignment propagation                   
            // let x = <expr> — if expr contains tainted var, x is tainted
            if t.starts_with("let ") && t.contains('=') {
                let lhs = t.split('=').next().unwrap_or("")
                    .trim_start_matches("let ")
                    .trim_start_matches("mut ")
                    .trim()
                    .split(':').next().unwrap_or("").trim().to_string();

                let rhs = t.split('=').skip(1).collect::<Vec<_>>().join("=");

                if is_tainted_expr(&rhs, tainted) && !lhs.is_empty() {
                    let tainted_source = tainted_vars_in_expr(&rhs, tainted);
                    let parent_hops = tainted_source.iter()
                        .flat_map(|v| hops.get(v).cloned().unwrap_or_default())
                        .collect::<Vec<_>>();

                    let mut new_hops = parent_hops;
                    new_hops.push(TaintHop {
                        operation: "assignment".into(),
                        description: format!("`{}` derives from tainted `{}`", lhs, tainted_source.join(", ")),
                        file: path.to_string(),
                        line: i + 1,
                        snippet: t.to_string(),
                    });

                    tainted.insert(lhs.clone());
                    hops.insert(lhs, new_hops);
                }
            }

            //   Augmented assignment (+=, -=, *=)             
            if (t.contains("+=") || t.contains("-=") || t.contains("*="))
                && !t.starts_with("//")
            {
                let lhs = t.split(|c| c == '+' || c == '-' || c == '*')
                    .next().unwrap_or("").trim()
                    .trim_start_matches("self.").to_string();
                let rhs_parts: Vec<&str> = t.splitn(2, '=').collect();
                let rhs = rhs_parts.get(1).unwrap_or(&"");

                if is_tainted_expr(rhs, tainted) {
                    let field_var = lhs.split('.').last().unwrap_or(&lhs).to_string();
                    let src_vars = tainted_vars_in_expr(rhs, tainted);

                    let mut new_hops = src_vars.iter()
                        .flat_map(|v| hops.get(v).cloned().unwrap_or_default())
                        .collect::<Vec<_>>();
                    new_hops.push(TaintHop {
                        operation: "state_write".into(),
                        description: format!("Tainted value written to `{}`", lhs),
                        file: path.to_string(),
                        line: i + 1,
                        snippet: t.to_string(),
                    });

                    // If we can resolve the state type, check field type for severity
                    // e.g. "self.vault.balance += amount_in" — balance is u64 → HIGH
                    //      "self.config.authority = ..." — authority is Pubkey → CRITICAL
                    let state_sev = self.resolve_state_field_access(&lhs)
                        .map(|(st, fd)| self.taint_severity_for_state_field(&st, &fd));

                    if let Some(sev) = state_sev {
                        if sev == Severity::Critical || sev == Severity::High {
                            let src_var = src_vars.first().cloned().unwrap_or_else(|| field_var.clone());
                            *flow_id += 1;
                            let (state_type, field_name) = self.resolve_state_field_access(&lhs)
                                .unwrap_or(("unknown".to_string(), field_var.clone()));
                            let type_str = self.state_field_type(&state_type, &field_name)
                                .unwrap_or_else(|| "unknown".to_string());

                            flows.push(TaintFlow {
                                id: format!("TAINT-{flow_id:03}"),
                                instruction: fn_name.to_string(),
                                source: TaintSource {
                                    taint_type: "instruction_param".into(),
                                    name: src_var.clone(),
                                    file: path.to_string(),
                                    line: 0,
                                },
                                sink: TaintSink {
                                    sink_type: "state_mutation".into(),
                                    description: format!(
                                        "Tainted `{}` written to `{}` (type: `{}`). {}",
                                        src_var, lhs, type_str,
                                        if type_str.contains("Pubkey") {
                                            "Pubkey field — attacker may control stored authority."
                                        } else {
                                            "Economic field — attacker may inflate/deflate balances."
                                        }
                                    ),
                                    file: path.to_string(),
                                    line: i + 1,
                                },
                                path: new_hops.clone(),
                                severity: sev,
                                finding_id: None,
                            });
                        }
                    }

                    tainted.insert(field_var.clone());
                    hops.insert(field_var, new_hops);
                }
            }

            //   Direct state field assignment               ─
            // Detect: self.vault.authority = ctx.accounts.authority.key()
            // where the RHS is tainted or derives from an unverified account
            let is_direct_assign = t.contains('=')
                && !t.contains("==") && !t.contains("+=") && !t.contains("-=")
                && !t.contains("*=") && !t.starts_with("let ")
                && !t.starts_with("//")
                && (t.starts_with("self.") || t.contains(".authority =")
                    || t.contains(".key =") || t.contains(".owner ="));

            if is_direct_assign {
                let parts: Vec<&str> = t.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let lhs = parts[0].trim();
                    let rhs = parts[1].trim();

                    // Is this writing to a known Pubkey field?
                    let is_pubkey_write = lhs.contains("authority") || lhs.contains("owner")
                        || lhs.contains("admin") || lhs.contains("maker")
                        || lhs.contains("operator") || lhs.contains("creator");

                    // RHS comes from an unverified account's key()
                    let from_unverified = tainted_vars_in_expr(rhs, tainted);
                    let is_from_account_key = rhs.contains(".key()") || rhs.contains(".key");

                    if (is_pubkey_write && is_from_account_key) || !from_unverified.is_empty() {
                        let src_var = if !from_unverified.is_empty() {
                            from_unverified[0].clone()
                        } else {
                            // Extract account name from rhs like "ctx.accounts.authority.key()"
                            rhs.split('.').find(|p| !["ctx","accounts","key()","key"].contains(p))
                               .unwrap_or("authority").to_string()
                        };

                        let sev = if let Some((ref st, ref fd)) = self.resolve_state_field_access(lhs) {
                            self.taint_severity_for_state_field(st, fd)
                        } else if is_pubkey_write {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        if sev == Severity::Critical || sev == Severity::High {
                            *flow_id += 1;
                            let mut flow_hops = hops.get(&src_var).cloned().unwrap_or_default();
                            flow_hops.push(TaintHop {
                                operation: "authority_stored".into(),
                                description: format!(
                                    "Unverified account key written to `{}` — stored authority is now attacker-controlled",
                                    lhs
                                ),
                                file: path.to_string(),
                                line: i + 1,
                                snippet: t.to_string(),
                            });

                            flows.push(TaintFlow {
                                id: format!("TAINT-{flow_id:03}"),
                                instruction: fn_name.to_string(),
                                source: TaintSource {
                                    taint_type: "unverified_account".into(),
                                    name: src_var.clone(),
                                    file: path.to_string(),
                                    line: 0,
                                },
                                sink: TaintSink {
                                    sink_type: "authority_stored".into(),
                                    description: format!(
                                        "Unverified account key stored in `{}`. Any subsequent `has_one = {}` check only verifies key equality — an attacker who controlled this write controls who passes that check.",
                                        lhs, src_var
                                    ),
                                    file: path.to_string(),
                                    line: i + 1,
                                },
                                path: flow_hops,
                                severity: sev,
                                finding_id: None,
                            });

                            // Also taint the lhs field so subsequent uses are tracked
                            let field_var = lhs.split('.').last().unwrap_or(lhs).to_string();
                            tainted.insert(field_var.clone());
                            hops.entry(field_var).or_insert_with(Vec::new);
                        }
                    }
                }
            }

            //   Sink: token transfer                    
            let is_transfer = t.contains("transfer(") || t.contains("transfer_checked(");
            if is_transfer {
                // Check if any tainted variable appears in the arguments
                // Transfer amount is typically the penultimate arg
                let tainted_in_call = tainted_vars_in_expr(t, tainted);
                if !tainted_in_call.is_empty() {
                    *flow_id += 1;
                    let src_var = tainted_in_call[0].clone();
                    let mut flow_hops = hops.get(&src_var).cloned().unwrap_or_default();
                    flow_hops.push(TaintHop {
                        operation: "sink_reached".into(),
                        description: "Tainted value reaches token transfer amount".into(),
                        file: path.to_string(),
                        line: i + 1,
                        snippet: t.to_string(),
                    });

                    flows.push(TaintFlow {
                        id: format!("TAINT-{flow_id:03}"),
                        instruction: fn_name.to_string(),
                        source: TaintSource {
                            taint_type: "instruction_param_or_unverified_account".into(),
                            name: src_var.clone(),
                            file: path.to_string(),
                            line: 0,
                        },
                        sink: TaintSink {
                            sink_type: "token_transfer_amount".into(),
                            description: format!(
                                "Tainted `{}` reaches token transfer — attacker may control transfer amount",
                                src_var
                            ),
                            file: path.to_string(),
                            line: i + 1,
                        },
                        path: flow_hops,
                        severity: Severity::Critical,
                        finding_id: None,
                    });
                }
            }

            //   Sink: require!() with tainted condition          ─
            if t.contains("require!") || t.contains("require_eq!") || t.contains("require_gte!") {
                let tainted_in_require = tainted_vars_in_expr(t, tainted);
                if !tainted_in_require.is_empty() {
                    *flow_id += 1;
                    let src_var = tainted_in_require[0].clone();
                    let mut flow_hops = hops.get(&src_var).cloned().unwrap_or_default();
                    flow_hops.push(TaintHop {
                        operation: "sink_reached".into(),
                        description: format!("Tainted `{}` appears in require! condition — attacker may influence invariant", src_var),
                        file: path.to_string(),
                        line: i + 1,
                        snippet: t.to_string(),
                    });

                    // Extract the condition text
                    let condition = extract_between(t, "require!(", ")");

                    flows.push(TaintFlow {
                        id: format!("TAINT-{flow_id:03}"),
                        instruction: fn_name.to_string(),
                        source: TaintSource {
                            taint_type: "instruction_param_or_unverified_account".into(),
                            name: src_var.clone(),
                            file: path.to_string(),
                            line: 0,
                        },
                        sink: TaintSink {
                            sink_type: "require_condition".into(),
                            description: format!(
                                "Tainted `{}` in: `require!({})` — attacker may force this condition to pass or fail",
                                src_var, condition.trim()
                            ),
                            file: path.to_string(),
                            line: i + 1,
                        },
                        path: flow_hops,
                        severity: Severity::High,
                        finding_id: None,
                    });
                }
            }

            //   Sink: division where tainted is denominator        ─
            // Division by a tainted value = divide-by-zero or manipulation
            if t.contains('/') && !t.starts_with("//") {
                let parts: Vec<&str> = t.splitn(2, '/').collect();
                if parts.len() == 2 {
                    let denominator = parts[1];
                    let tainted_denom = tainted_vars_in_expr(denominator, tainted);
                    if !tainted_denom.is_empty() {
                        *flow_id += 1;
                        let src_var = tainted_denom[0].clone();
                        flows.push(TaintFlow {
                            id: format!("TAINT-{flow_id:03}"),
                            instruction: fn_name.to_string(),
                            source: TaintSource {
                                taint_type: "instruction_param".into(),
                                name: src_var.clone(),
                                file: path.to_string(),
                                line: 0,
                            },
                            sink: TaintSink {
                                sink_type: "division_denominator".into(),
                                description: format!(
                                    "Tainted `{}` used as division denominator — attacker could cause divide-by-zero or precision manipulation",
                                    src_var
                                ),
                                file: path.to_string(),
                                line: i + 1,
                            },
                            path: hops.get(&src_var).cloned().unwrap_or_default(),
                            severity: Severity::Medium,
                            finding_id: None,
                        });
                    }
                }
            }
        }
    }

    /// Look up the trust map for a given Accounts struct name
    fn trust_for_struct(&self, struct_name: &str) -> HashMap<String, AccountTrust> {
        let mut map = HashMap::new();
        if let Some(s) = self.visitor.account_structs.iter().find(|s| s.name == struct_name) {
            for f in &s.fields {
                let trust = if !f.seeds.is_empty() {
                    AccountTrust::ProgramControlled
                } else if f.is_signer || f.field_type.contains("Signer") {
                    AccountTrust::SignerRequired
                } else if f.field_type.contains("AccountInfo") {
                    AccountTrust::UserSuppliedUnverified
                } else {
                    AccountTrust::UserSuppliedVerified
                };
                map.insert(f.name.clone(), trust);
            }
        }
        map
    }

    /// Given a state struct name and field name, return the field's Rust type.
    /// e.g. state_field_type("Vault", "balance") → Some("u64")
    ///      state_field_type("Pool", "authority") → Some("Pubkey")
    fn state_field_type(&self, state_name: &str, field_name: &str) -> Option<String> {
        self.visitor.state_account_fields
            .get(state_name)
            .and_then(|fields| {
                fields.iter()
                    .find(|(fname, _)| fname == field_name)
                    .map(|(_, ftype)| ftype.clone())
            })
    }

    /// Given an expression like "self.vault.balance" or "ctx.accounts.pool.reserve_a",
    /// try to resolve the state struct name and field name.
    /// Returns (state_type, field_name) if found.
    fn resolve_state_field_access(&self, expr: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = expr.split('.').collect();
        if parts.len() < 2 { return None; }
        let field = parts.last()?;
        for acct_struct in &self.visitor.account_structs {
            for account_field in &acct_struct.fields {
                let account_name = &account_field.name;
                if parts.iter().any(|p| *p == account_name.as_str()) {
                    if let Some(st) = self.resolve_account_state_type(account_field.field_type.as_str()) {
                        if self.state_field_type(&st, field).is_some() {
                            return Some((st, field.to_string()));
                        }
                    }
                }
            }
        }
        None
    }

    fn resolve_account_state_type(&self, field_type: &str) -> Option<String> {
        if let Some(start) = field_type.find("Account<") {
            let inner = &field_type[start + 8..];
            if let Some(comma) = inner.rfind(',') {
                let candidate = inner[comma + 1..].trim().trim_end_matches('>').trim();
                if self.visitor.state_account_fields.contains_key(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }
        None
    }

    fn taint_severity_for_state_field(&self, state_type: &str, field_name: &str) -> Severity {
        let ftype = match self.state_field_type(state_type, field_name) {
            Some(t) => t.clone(),
            None => return Severity::Medium,
        };

        if ftype.contains("Pubkey") {
            // Tainted Pubkey field = authority bypass = Critical
            Severity::Critical
        } else if ftype == "u64" || ftype == "u128" || ftype == "i64" || ftype == "i128" {
            // Tainted numeric field that likely affects economics = High
            let economic_names = ["balance", "amount", "reserve", "supply",
                                   "total", "fee", "rate", "reward", "staked",
                                   "deposit", "borrow", "liquidity"];
            if economic_names.iter().any(|n| field_name.contains(n)) {
                Severity::High
            } else {
                Severity::Medium
            }
        } else if ftype == "bool" {
            // Tainted bool = could be a pause/freeze flag bypass
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

//   Helpers                                  ─

/// Check whether an expression string contains any tainted variable
fn is_tainted_expr(expr: &str, tainted: &HashSet<String>) -> bool {
    tainted.iter().any(|v| expr_contains_var(expr, v))
}

/// Return which tainted variables appear in an expression
fn tainted_vars_in_expr(expr: &str, tainted: &HashSet<String>) -> Vec<String> {
    tainted.iter()
        .filter(|v| expr_contains_var(expr, v))
        .cloned()
        .collect()
}

/// Check if a variable name appears as a whole word in an expression
fn expr_contains_var(expr: &str, var: &str) -> bool {
    let bytes = expr.as_bytes();
    let var_bytes = var.as_bytes();
    if var_bytes.is_empty() { return false; }

    let mut i = 0;
    while i + var_bytes.len() <= bytes.len() {
        if &bytes[i..i + var_bytes.len()] == var_bytes {
            let before_ok = i == 0 || !bytes[i-1].is_ascii_alphanumeric() && bytes[i-1] != b'_';
            let after = i + var_bytes.len();
            let after_ok = after == bytes.len()
                || !bytes[after].is_ascii_alphanumeric() && bytes[after] != b'_';
            if before_ok && after_ok { return true; }
        }
        i += 1;
    }
    false
}

fn extract_between(s: &str, start: &str, end: &str) -> String {
    if let Some(si) = s.find(start) {
        let rest = &s[si + start.len()..];
        if let Some(ei) = rest.rfind(end) {
            return rest[..ei].to_string();
        }
    }
    s.to_string()
}
