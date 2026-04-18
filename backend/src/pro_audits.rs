// backend/src/pro_audits.rs
// Professional-grade audit patterns from Ackee, Neodyme, DeFimSOL
// Based on real audit reports and CVE findings

use crate::{
    ast_visitor::ProjectVisitor,
    types::{Category, Finding, InputFile, Severity},
};

pub fn detect_pro_audits(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut findings = vec![];
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // INTEGER & ARITHMETIC ATTACKS (Ackee, Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_integer_truncation(files, next_id));
    findings.extend(detect_overflow_underflow(files, next_id));
    findings.extend(detect_precision_loss(files, next_id));
    findings.extend(detect_double_spend(files, next_id));
    findings.extend(detect_integer_casting(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // ORACLE & PRICE MANIPULATION (Ackee, Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_oracle_manipulation(files, next_id));
    findings.extend(detect_price_oracle_access(files, next_id));
    findings.extend(detect_twap_manipulation(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // ACCESS CONTROL & UPGRADES (Ackee, Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_upgrade_authority(files, next_id));
    findings.extend(detect_freeze_authority_abuse(files, next_id));
    findings.extend(detect_mint_authority_abuse(files, next_id));
    findings.extend(detect_treasury_drain(files, next_id));
    findings.extend(detect_admin_functions(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // COLLATERAL & LIQUIDATION (Ackee)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_undercollateralized(files, next_id));
    findings.extend(detect_liquidation_frontrun(files, next_id));
    findings.extend(detect_health_factor_bypass(files, next_id));
    findings.extend(detect_liquidation_reserve_bypass(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // YIELD & RATE ATTACKS (Ackee)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_yield_drain(files, next_id));
    findings.extend(detect_rate_manipulation(files, next_id));
    findings.extend(detect_flash_loan_manipulation(files, next_id));
    findings.extend(detect_negative_yield(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // PROGRAM UPGRADE ATTACKS (Ackee, Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_upgradeable_program(files, next_id));
    findings.extend(detect_proxy_upgrade(files, next_id));
    findings.extend(detect_authority_transfer(files, next_id));
    findings.extend(detect_pause_timeline(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // CROSS-PROGRAM ATTACKS (Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_cross_program_attack(files, next_id));
    findings.extend(detect_wormhole_style(files, next_id));
    findings.extend(detect_sysvar_spoofing(files, next_id));
    findings.extend(detect_instruction_introspection(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // TOKEN SPECIFIC (Neodyme)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_spl_mint_bypass(files, next_id));
    findings.extend(detect_token_freeze_bypass(files, next_id));
    findings.extend(detect_transfer_fee_bypass(files, next_id));
    findings.extend(detect_unchecked_token_operation(files, next_id));
    
    // ═══════════════════════════════════════════════════════════════════════════════════════════════
    // STAKING & DELEGATION (DeFimSOL)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_staking_drain(files, next_id));
    findings.extend(detect_delegation_escrow(files, next_id));
    findings.extend(detect_validator_bribe(files, next_id));
    findings.extend(detect_vote_manipulation(files, next_id));
    
    findings
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// INTEGER & ARITHMETIC ATTACKS - #1 category in audits
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_integer_truncation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // u128 to u64 or u64 to u32 truncation - critical in financial code
        if file.content.contains("as u64") || file.content.contains("as u32") || file.content.contains("as u128") {
            // Check if it's in arithmetic context
            if file.content.contains("*") || file.content.contains("+") || file.content.contains("/") || 
               file.content.contains("balance") || file.content.contains("amount") || file.content.contains("rate") {
                if let Some(line) = find_line(file, "as u", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Critical,
                        category: Category::ArithmeticOverflow,
                        title: "Integer Truncation: Casting larger integer to smaller without checked conversion".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Integer truncation from larger to smaller type. \
                            Critical in MetaDAO audit - allowed inflated withdrawals.".to_string(),
                        recommendation: "Use try_into() with checked conversion".to_string(),
                        anchor_fix: "Use value.try_into().unwrap() or checked math".to_string(),
                        cwe: "CWE-190".to_string(),
                        needs_ai_context: true,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_overflow_underflow(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Direct arithmetic without checked
        if file.content.contains("+=") || file.content.contains("-=") || file.content.contains("*=") {
            if !file.content.contains("checked_") && !file.content.contains("saturating_") && 
               !file.content.contains("overflow") {
                if let Some(line) = find_line(file, "+=", 2).or_else(|| find_line(file, "*=", 2)) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Critical,
                        category: Category::ArithmeticOverflow,
                        title: "Overflow/Underflow: Unchecked arithmetic without checked_* or saturating_*".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Direct arithmetic without overflow checks. Can cause \
                            unexpected wrapping or panic.".to_string(),
                        recommendation: "Use checked_add, checked_mul, saturating_add".to_string(),
                        anchor_fix: "Use num_traits or checked math functions".to_string(),
                        cwe: "CWE-190".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_precision_loss(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Division before multiplication causes precision loss
        if file.content.contains("/") && file.content.contains("*") {
            let content = &file.content;
            if let Some(div_pos) = content.find("/=") {
                if let Some(mul_pos) = content.find("*=") {
                    if mul_pos > div_pos && mul_pos - div_pos < 50 {
                        if let Some(line) = find_line(file, "/", 2) {
                            out.push(Finding {
                                id: next_id(),
                                severity: Severity::Medium,
                                category: Category::ArithmeticOverflow,
                                title: "Precision Loss: Division before multiplication loses precision".to_string(),
                                file: file.path.clone(),
                                line: Some(line),
                                function: "".to_string(),
                                snippet: get_snippet(file, line),
                                description: "x * y / z loses more than x / z * y. Use multiply after divide.".to_string(),
                                recommendation: "Reorder: (x * y) / z instead of x / z * y".to_string(),
                                anchor_fix: "Use correct order of operations for precision".to_string(),
                                cwe: "CWE-190".to_string(),
                                needs_ai_context: false,
                                ai_explanation: None,
                                ai_severity: None,
                                exploitability: 0,
                                confirmed_by_taint: vec![],
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

fn detect_double_spend(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Transfer without updating balance before
        if file.content.contains("transfer") && !file.content.contains("state") && !file.content.contains("balance") {
            if let Some(line) = find_line(file, "transfer", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Critical,
                    category: Category::ArithmeticOverflow,
                    title: "Double Spend: Balance updated after transfer allows replay".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Transfer executed before state update. Can call transfer twice \
                        in same transaction.".to_string(),
                    recommendation: "Update balance state BEFORE external call".to_string(),
                    anchor_fix: "Update state first, then external call".to_string(),
                    cwe: "CWE-367".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_integer_casting(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Type cast between signed/unsigned
        if file.content.contains("as i") || file.content.contains("as u") {
            if let Some(line) = find_line(file, "as", 2) {
                let snippet = get_snippet(file, line);
                if snippet.contains("signed") || snippet.contains("unsigned") || snippet.contains("i64") || snippet.contains("u128") {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::ArithmeticOverflow,
                        title: "Unsafe Integer Cast: Type casting between signed/unsigned".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Converting between signed/unsigned can cause unexpected sign flip.".to_string(),
                        recommendation: "Use checked conversion or validate range".to_string(),
                        anchor_fix: "Use TryFrom or validate before cast".to_string(),
                        cwe: "CWE-190".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// ORACLE & PRICE MANIPULATION - Mango, Cream style
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_oracle_manipulation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Self-delivered price or single oracle
        if file.content.contains("price") || file.content.contains("rate") {
            if !file.content.contains("pyth") && !file.content.contains("switchboard") && 
               !file.content.contains("median") && !file.content.contains("time_weighted") {
                if let Some(line) = find_line(file, "price", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Critical,
                        category: Category::AccountValidation,
                        title: "Oracle Manipulation: Single source price feed".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Single oracle price feed can be manipulated (Mango Markets $110M exploit). \
                            Use TWAP or aggregated multi-oracle.".to_string(),
                        recommendation: "Use time-weighted price average or multi-oracle".to_string(),
                        anchor_fix: "Use switchboard/pyth with aggregation".to_string(),
                        cwe: "CWE-754".to_string(),
                        needs_ai_context: true,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_price_oracle_access(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Using stale price data
        if file.content.contains("get_price") || file.content.contains("load_price") {
            if !file.content.contains("confidence") && !file.content.contains("max_confidence") {
                if let Some(line) = find_line(file, "price", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccountValidation,
                        title: "Stale Price Oracle: No staleness check on price feed".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Oracle price could be stale without staleness check. Attacker can \
                            use outdated prices.".to_string(),
                        recommendation: "Check confidence/slot or use time-weighted average".to_string(),
                        anchor_fix: "Add staleness check: require!(price.timestamp > now - MAX_AGE)".to_string(),
                        cwe: "CWE-754".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_twap_manipulation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // TWAP without sufficient buffer
        if file.content.contains("twap") || file.content.contains("time_weighted") {
            if !file.content.contains("min_period") && !file.content.contains("min_samples") {
                if let Some(line) = find_line(file, "twap", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::AccountValidation,
                        title: "TWAP Manipulation: Insufficient buffer period for TWAP".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "TWAP with lowbuffer can be manipulated within voting period.".to_string(),
                        recommendation: "Use large min_samples or TWAP".to_string(),
                        anchor_fix: "Set TWAP min_period > attack cost".to_string(),
                        cwe: "CWE-754".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// ACCESS CONTROL - Rug pulls and admin abuse
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_upgrade_authority(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Upgrade authority single point of failure
        if file.content.contains("upgrade_authority") || file.content.contains("upgrader") {
            if !file.content.contains("multisig") && !file.content.contains("timelock") {
                if let Some(line) = find_line(file, "upgrade", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Single Admin Upgrade Authority: No timelock or multisig".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Single upgrade authority = rug pull vector. Use timelock or multisig.".to_string(),
                        recommendation: "Add timelock or multi-sig for upgrades".to_string(),
                        anchor_fix: "Add: #[account(upgrade_authority = multi_sig)]".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_freeze_authority_abuse(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Freeze authority can freeze funds
        if file.content.contains("freeze_authority") && !file.content.contains("no_freeze") {
            if let Some(line) = find_line(file, "freeze", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::High,
                    category: Category::AccessControl,
                    title: "Freeze Authority: Admin can freeze user funds".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Freeze authority can freeze all user tokens. Risk: rug pull.".to_string(),
                    recommendation: "Use no-freeze option or limited freeze".to_string(),
                    anchor_fix: "Add: set_freeze_authority(no_freeze = true)".to_string(),
                    cwe: "CWE-862".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_mint_authority_abuse(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Unlimited mint
        if file.content.contains("mint") && (file.content.contains("max_supply") || file.content.contains("supply:")) {
            if !file.content.contains("fixed_supply") && !file.content.contains("no_mint") {
                if let Some(line) = find_line(file, "mint", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Unlimited Mint: Admin can mint unlimited tokens".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Admin can inflate supply and dilute users. Use fixed or no-mint.".to_string(),
                        recommendation: "Remove mint authority or use no-mint".to_string(),
                        anchor_fix: "Set: max_supply = FIXED".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_treasury_drain(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Admin can drain treasury
        if file.content.contains("treasury") || file.content.contains("vault") {
            if file.content.contains("withdraw") || file.content.contains("drain") {
                if !file.content.contains("timelock") && !file.content.contains("multisig") {
                    if let Some(line) = find_line(file, "treasury", 2) {
                        out.push(Finding {
                            id: next_id(),
                            severity: Severity::Critical,
                            category: Category::AccessControl,
                            title: "Treasury Drain: Admin can withdraw all protocol funds".to_string(),
                            file: file.path.clone(),
                            line: Some(line),
                            function: "".to_string(),
                            snippet: get_snippet(file, line),
                            description: "Admin withdraw from treasury with no timelock. Full rug pull risk.".to_string(),
                            recommendation: "Add timelock or treasury governance".to_string(),
                            anchor_fix: "Add: treasury -> governance multisig".to_string(),
                            cwe: "CWE-862".to_string(),
                            needs_ai_context: false,
                            ai_explanation: None,
                            ai_severity: None,
                            exploitability: 0,
                            confirmed_by_taint: vec![],
                        });
                    }
                }
            }
        }
    }
    out
}

fn detect_admin_functions(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Any admin-only function
        if file.content.contains("admin") || file.content.contains("owner") || file.content.contains("authority") {
            if file.content.contains("pub fn") && !file.content.contains("pub owner") || !file.content.contains("Signer") {
                if let Some(line) = find_line(file, "admin", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Missing Admin Validation: Function with admin in name lacks check".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Function mentions admin but may not verify admin identity.".to_string(),
                        recommendation: "Explicit admin verification required".to_string(),
                        anchor_fix: "Add: require!(ctx.accounts.admin.key() == admin)".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// COLLATERAL & LIQUIDATION - lending protocol specific
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_undercollateralized(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Lending but no collateral check
        if file.content.contains("borrow") || file.content.contains("lend") {
            if !file.content.contains("collateral") && !file.content.contains("health") {
                if let Some(line) = find_line(file, "borrow", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Critical,
                        category: Category::AccountValidation,
                        title: "Undercollateralized Lending: No collateral verification before loan".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "User can borrow without sufficient collateral value.".to_string(),
                        recommendation: "Add health factor and collateral checks".to_string(),
                        anchor_fix: "Check: health_factor > MIN && collateral >= borrowed".to_string(),
                        cwe: "CWE-703".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_liquidation_frontrun(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Public liquidation function
        if file.content.contains("liquidate") || file.content.contains("liquidator") {
            if !file.content.contains("only_liquidator") && !file.content.contains("internal") {
                if let Some(line) = find_line(file, "liquidate", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::AccessControl,
                        title: "Liquidation Frontrun: Public liquidation allows MEV extraction".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Anyone can liquidate - MEV bots can extract value. Consider permissioned liquidators.".to_string(),
                        recommendation: "Consider liquidator whitelist or fee structure".to_string(),
                        anchor_fix: "Add liquidator rewards or access control".to_string(),
                        cwe: "CWE-770".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_health_factor_bypass(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Health factor check after borrow
        if file.content.contains("health_factor") || file.content.contains("health") {
            if file.content.contains("borrow") || file.content.contains("withdraw") {
                let borrow_pos = file.content.find("borrow").unwrap_or(usize::MAX);
                let health_pos = file.content.find("health").unwrap_or(usize::MAX);
                if health_pos > borrow_pos {
                    if let Some(line) = find_line(file, "health", 2) {
                        out.push(Finding {
                            id: next_id(),
                            severity: Severity::Medium,
                            category: Category::AccountValidation,
                            title: "Health Factor Check After Borrow: State changes before health check".to_string(),
                            file: file.path.clone(),
                            line: Some(line),
                            function: "".to_string(),
                            snippet: get_snippet(file, line),
                            description: "Health factor checked AFTER borrow executes. Can undercollateralize before check.".to_string(),
                            recommendation: "Check health BEFORE state change".to_string(),
                            anchor_fix: "Check health first, then modify state".to_string(),
                            cwe: "CWE-367".to_string(),
                            needs_ai_context: false,
                            ai_explanation: None,
                            ai_severity: None,
                            exploitability: 0,
                            confirmed_by_taint: vec![],
                        });
                    }
                }
            }
        }
    }
    out
}

fn detect_liquidation_reserve_bypass(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Liquidation without reserve
        if file.content.contains("liquidate") && !file.content.contains("reserve_fee") {
            if let Some(line) = find_line(file, "liquidate", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Low,
                    category: Category::AccountValidation,
                    title: "Missing Liquidation Reserve Fee: Protocol loses reserve on liquidation".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Liquidation doesn't allocate reserve fee. Protocol loses value.".to_string(),
                    recommendation: "Add liquidation reserve to protocol revenue".to_string(),
                    anchor_fix: "Add: protocol_fee = amount * LIQUIDATION_FEE".to_string(),
                    cwe: "CWE-476".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// YIELD & RATE ATTACKS
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_yield_drain(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Yield distribution without verification
        if file.content.contains("yield") || file.content.contains("interest") {
            if !file.content.contains("accrue") && !file.content.contains("calculate") && 
               !file.content.contains("accrued") {
                if let Some(line) = find_line(file, "yield", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::ArithmeticOverflow,
                        title: "Yield Drain: Yield calculation without proper accrue records".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Yield calculated without checking accrued amounts. Can drain yield pool.".to_string(),
                        recommendation: "Track accrued yield separately per user".to_string(),
                        anchor_fix: "Calculate accrued before distribution".to_string(),
                        cwe: "CWE-367".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_rate_manipulation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Rate set by user without bounds
        if file.content.contains("rate") || file.content.contains("apr") {
            if !file.content.contains("max_rate") && !file.content.contains("MIN_RATE") {
                if let Some(line) = find_line(file, "rate", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Rate Manipulation: Interest rate set without bounds".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Admin can set interest rate to 100%+. No bounds check.".to_string(),
                        recommendation: "Add MIN_RATE and MAX_RATE bounds".to_string(),
                        anchor_fix: "require!(rate >= MIN_RATE && rate <= MAX_RATE)".to_string(),
                        cwe: "CWE-20".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_flash_loan_manipulation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Flash loan without callback check
        if file.content.contains("flash_loan") || file.content.contains("flash") {
            if !file.content.contains("callback") && !file.content.contains("repay") {
                if let Some(line) = find_line(file, "flash", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccountValidation,
                        title: "Flash Loan Manipulation: No callback ensures repay".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Flash loan doesn't verify internal callback to force repayment.".to_string(),
                        recommendation: "Use flash loan callback to ensure repayment".to_string(),
                        anchor_fix: "Use callback to force repay in same tx".to_string(),
                        cwe: "CWE-367".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_negative_yield(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Negative yield possible
        if file.content.contains("interest") && file.content.contains("-") {
            if let Some(line) = find_line(file, "interest", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Medium,
                    category: Category::ArithmeticOverflow,
                    title: "Negative Yield: Interest can go negative".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Interest calculation allows negative values. Protocol pays borrower.".to_string(),
                    recommendation: "Floor interest at 0".to_string(),
                    anchor_fix: "Set: interest = interest.max(0)".to_string(),
                    cwe: "CWE-190".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// PROGRAM UPGRADE ATTACKS
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_upgradeable_program(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if file.content.contains("upgradeable_program") || file.content.contains("UPGRADEABLE") {
            if let Some(line) = find_line(file, "upgrade", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Info,
                    category: Category::AccessControl,
                    title: "Program Upgradeable: Program can be upgraded".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Program is marked upgradeable. Verify upgrade authority.".to_string(),
                    recommendation: "Ensure upgrade authority is multisig/timelock".to_string(),
                    anchor_fix: "Use upgrade authority governance".to_string(),
                    cwe: "CWE-284".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_proxy_upgrade(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Proxy with upgrade
        if file.content.contains("proxy") && file.content.contains("upgrade") {
            if !file.content.contains("implementation") {
                if let Some(line) = find_line(file, "proxy", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Proxy Upgrade: Implementation can be swapped".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Proxy implementation can be swapped by admin. Risk of rug via swap.".to_string(),
                        recommendation: "Verify implementation address or use immutable proxy".to_string(),
                        anchor_fix: "Verify: implementation == STORED_IMPL".to_string(),
                        cwe: "CWE-284".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_authority_transfer(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Authority can be transferred to anyone
        if file.content.contains("set_authority") || file.content.contains("transfer_authority") ||
           file.content.contains("set_admin") {
            if !file.content.contains("only_current") && !file.content.contains("timelock") {
                if let Some(line) = find_line(file, "authority", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Authority Transfer: Admin can transfer ownership to anyone".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Admin can transfer all privileges to any address. Complete rug.".to_string(),
                        recommendation: "Use pending authority with acceptance pattern".to_string(),
                        anchor_fix: "Use two-step authority transfer".to_string(),
                        cwe: "CWE-284".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_pause_timeline(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Pause without timeline
        if file.content.contains("pause") && !file.content.contains("unpause") && 
           !file.content.contains("unpause_delay") {
            if let Some(line) = find_line(file, "pause", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Low,
                    category: Category::AccessControl,
                    title: "Pause Without Unpause Timeline: Functions can be paused forever".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Pause can be indefinite. Consider unpause delay or governance.".to_string(),
                    recommendation: "Add unpause timelock".to_string(),
                    anchor_fix: "Add: unpauseable_after = now + TIMELOCK".to_string(),
                    cwe: "CWE-1128".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// CROSS-PROGRAM ATTACKS - CPI vulnerabilities
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_cross_program_attack(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // CPI with unverified program
        if file.content.contains("invoke_signed") && !file.content.contains("program_id") &&
           !file.content.contains("seeds") {
            if let Some(line) = find_line(file, "invoke", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Critical,
                    category: Category::AccountValidation,
                    title: "Cross-Program Attack: CPI target not verified".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Calling program via CPI without verifying it's the expected one.".to_string(),
                    recommendation: "Verify program_id before CPI".to_string(),
                    anchor_fix: "require!(cpi_program == EXPECTED)".to_string(),
                    cwe: "CWE-346".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_wormhole_style(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Sysvar or account type spoofing
        if file.content.contains("sysvar") && !file.content.contains("verify") &&
           !file.content.contains("assert") {
            if let Some(line) = find_line(file, "sysvar", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Critical,
                    category: Category::AccountValidation,
                    title: "Wormhole Exploit Style: Sysvar account not verified".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Sysvar account accepted without verification. Wormhole $326M was this exact bug.".to_string(),
                    recommendation: "Verify: account.key() == expected_sysvar::id()".to_string(),
                    anchor_fix: "Add sysvar verification constraint".to_string(),
                    cwe: "CWE-346".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_sysvar_spoofing(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Clock account not verified
        if file.content.contains("clock") && !file.content.contains("Clock") && 
           !file.content.contains("sysvar::clock") {
            if let Some(line) = find_line(file, "clock", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::High,
                    category: Category::AccountValidation,
                    title: "Clock Account Spoofing: Clock passed without verification".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Clock account could be spoofed with manipulated timestamp.".to_string(),
                    recommendation: "Use Clock::get() or verify clock account key".to_string(),
                    anchor_fix: "Use sysvar::clock::Clock for timestamp".to_string(),
                    cwe: "CWE-346".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_instruction_introspection(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Instruction data introspection attacks
        if file.content.contains("instruction_data") || file.content.contains("instruction_sysvar") {
            if !file.content.contains("check") && !file.content.contains("verify") {
                if let Some(line) = find_line(file, "instruction", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccountValidation,
                        title: "Instruction Introspection: No validation on instruction data".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Instruction data accessed without validation. Can inject malicious data.".to_string(),
                        recommendation: "Validate all instruction data fields".to_string(),
                        anchor_fix: "Parse and validate instruction data".to_string(),
                        cwe: "CWE-20".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// TOKEN SPECIFIC ATTACKS
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_spl_mint_bypass(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Custom mint
        if file.content.contains("mint::create") && !file.content.contains("initialize_mint") {
            if let Some(line) = find_line(file, "mint", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Medium,
                    category: Category::AccountValidation,
                    title: "Custom SPL Token: Non-standard mint creation".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Custom token mint. Verify security of mint parameters.".to_string(),
                    recommendation: "Use spl_token 2022 or verify mint params".to_string(),
                    anchor_fix: "Use standard SPL token program".to_string(),
                    cwe: "CWE-20".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_token_freeze_bypass(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Token with freeze but no check
        if file.content.contains("freeze") && !file.content.contains("is_frozen") &&
           !file.content.contains("check_frozen") {
            if let Some(line) = find_line(file, "freeze", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Medium,
                    category: Category::AccountValidation,
                    title: "Token Freeze Bypass: Transfer doesn't check frozen state".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Transfer happens regardless of account freeze. Verify frozen state.".to_string(),
                    recommendation: "Check: require!(!account.is_frozen)".to_string(),
                    anchor_fix: "Add: is_frozen check in transfer".to_string(),
                    cwe: "CWE-346".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_transfer_fee_bypass(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // With transfer fee but no burn
        if file.content.contains("transfer") && file.content.contains("fee") {
            if !file.content.contains("burn") && !file.content.contains("calculate_fee") {
                if let Some(line) = find_line(file, "fee", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::ArithmeticOverflow,
                        title: "Transfer Fee Bypass: Fee calculated but not applied to burn".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Transfer fee calculated but attacker can bypass.".to_string(),
                        recommendation: "Apply fee to token transfer or burn".to_string(),
                        anchor_fix: "Ensure: amount_with_fee >= amount".to_string(),
                        cwe: "CWE-20".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_unchecked_token_operation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Raw token operation without amount check
        if file.content.contains("token::transfer") && !file.content.contains("amount > 0") {
            if let Some(line) = find_line(file, "transfer", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::High,
                    category: Category::ArithmeticOverflow,
                    title: "Unchecked Token Operation: Transfer allows zero amount".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Zero token transfer drains gas but may have side effects.".to_string(),
                    recommendation: "Check: require!(amount > 0)".to_string(),
                    anchor_fix: "Add: amount > 0 check".to_string(),
                    cwe: "CWE-20".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// STAKING & DELEGATION
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_staking_drain(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Stake withdraw without lock
        if file.content.contains("stake") && (file.content.contains("withdraw") || file.content.contains("unstake")) {
            if !file.content.contains("locked") && !file.content.contains("lock_period") {
                if let Some(line) = find_line(file, "stake", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Staking Drain: Unstake without lock period".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Can withdraw immediately without lock period. Attackable if slash not active.".to_string(),
                        recommendation: "Add lock period or cooldown".to_string(),
                        anchor_fix: "Check: lock_end < Clock::slot()".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_delegation_escrow(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Delegate can withdraw from escrow
        if file.content.contains("delegate") && file.content.contains("withdraw") {
            if !file.content.contains("owner") && !file.content.contains("delegator") {
                if let Some(line) = find_line(file, "delegate", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Delegation Escrow: Delegate can withdraw escrowed funds".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Delegated account can withdraw from escrow. Check delegate scope.".to_string(),
                        recommendation: "Limit delegation scope".to_string(),
                        anchor_fix: "Restrict delegate actions".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

fn detect_validator_bribe(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Validator can be bribed by setting wrong vote
        if file.content.contains("vote_account") && !file.content.contains("authorized") &&
           file.content.contains("set") {
            if let Some(line) = find_line(file, "vote", 2) {
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Critical,
                    category: Category::AccessControl,
                    title: "Validator Bribe: Wrong vote account can receive stake".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet: get_snippet(file, line),
                    description: "Validator vote account can be manipulated. MEV extraction.".to_string(),
                    recommendation: "Verify vote account authorized".to_string(),
                    anchor_fix: "Verify vote account via network".to_string(),
                    cwe: "CWE-862".to_string(),
                    needs_ai_context: false,
                    ai_explanation: None,
                    ai_severity: None,
                    exploitability: 0,
                    confirmed_by_taint: vec![],
                });
            }
        }
    }
    out
}

fn detect_vote_manipulation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        // Vote without stake verification
        if file.content.contains("vote") && file.content.contains("submit") {
            if !file.content.contains("stake") && !file.content.contains("verify_vote") {
                if let Some(line) = find_line(file, "vote", 2) {
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccessControl,
                        title: "Vote Manipulation: Vote registered without stake verification".to_string(),
                        file: file.path.clone(),
                        line: Some(line),
                        function: "".to_string(),
                        snippet: get_snippet(file, line),
                        description: "Submit vote without verifying voter's stake weight. Can vote with zero.".to_string(),
                        recommendation: "Verify vote account stake balance".to_string(),
                        anchor_fix: "Check: stake_account.vote_weight > 0".to_string(),
                        cwe: "CWE-862".to_string(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════════════

fn find_line(file: &InputFile, pattern: &str, _ctx: usize) -> Option<usize> {
    for (i, line) in file.content.lines().enumerate() {
        if line.contains(pattern) {
            return Some(i + 1);
        }
    }
    None
}

fn get_snippet(file: &InputFile, line_num: usize) -> String {
    let lines: Vec<&str> = file.content.lines().collect();
    let start = line_num.saturating_sub(2);
    let end = (line_num + 3).min(lines.len());
    lines[start..end].join("\n").to_string()
}