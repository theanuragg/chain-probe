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
    
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // ORACLE & DEFI ADVANCED (v4.2)
    // ═══════════════════════════════════════════════════════════════════════════════════════
    findings.extend(detect_single_oracle_no_twap(files, next_id));
    findings.extend(detect_flash_loan_no_repayment(files, next_id));
    findings.extend(detect_share_price_donation(files, next_id));
    findings.extend(detect_stale_oracle_price(files, next_id));
    findings.extend(detect_timestamp_dependence(files, next_id));
    
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
// SINGLE ORACLE — NO TWAP
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_single_oracle_no_twap(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Check if only one oracle price feed is used
        let oracle_count = content.matches("oracle").count()
            + content.matches("price_feed").count()
            + content.matches("pyth").count()
            + content.matches("switchboard").count();

        if oracle_count < 2 { continue; }

        // Now check if a TWAP is used anywhere
        let has_twap = content.contains("twap") || content.contains("TWAP")
            || content.contains("ema") || content.contains("EMA")
            || content.contains("moving_average") || content.contains("rolling_average")
            || content.contains("historical_price");

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if (t.contains("oracle") || t.contains("price_feed") || t.contains("pyth"))
                && !t.contains("//")
            {
                let ctx_start = i.saturating_sub(5);
                let ctx_end = (i + 10).min(lines.len());
                let ctx_str = lines[ctx_start..ctx_end].join("\n");

                let uses_single = ctx_str.matches("oracle").count() <= 1
                    || ctx_str.matches("price_feed").count() <= 1;
                let is_price_calc = ctx_str.contains("price") || ctx_str.contains("value")
                    || ctx_str.contains("amount") || ctx_str.contains("collateral");

                if uses_single && is_price_calc && !has_twap {
                    let snippet = get_snippet(file, i + 1);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::OracleManip,
                        title: "Single oracle price feed without TWAP — flash loan manipulation".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "This program reads a price from a single oracle feed without \
                            using a time-weighted average price (TWAP). A single oracle price can be \
                            manipulated via flash loans or large swaps that temporarily skew the \
                            oracle's reported price. This allows an attacker to borrow against \
                            inflated collateral or liquidate healthy positions at a favorable price.".into(),
                        recommendation: "Use a TWAP oracle (e.g., Pyth's EMA price) or compute a \
                            TWAP from multiple historical observations. For critical operations like \
                            liquidation or borrowing, require the TWAP price rather than the spot price.".into(),
                        anchor_fix: "Use pyth_solana_receiver with ema_price instead of price".into(),
                        cwe: "CWE-682".into(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                    break;
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// FLASH LOAN — NO REPAYMENT CHECK
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_flash_loan_no_repayment(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Check if flash loan is implemented
        if !content.contains("flash") && !content.contains("Flash") { continue; }

        // Check for repayment verification
        let has_repayment = content.contains("repay") || content.contains("Repay")
            || content.contains("repayment") || content.contains("Repayment")
            || content.contains("return_amount") || content.contains("balance_before")
            || content.contains("balance_after") || content.contains("pre_balance")
            || content.contains("post_balance");

        let has_fee_check = content.contains("flash_loan_fee") || content.contains("flash_fee")
            || content.contains("protocol_fee") || content.contains("borrow_fee");

        if !has_repayment && !has_fee_check {
            if let Some(line) = find_line_audit(file, "fn.*flash", 3) {
                let snippet = get_snippet(file, line);
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Critical,
                    category: Category::FlashLoan,
                    title: "Flash loan without repayment verification — free borrow".into(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: String::new(),
                    snippet,
                    description: "This program has a flash loan function but does NOT verify that \
                        borrowed tokens plus fees are returned before the transaction ends. Without \
                        a balance-before/balance-after check or a repayment instruction, an attacker \
                        can borrow tokens and never return them. This is the root cause of multiple \
                        Solana flash loan exploits where the borrowed amount was never verified.".into(),
                    recommendation: "Implement balance-before/balance-after tracking on the token \
                        account. Record the pre-flash balance, execute the callback, then verify \
                        the post-flash balance >= pre-flash balance + fee.".into(),
                    anchor_fix: "let balance_before = token_account.amount; /* callback */ require!(token_account.amount >= balance_before + fee)".into(),
                    cwe: "CWE-841".into(),
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
// SHARE PRICE DONATION ATTACK
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_share_price_donation(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Only scan vault/lending/pool contracts
        if !content.contains("vault") && !content.contains("Vault")
            && !content.contains("pool") && !content.contains("Pool")
            && !content.contains("lend") && !content.contains("Lend")
        {
            continue;
        }

        // Check if share calculation uses total_supply or total_shares
        let has_share_calc = content.contains("total_supply") || content.contains("total_shares")
            || content.contains("total_value") || content.contains("total_assets")
            || content.contains("share_price") || content.contains("share_value");

        if !has_share_calc { continue; }

        // Look for the share price calculation pattern: shares = amount * total_shares / reserve
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Detect shares = amount * total_supply / reserve or similar
            if (t.contains("shares") || t.contains("share")) && t.contains("total_supply")
                || t.contains("shares") && t.contains("total_shares")
                || t.contains("shares") && t.contains("total_value")
                || t.contains("shares") && t.contains("reserve")
                || t.contains("shares") && t.contains("liquidity")
            {
                // Check if there's a donation guard (total_supply == 0 check, minimum_liquidity)
                let ctx_start = i.saturating_sub(10);
                let ctx_end = (i + 15).min(lines.len());
                let ctx_str = lines[ctx_start..ctx_end].join("\n");

                let has_donation_guard = ctx_str.contains("total_supply == 0") || ctx_str.contains("total_shares == 0")
                    || ctx_str.contains("is_empty") || ctx_str.contains("minimum_liquidity")
                    || ctx_str.contains("MINIMUM_LIQUIDITY") || ctx_str.contains("dead_shares")
                    || ctx_str.contains("lock_shares") || ctx_str.contains("pre_mint")
                    || ctx_str.contains("initial_shares") || ctx_str.contains("first_deposit");

                if !has_donation_guard {
                    let snippet = get_snippet(file, i + 1);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Critical,
                        category: Category::YieldDrain,
                        title: "Share price donation attack — first depositor can be drained".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "The share/price calculation does not protect against the \
                            classic donation attack. A first depositor can mint a tiny number of \
                            shares, then donate assets directly to inflate the share price. \
                            Subsequent depositors receive very few shares, allowing the attacker \
                            to withdraw most of their value. This has been exploited in multiple \
                            Solana vault protocols.".into(),
                        recommendation: "Mint a minimum number of dead/locked shares on first deposit \
                            (e.g., 1000 shares sent to a burn address). Or require a minimum initial \
                            deposit and lock those shares forever. This is the Uniswap V2 pattern.".into(),
                        anchor_fix: "if total_shares == 0 { mint(1000, burn_address); }".into(),
                        cwe: "CWE-682".into(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                    break;
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// STALE ORACLE PRICE
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_stale_oracle_price(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Only scan files that use oracle prices
        if !content.contains("oracle") && !content.contains("price_feed")
            && !content.contains("pyth") && !content.contains("switchboard")
        {
            continue;
        }

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Find where oracle price is read
            if (t.contains("oracle.") || t.contains("price_feed.") || t.contains("pyth."))
                && (t.contains("price") || t.contains("value"))
                && !t.contains("//")
            {
                let ctx_start = i.saturating_sub(10);
                let ctx_end = (i + 15).min(lines.len());
                let ctx_str = lines[ctx_start..ctx_end].join("\n");

                // Check for staleness checks
                let has_staleness_check = ctx_str.contains("publish_time") || ctx_str.contains("timestamp")
                    || ctx_str.contains("slot") || ctx_str.contains("confidence")
                    || ctx_str.contains("staleness") || ctx_str.contains("max_age")
                    || ctx_str.contains("valid_time") || ctx_str.contains("expir")
                    || ctx_str.contains("require!(.*publish_time") || ctx_str.contains("require!(.*slot")
                    || ctx_str.contains("current_time") || ctx_str.contains("clock");

                if !has_staleness_check {
                    let snippet = get_snippet(file, i + 1);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::PriceOracle,
                        title: "Oracle price used without staleness check — stale price risk".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "An oracle price is read but its timestamp or slot is not \
                            verified for freshness. If the oracle feed becomes stale (e.g., due to \
                            network issues, low liquidity, or a paused market), the program will \
                            use an outdated price. This allows arbitrage against stale prices, \
                            causing incorrect liquidations, borrows, or swaps.".into(),
                        recommendation: "Always verify the oracle price is fresh: check \
                            `price.publish_time >= Clock::get()?.unix_timestamp - MAX_AGE_SECONDS` \
                            and verify `price.confidence_interval` is within acceptable range.".into(),
                        anchor_fix: "require!(price.publish_time >= Clock::get()?.unix_timestamp - 60, StalePrice)".into(),
                        cwe: "CWE-682".into(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                    break;
                }
            }
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// TIMESTAMP DEPENDENCE
// ═══════════════════════════════════════════════════════════════════════════════════════

fn detect_timestamp_dependence(files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Only scan files that use Clock or timestamps
        if !content.contains("Clock") && !content.contains("unix_timestamp")
            && !content.contains("timestamp")
        {
            continue;
        }

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Find timestamp usage in decision logic
            if (t.contains("unix_timestamp") || t.contains("clock().timestamp"))
                && (t.contains("if ") || t.contains("require!") || t.contains(">") || t.contains("<")
                    || t.contains("==") || t.contains("!="))
                && !t.contains("//")
            {
                let ctx_start = i.saturating_sub(5);
                let ctx_end = (i + 15).min(lines.len());
                let ctx_str = lines[ctx_start..ctx_end].join("\n");

                // Check if it's used for deadline/round boundaries (acceptable) or precise timing (bad)
                let is_deadline = ctx_str.contains("deadline") || ctx_str.contains("expir")
                    || ctx_str.contains("maturity") || ctx_str.contains("vest")
                    || ctx_str.contains("cliff") || ctx_str.contains("cutoff");

                if !is_deadline {
                    let snippet = get_snippet(file, i + 1);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::SysvarUsage,
                        title: "Timestamp-based decision logic — validator manipulation risk".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "The program uses `unix_timestamp` in a decision/branch. \
                            On Solana, block timestamps are set by validators and can vary by up to \
                            a few seconds. If precise timing (~second-level) is required for financial \
                            decisions (vesting, auctions, liquidations), a malicious validator can \
                            manipulate the timestamp by a small amount for profit.".into(),
                        recommendation: "For financial decisions, use slot numbers (which are precise) \
                            instead of timestamps. If timestamps are required, accept a tolerance of \
                            several seconds. For auctions, use slot-based deadlines.".into(),
                        anchor_fix: "Use `Clock::get()?.slot` for precise ordering instead of timestamps".into(),
                        cwe: "CWE-829".into(),
                        needs_ai_context: false,
                        ai_explanation: None,
                        ai_severity: None,
                        exploitability: 0,
                        confirmed_by_taint: vec![],
                    });
                    break;
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

fn find_line_audit(file: &InputFile, pattern: &str, _ctx: usize) -> Option<usize> {
    for (i, line) in file.content.lines().enumerate() {
        if line.contains(pattern.trim_matches('/')) || {
            // Try pattern as regex-like prefix
            let clean = pattern.trim_start_matches("fn.*");
            line.contains(clean)
        } {
            return Some(i + 1);
        }
    }
    // Fallback: search for "fn flash" or whatever function name
    let simple = pattern.trim_start_matches("fn.*").trim_start_matches("fn ");
    for (i, line) in file.content.lines().enumerate() {
        if line.contains(simple) {
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