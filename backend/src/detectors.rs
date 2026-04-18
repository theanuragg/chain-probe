// backend/src/detectors.rs
// Advanced vulnerability detectors - expanded v4.1
// Makes ChainProbe the best Solana security auditor

use crate::{
    ast_visitor::ProjectVisitor,
    types::{Category, Finding, InputFile, Severity},
};

pub fn detect_advanced(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut findings = vec![];
    
    findings.extend(detect_token_safety(visitor, files, next_id));
    findings.extend(detect_pda_bumps(visitor, files, next_id));
    findings.extend(detect_cpi_validation(visitor, files, next_id));
    findings.extend(detect_sysvar_usage(visitor, files, next_id));
    findings.extend(detect_rent_exempt(visitor, files, next_id));
    findings.extend(detect_anchor_unchecked(visitor, files, next_id));
    findings.extend(detect_bump_canonical(visitor, files, next_id));
    findings.extend(detect_init_safety(visitor, files, next_id));
    findings.extend(detect_close_authority(visitor, files, next_id));
    findings.extend(detect_mint_auth(visitor, files, next_id));
    findings.extend(detect_program_id(visitor, files, next_id));
    findings.extend(detect_multiple_mint(visitor, files, next_id));
    findings.extend(detect_unchecked_params(visitor, files, next_id));
    findings.extend(detect_freeze_auth(visitor, files, next_id));
    findings.extend(detect_update_authority(visitor, files, next_id));
    findings.extend(detect_delegate_usage(visitor, files, next_id));
    findings.extend(detect_transfer_hook(visitor, files, next_id));
    findings.extend(detect_metadata_update(visitor, files, next_id));
    findings.extend(detect_scope_validation(visitor, files, next_id));
    findings.extend(detect_executable_accounts(visitor, files, next_id));
    
    findings
}

//   TOKEN SAFETY CHECKS                         ─

fn detect_token_safety(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        if !file.path.contains("token") && !file.content.contains("spl_token") {
            continue;
        }
        
        // Missing transfer check
        if file.content.contains("transfer(") && !file.content.contains("transfer_checked") {
            let (snippet, line) = get_snippet(file, "transfer(", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::TokenSafety,
                title: "Use transfer_checked for token transfers".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Use transfer_checked which validates token mint to prevent \
                    transfers of wrong token type.".to_string(),
                recommendation: "Use token::transfer_checked instead of transfer".to_string(),
                anchor_fix: "token::transfer_checked(...)".to_string(),
                cwe: "CWE-20".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

fn detect_pda_bumps(visitor: &ProjectVisitor, _files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for pda in &visitor.pda_derivations {
        // Bump not stored but used - potential issues
        if pda.seeds.iter().any(|s| s.contains("bump")) 
            && !pda.seeds.iter().any(|s| s.contains("bump = ")) 
            && !pda.seeds.iter().any(|s| s.contains("bump.unwrap")) {
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::PdaSeedCollision,
                title: format!("PDA `{}` uses bump but doesn't store canonical bump", pda.account_name),
                file: pda.file.clone(),
                line: None,
                function: pda.account_name.clone(),
                snippet: format!("seeds = {:?}", pda.seeds),
                description: "Using bump in PDA seeds without storing the canonical bump \
                    means the PDA can only be derived with the exact bump value.".to_string(),
                recommendation: "Store bump = ctx.bumps.get(\"bump\") and use it in seeds".to_string(),
                anchor_fix: "bump = ctx.bumps.get(\"bump\")".to_string(),
                cwe: "CWE-330".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   CPI VALIDATION                               

fn detect_cpi_validation(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Missing program ID validation in CPI
        let cpi_calls: Vec<_> = file.content.matches("CpiContext::new(").collect();
        for cpi in cpi_calls {
            if !file.content.contains("crate::ID") && !file.content.contains("program::ID") {
                let (snippet, line) = get_snippet(file, "CpiContext::new", 2);
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Medium,
                    category: Category::AccountValidation,
                    title: "CPI may lack program ID verification".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet,
                    description: "Calling program without verifying its ID could allow \
                        attackers to substitute malicious program.".to_string(),
                    recommendation: "Add program ID check: Anchor automatically validates, \
                        but verify for raw CPIs.".to_string(),
                    anchor_fix: "Use Anchor's derive macro which includes ID check".to_string(),
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

//   SYSVAR USAGE                               

fn detect_sysvar_usage(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for instr in &visitor.instructions {
        if instr.ctx_type.contains("Sysvar") {
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::AccountValidation,
                title: "Direct Sysvar account usage".to_string(),
                file: instr.file.clone(),
                line: None,
                function: instr.name.clone(),
                snippet: "Sysvar account".to_string(),
                description: "Direct Sysvar usage can fail if sysvar is not updated. \
                    Use Clock::get() instead for better reliability.".to_string(),
                recommendation: "Use anchor_lang::prelude::Clock::get() instead".to_string(),
                anchor_fix: "Clock::get()".to_string(),
                cwe: "CWE-252".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   RENT EXEMPTION                               

fn detect_rent_exempt(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // init without enough space for rent
        if file.content.contains("#[account(init") && !file.content.contains("space = ") {
            let (snippet, line) = get_snippet(file, "#[account(init", 3);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccountValidation,
                title: "May lack rent-exempt space allocation".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Accounts must maintain minimum rent-exempt balance. \
                    Calculate correct space for each field.".to_string(),
                recommendation: "Add space = N, where N accounts for all fields + discriminator".to_string(),
                anchor_fix: "#[account(init, payer = authority, space = 8 + 32 + ...)]".to_string(),
                cwe: "CWE-789".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   ANCHOR UNCHECKED                               

fn detect_anchor_unchecked(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Unchecked accounts
        if file.content.contains("#[account(uncheck") {
            let (snippet, line) = get_snippet(file, "uncheck", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Info,
                category: Category::AccountValidation,
                title: "Account constraint validation disabled".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "#[account(unchecked)] skips all Anchor validations. Ensure you manually \
                    validate type/owner/mint in the instruction.".to_string(),
                recommendation: "Add manual validation checks in instruction".to_string(),
                anchor_fix: "Remove #[account(unchecked)] or add validation".to_string(),
                cwe: "CWE-20".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   BUMP CANONICAL                               

fn detect_bump_canonical(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        if file.content.contains("find_program_address") && !file.content.contains("Canonical") {
            let (snippet, line) = get_snippet(file, "find_program_address", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::PdaSeedCollision,
                title: "Non-canonical PDA derivation".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Using find_program_address without canonical bump is deprecated. \
                    Use Pubkey::find_program_address instead.".to_string(),
                recommendation: "Use Pubkey::find_program_address for canonical bump".to_string(),
                anchor_fix: "Pubkey::find_program_address(program_id, &seeds)".to_string(),
                cwe: "CWE-330".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   INIT SAFETY                       ─��       

fn detect_init_safety(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // init_if_needed without proper checks
        if file.content.contains("init_if_needed") && !file.content.contains("realloc") {
            let (snippet, line) = get_snippet(file, "init_if_needed", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccountValidation,
                title: "init_if_needed without realloc guard".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "init_if_needed can create or modify accounts. Ensure realloc \
                    is properly protected with access controls.".to_string(),
                recommendation: "Add authority check on init path".to_string(),
                anchor_fix: "Add init_if_needed + authority validation".to_string(),
                cwe: "CWE-284".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   CLOSE AUTHORITY                             

fn detect_close_authority(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // close authority without Signer
        if file.content.contains("#[account(close") && !file.content.contains("Signer") {
            let (snippet, line) = get_snippet(file, "close", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccessControl,
                title: "Close authority may not be Signer".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Close authority should be Signer to prevent arbitrary account closure.".to_string(),
                recommendation: "Use pub close_authority: Signer<'info>".to_string(),
                anchor_fix: "pub close_authority: Signer<'info>".to_string(),
                cwe: "CWE-862".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   MINT AUTHORIZATION                          

fn detect_mint_auth(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Mint without mint authority
        if file.content.contains("mint: Mint") && !file.content.contains("mint_authority") {
            let (snippet, line) = get_snippet(file, "mint: Mint", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::AccessControl,
                title: "Token Mint without explicit authority".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Token mint should have explicit mint authority control.".to_string(),
                recommendation: "Add mint_authority: Signer<'info>".to_string(),
                anchor_fix: "pub mint_authority: Signer<'info>".to_string(),
                cwe: "CWE-284".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   PROGRAM ID                                ─

fn detect_program_id(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Hardcoded program ID
        if file.content.contains("programid") || file.content.contains("PROGRAM_ID") {
            if file.content.contains("const ID:") || file.content.contains("pub const ID") {
                let (snippet, line) = get_snippet(file, "const ID", 2);
                out.push(Finding {
                    id: next_id(),
                    severity: Severity::Info,
                    category: Category::AccountValidation,
                    title: "Program ID should be derived from program".to_string(),
                    file: file.path.clone(),
                    line: Some(line),
                    function: "".to_string(),
                    snippet,
                    description: "Program ID should be derived from program to ensure \
                        upgrade safety.".to_string(),
                    recommendation: "Use declare_id!(\"...\") for proper ID".to_string(),
                    anchor_fix: "declare_id!(\"ProgramID...\")".to_string(),
                    cwe: "CWE-477".to_string(),
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

//   MULTIPLE MINT                             

fn detect_multiple_mint(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    // Check for multiple token mints in same accounts struct
    for acct in &visitor.account_structs {
        let mint_count = acct.fields.iter()
            .filter(|f| f.field_type.contains("Mint"))
            .count();
        
        if mint_count > 1 {
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::AccountValidation,
                title: "Multiple Token Mints in single account".to_string(),
                file: acct.file.clone(),
                line: None,
                function: acct.name.clone(),
                snippet: format!("{} mints in struct", mint_count),
                description: "Multiple mints in single account structure can cause confusion. \
                    Consider separating.".to_string(),
                recommendation: "Separate into different account structures".to_string(),
                anchor_fix: "Split into multiple account structs".to_string(),
                cwe: "CWE-104".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   UNCHECKED PARAMS                           

fn detect_unchecked_params(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Unchecked instruction params
        if file.content.contains("pub ") && file.content.contains(": u64") 
            && !file.content.contains("checked_") && !file.content.contains("try_from") {
            let (snippet, line) = get_snippet(file, ": u64", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::TokenSafety,
                title: "Unchecked numeric instruction parameter".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Numeric parameters should use checked arithmetic \
                    or TryFrom to prevent overflow.".to_string(),
                recommendation: "Use checked_add/checked_mul or num_traits".to_string(),
                anchor_fix: "amount.checked_add(...)".to_string(),
                cwe: "CWE-190".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   FREEZE AUTHORITY                          

fn detect_freeze_auth(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Freeze authority without Signer
        if file.content.contains("freeze_authority") && !file.content.contains("Signer") {
            let (snippet, line) = get_snippet(file, "freeze_authority", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccessControl,
                title: "Freeze authority without Signer".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Freeze authority should be Signer to prevent unauthorized freezing.".to_string(),
                recommendation: "Use pub freeze_authority: Signer<'info>".to_string(),
                anchor_fix: "pub freeze_authority: Signer<'info>".to_string(),
                cwe: "CWE-862".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   UPDATE AUTHORITY                         ─

fn detect_update_authority(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Update authority missing validation
        if file.content.contains("update_authority") && !file.content.contains("has_one") {
            let (snippet, line) = get_snippet(file, "update_authority", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::High,
                category: Category::AccessControl,
                title: "Update authority lacks validation".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "update_authority should be validated with has_one or manual check.".to_string(),
                recommendation: "Add has_one = update_authority or require!".to_string(),
                anchor_fix: "has_one = update_authority".to_string(),
                cwe: "CWE-862".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   DELEGATE USAGE                             

fn detect_delegate_usage(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Delegate without adequate checks
        if file.content.contains("delegate") && !file.content.contains("delegate_of") {
            let (snippet, line) = get_snippet(file, "delegate", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccessControl,
                title: "Token delegate without full validation".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Delegated transfers should verify delegate signature.".to_string(),
                recommendation: "Add delegate_of authority check".to_string(),
                anchor_fix: "require!(ctx.accounts.delegate_of.is_some())".to_string(),
                cwe: "CWE-862".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   TRANSFER HOOK                           

fn detect_transfer_hook(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Transfer hook without validation
        if file.content.contains("transfer_hook") && !file.content.contains("invoke") {
            out.push(Finding {
                id: next_id(),
                severity: Severity::Info,
                category: Category::AccessControl,
                title: "Transfer hook may require additional validation".to_string(),
                file: file.path.clone(),
                line: None,
                function: "".to_string(),
                snippet: "transfer_hook".to_string(),
                description: "Transfer hooks should be carefully validated.".to_string(),
                recommendation: "Add appropriate validation in hook".to_string(),
                anchor_fix: "Validate in hook callback".to_string(),
                cwe: "CWE-346".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   METADATA UPDATE                             

fn detect_metadata_update(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Metadata update without authority
        if file.content.contains("metadata") && file.content.contains("update") 
            && !file.content.contains("update_authority") {
            let (snippet, line) = get_snippet(file, "metadata", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::AccessControl,
                title: "Metadata update without explicit authority".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Token metadata should require authority to update.".to_string(),
                recommendation: "Add update_authority: Signer".to_string(),
                anchor_fix: "pub update_authority: Signer<'info>".to_string(),
                cwe: "CWE-862".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

//   SCOPE VALIDATION                             

fn detect_scope_validation(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Scope - similar to address but for collections
        if file.content.contains("scope::") && !file.content.contains("verify_collections") {
            let (snippet, line) = get_snippet(file, "scope", 2);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::AccountValidation,
                title: "Scope collection without verification".to_string(),
                file: file.path.clone(),
                line: Some(line),
                function: "".to_string(),
                snippet,
                description: "Scope collections should be verified.".to_string(),
                recommendation: "Add verify_collections constraint".to_string(),
                anchor_fix: "verify_collections = ...".to_string(),
                cwe: "CWE-346".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

fn detect_executable_accounts(visitor: &ProjectVisitor, files: &[InputFile], next_id: &mut impl FnMut() -> String) -> Vec<Finding> {
    let mut out = vec![];
    
    for file in files {
        // Loading executable accounts
        if file.content.contains("programdata") || file.content.contains("executable") {
            out.push(Finding {
                id: next_id(),
                severity: Severity::Low,
                category: Category::AccountValidation,
                title: "Direct executable account load".to_string(),
                file: file.path.clone(),
                line: None,
                function: "".to_string(),
                snippet: "Executable account".to_string(),
                description: "Loading executable accounts directly should verify it's expected program.".to_string(),
                recommendation: "Verify program ID before execution".to_string(),
                anchor_fix: "Verify program ID".to_string(),
                cwe: "CWE-346".to_string(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }
    }
    out
}

fn get_snippet(file: &InputFile, pattern: &str, _lines: usize) -> (String, usize) {
    for (i, line) in file.content.lines().enumerate() {
        if line.contains(pattern) {
            let start = i.saturating_sub(1);
            let end = (i + 3).min(file.content.lines().count());
            let snippet: String = file.content.lines().skip(start).take(end - start).collect::<Vec<_>>().join("\n");
            return (snippet, i + 1);
        }
    }
    (String::new(), 0)
}