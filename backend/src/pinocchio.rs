use crate::{
    ast_visitor::ProjectVisitor,
    types::{Category, Finding, InputFile, Severity},
};

pub fn detect_pinocchio(
    visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut findings = vec![];

    findings.extend(detect_no_std_missing_panic(visitor, files, next_id));
    findings.extend(detect_manual_account_parsing(visitor, files, next_id));
    findings.extend(detect_raw_invoke_no_program_check(visitor, files, next_id));
    findings.extend(detect_pinocchio_missing_owner_check(visitor, files, next_id));
    findings.extend(detect_pinocchio_account_index_oob(visitor, files, next_id));
    findings.extend(detect_pinocchio_no_signer_verify(visitor, files, next_id));
    findings.extend(detect_pinocchio_no_bump_check(visitor, files, next_id));
    findings.extend(detect_pinocchio_instruction_data_validation(visitor, files, next_id));
    findings.extend(detect_pinocchio_missing_entrypoint_validation(visitor, files, next_id));

    findings
}

fn detect_no_std_missing_panic(
    visitor: &ProjectVisitor,
    _files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    if !visitor.is_no_std { return out; }

    for file in &visitor.modules {
        let Some(lines) = visitor.raw_lines.get(file) else { continue; };
        let content = lines.join("\n");
        let has_panic_handler = content.contains("nostd_panic_handler")
            || content.contains("set_custom_panic_handler")
            || content.contains("#[panic_handler]");
        let has_allocator = content.contains("default_allocator")
            || content.contains("no_allocator");

        if !has_panic_handler {
            let (snippet, line) = visitor.snippet_for_pattern(file, "#![no_std]", 4);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Medium,
                category: Category::ProgramId,
                title: "no_std program missing panic handler — undefined behavior on panic".into(),
                file: file.clone(),
                line: Some(line),
                function: String::new(),
                snippet,
                description: "This program uses #![no_std] but does not declare a panic handler. \
                    Without nostd_panic_handler!, a panic will invoke the abort() syscall \
                    indirectly or cause undefined behavior. Pinocchio programs must use \
                    nostd_panic_handler! to ensure deterministic abort on panic.".into(),
                recommendation: "Add nostd_panic_handler! macro after the entrypoint: \
                    `pinocchio::nostd_panic_handler!();`".into(),
                anchor_fix: "pinocchio::nostd_panic_handler!();".into(),
                cwe: "CWE-754".into(),
                needs_ai_context: false,
                ai_explanation: None,
                ai_severity: None,
                exploitability: 0,
                confirmed_by_taint: vec![],
            });
        }

        if !has_allocator {
            let (snippet, line) = visitor.snippet_for_pattern(file, "#![no_std]", 4);
            out.push(Finding {
                id: next_id(),
                severity: Severity::Info,
                category: Category::ProgramId,
                title: "no_std program missing global allocator — heap allocation unavailable".into(),
                file: file.clone(),
                line: Some(line),
                function: String::new(),
                snippet,
                description: "This no_std program does not declare a global allocator. \
                    Without default_allocator!, types like Vec, String, and Box will panic. \
                    Use no_allocator if the program does not require heap allocation.".into(),
                recommendation: "Add default_allocator! or no_allocator! macro. \
                    `pinocchio::default_allocator!();` for programs that need heap, \
                    or `pinocchio::no_allocator!();` for zero-alloc programs.".into(),
                anchor_fix: "pinocchio::default_allocator!();".into(),
                cwe: "CWE-754".into(),
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

fn detect_manual_account_parsing(
    visitor: &ProjectVisitor,
    _files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for (func, line_str, _) in &visitor.pinocchio_manual_accounts {
        let (snippet, snip_line) = visitor.snippet_for_pattern(
            &visitor.current_file,
            &line_str.chars().take(30).collect::<String>(),
            3,
        );
        out.push(Finding {
            id: next_id(),
            severity: Severity::Medium,
            category: Category::AccountValidation,
            title: format!("Manual account parsing in `{}` — no type safety", func),
            file: visitor.current_file.clone(),
            line: Some(snip_line),
            function: func.clone(),
            snippet,
            description: "Manual account iteration (accounts.iter() or &accounts[]) bypasses \
                Anchor's type-safe account deserialization. Since Pinocchio uses raw &[AccountInfo], \
                the program must manually verify owner, signer, writable, and data validity for \
                every account. A single missed check can lead to account substitution attacks.".into(),
            recommendation: "For each account accessed from the iterator, verify: \
                1. Owner is the expected program with `owner == &solana_program::system_program::ID` \
                2. Signer status with `account.is_signer` \
                3. Account data discriminator matches expected type \
                4. Index bounds are validated (avoid panic on out-of-range)".into(),
            anchor_fix: String::new(),
            cwe: "CWE-284".into(),
            needs_ai_context: true,
            ai_explanation: None,
            ai_severity: None,
            exploitability: 0,
            confirmed_by_taint: vec![],
        });
    }
    out
}

fn detect_raw_invoke_no_program_check(
    visitor: &ProjectVisitor,
    _files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for cpi in &visitor.uses_raw_invoke {
        let (snippet, line) = visitor.snippet_for_pattern(&cpi.file, "sol_invoke", 4);
        out.push(Finding {
            id: next_id(),
            severity: Severity::Critical,
            category: Category::CpiValidation,
            title: format!("Raw sol_invoke at line {} without program ID verification", cpi.line),
            file: cpi.file.clone(),
            line: Some(cpi.line),
            function: cpi.function_name.clone(),
            snippet,
            description: "sol_invoke / sol_invoke_signed is called without verifying the \
                target program ID. In Pinocchio, raw syscall invocation bypasses all framework \
                safety guarantees. An attacker can supply their own malicious program as the \
                CPI target, hijacking all token transfers or state mutations performed via CPI.".into(),
            recommendation: "Before sol_invoke, verify: \
                `assert_eq!(program_id, &expected_program_id);` \
                or use pinocchio-cpi's typed CPI builders that enforce program ID checks.".into(),
            anchor_fix: "if program_id != &expected_program_id { return Err(ProgramError::IncorrectProgramId); }".into(),
            cwe: "CWE-345".into(),
            needs_ai_context: false,
            ai_explanation: None,
            ai_severity: None,
            exploitability: 0,
            confirmed_by_taint: vec![],
        });
    }
    out
}

fn detect_pinocchio_missing_owner_check(
    visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    if !visitor.is_pinocchio { return out; }

    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();

            // Detect account access with no preceding owner check in the function
            if (t.contains(".data") || t.contains(".try_borrow_data"))
                && !t.trim_start().starts_with("//")
            {
                let function_start = lines[..i].iter().rposition(|l| {
                    l.trim().starts_with("pub fn ") || l.trim().starts_with("fn ")
                });

                if let Some(func_start) = function_start {
                    let func_body: String = lines[func_start..=i].join("\n");
                    let has_owner_check = func_body.contains("owner")
                        && (func_body.contains("==") || func_body.contains("assert_eq"));

                    if !has_owner_check {
                        let snippet = get_lines(&lines, i, 3);
                        out.push(Finding {
                            id: next_id(),
                            severity: Severity::High,
                            category: Category::AccountValidation,
                            title: "Account data accessed without owner verification".into(),
                            file: file.path.clone(),
                            line: Some(i + 1),
                            function: String::new(),
                            snippet,
                            description: "Account data is accessed via .data / .try_borrow_data() \
                                without first verifying the account owner. In Pinocchio, every \
                                AccountInfo is unverified — any program's account can be passed. \
                                Without owner verification, an attacker can supply a fake account \
                                that matches the expected data layout but is owned by a different program.".into(),
                            recommendation: "Add an owner check before any data access: \
                                `assert_eq!(account.owner, &expected_owner, \"Invalid account owner\");`".into(),
                            anchor_fix: String::new(),
                            cwe: "CWE-345".into(),
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

fn detect_pinocchio_account_index_oob(
    _visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }

        for (i, line) in file.content.lines().enumerate() {
            let t = line.trim();
            // Detect &accounts[N] without bounds check
            if t.contains("&accounts[") && !t.contains(".get(") {
                let has_bound_check = file.content.lines().skip(i.saturating_sub(10)).take(10).any(|l| {
                    let tt = l.trim();
                    tt.contains("accounts.len()") || tt.contains("accounts.is_empty()")
                        || tt.contains(">= accounts.len()")
                });

                if !has_bound_check {
                    let snippet = get_line_snippet(file, i, 4);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::AccountValidation,
                        title: "Account index access without bounds check — potential panic".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "accounts[N] indexing without a prior length check. \
                            In Pinocchio, accounts is a slice &[AccountInfo]. Indexing beyond \
                            its length causes a runtime panic, crashing the instruction. \
                            An attacker can construct a transaction with fewer accounts than \
                            expected, causing the program to panic and roll back legitimate operations.".into(),
                        recommendation: "Use accounts.get(N) instead of &accounts[N], \
                            or validate length first: \
                            `if accounts.len() < EXPECTED_COUNT { return Err(ProgramError::NotEnoughAccountKeys); }`".into(),
                        anchor_fix: String::new(),
                        cwe: "CWE-129".into(),
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

fn detect_pinocchio_no_signer_verify(
    _visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }

        // Look for functions that access accounts but never check .is_signer
        let mut current_fn = String::new();
        let mut fn_body_start = 0;
        let mut has_is_signer = false;

        for (i, line) in file.content.lines().enumerate() {
            let t = line.trim();

            if t.starts_with("pub fn ") || t.starts_with("fn ") {
                // Check previous function
                if !current_fn.is_empty() && !has_is_signer && fn_body_start > 0 {
                    let body: String = file.content.lines().skip(fn_body_start).take(i - fn_body_start).collect::<Vec<_>>().join("\n");
                    if body.contains("account") || body.contains("accounts") {
                        let snippet = get_line_snippet(file, fn_body_start, 2);
                        out.push(Finding {
                            id: next_id(),
                            severity: Severity::High,
                            category: Category::SignerAuthority,
                            title: format!("No signer verification in `{}` — authority not confirmed", current_fn),
                            file: file.path.clone(),
                            line: Some(fn_body_start + 1),
                            function: current_fn.clone(),
                            snippet,
                            description: format!(
                                "Function `{}` accesses accounts without checking .is_signer \
                                on any account. In Pinocchio, no account is verified as a signer \
                                unless the program explicitly checks. This means authority-gated \
                                operations (admin, fee changes, etc.) may be callable by anyone.",
                                current_fn
                            ),
                            recommendation: "For each authority account, add: \
                                `if !account.is_signer { return Err(ProgramError::MissingRequiredSignature); }`".into(),
                            anchor_fix: String::new(),
                            cwe: "CWE-862".into(),
                            needs_ai_context: true,
                            ai_explanation: None,
                            ai_severity: None,
                            exploitability: 0,
                            confirmed_by_taint: vec![],
                        });
                    }
                }

                current_fn = t.split('(').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("").to_string();
                fn_body_start = i + 1;
                has_is_signer = false;
            }

            if t.contains("is_signer") { has_is_signer = true; }
        }
    }
    out
}

fn detect_pinocchio_no_bump_check(
    _visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;

        let has_find_program = content.contains("find_program_address")
            || content.contains("try_find_program_address");

        let has_bump_check = content.contains("bump")
            && (content.contains("seeds") || content.contains("PDA"));

        if has_find_program && !has_bump_check {
            for (i, line) in content.lines().enumerate() {
                if line.contains("find_program_address") {
                    let snippet = get_line_snippet(file, i, 4);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::PdaSeedCollision,
                        title: "PDA derivation without bump validation — seed collision possible".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "Pinocchio program uses find_program_address but does not \
                            validate the bump seed on subsequent calls. Without storing and \
                            verifying the canonical bump, an attacker can supply a different \
                            non-canonical bump that still produces a valid PDA under a different \
                            seed set, enabling address collision attacks.".into(),
                        recommendation: "Store the canonical bump in the PDA account on init. \
                            On every access, verify: \
                            `let (expected_pda, _) = Pubkey::find_program_address(&[seeds], program_id); \
                            assert_eq!(account.key, &expected_pda);`".into(),
                        anchor_fix: String::new(),
                        cwe: "CWE-330".into(),
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

fn detect_pinocchio_instruction_data_validation(
    _visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;
        let lines: Vec<&str> = content.lines().collect();

        // Check if there's instruction data parsing but no length validation
        let has_data_parsing = content.contains("instruction_data")
            || content.contains("data.get")
            || content.contains("try_from_slice");

        let has_length_check = content.contains("instruction_data.len()")
            || content.contains("data.len()")
            || content.contains(">= 4") || content.contains(">= 8")
            || content.contains(">= 16") || content.contains(">= 32");

        if has_data_parsing && !has_length_check {
            for (i, line) in lines.iter().enumerate() {
                if line.contains("instruction_data") && line.contains("get(") {
                    let snippet = get_lines(&lines, i, 4);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::Medium,
                        category: Category::AccountValidation,
                        title: "Instruction data access without length validation — panic risk".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "instruction_data is accessed via get() or indexing without \
                            prior length validation. In Pinocchio, instruction_data is a raw &[u8]. \
                            If the data is shorter than expected, the program panics. Attacker can \
                            craft transactions with malformed instruction data to crash the program.".into(),
                        recommendation: "Add length check before parsing: \
                            `if instruction_data.len() < EXPECTED_LEN { return Err(ProgramError::InvalidInstructionData); }`".into(),
                        anchor_fix: String::new(),
                        cwe: "CWE-129".into(),
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

fn detect_pinocchio_missing_entrypoint_validation(
    _visitor: &ProjectVisitor,
    files: &[InputFile],
    next_id: &mut impl FnMut() -> String,
) -> Vec<Finding> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;

        if !content.contains("process_instruction") { continue; }

        // Check if the first thing process_instruction does is dispatch without validation
        let has_cpi_early = content.contains("sol_invoke")
            || content.contains("invoke_signed");
        let has_program_check_early = content.contains("program_id")
            && (content.contains("== Expected") || content.contains("!= Expected")
                || content.contains("expected_program_id") || content.contains("expected_program"));

        if has_cpi_early && !has_program_check_early {
            for (i, line) in content.lines().enumerate() {
                if line.contains("process_instruction") {
                    let snippet = get_line_snippet(file, i, 3);
                    out.push(Finding {
                        id: next_id(),
                        severity: Severity::High,
                        category: Category::CpiValidation,
                        title: "Entrypoint does not validate program_id before CPI".into(),
                        file: file.path.clone(),
                        line: Some(i + 1),
                        function: String::new(),
                        snippet,
                        description: "The process_instruction entrypoint performs CPIs without \
                            first validating the program_id. In Pinocchio, the entrypoint receives \
                            a &Pubkey parameter but the program does not verify it matches the \
                            expected program ID. This allows front-running via program upgrade \
                            or proxy substitution attacks.".into(),
                        recommendation: "At the start of process_instruction, add: \
                            `if program_id != &id() { return Err(ProgramError::IncorrectProgramId); }`".into(),
                        anchor_fix: String::new(),
                        cwe: "CWE-345".into(),
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

// Helper functions for snippet extraction

fn get_line_snippet(file: &InputFile, line_idx: usize, ctx: usize) -> String {
    let lines: Vec<&str> = file.content.lines().collect();
    get_lines(&lines, line_idx, ctx)
}

fn get_lines(lines: &[&str], line_idx: usize, ctx: usize) -> String {
    let start = line_idx.saturating_sub(ctx);
    let end = (line_idx + ctx + 1).min(lines.len());
    lines[start..end].join("\n")
}
