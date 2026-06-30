// Parses every .rs file with `syn` and extracts all Anchor-relevant constructs.
// This is pure deterministic parsing — no heuristics, no AI.

use std::collections::HashMap;
use syn::{visit::Visit, *};
use crate::types::{
    AccountField, AccountStructInfo, ArithmeticOp, CpiCallInfo,
    InstructionInfo, PdaInfo,
};

pub struct ProjectVisitor {
    pub current_file: String,
    pub instructions: Vec<InstructionInfo>,
    pub account_structs: Vec<AccountStructInfo>,
    pub state_accounts: Vec<String>,
    pub state_account_fields: HashMap<String, Vec<(String, String)>>,
    pub cpi_calls: Vec<CpiCallInfo>,
    pub pda_derivations: Vec<PdaInfo>,
    pub arithmetic_ops: Vec<ArithmeticOp>,
    pub modules: Vec<String>,
    pub anchor_version: Option<String>,
    pub program_name: Option<String>,
    pub uses_token_program: bool,
    pub uses_token_2022: bool,
    pub uses_init_if_needed: bool,
    pub overflow_checks_enabled: bool,
    pub dependency_count: usize,
    pub raw_lines: HashMap<String, Vec<String>>,
    // Pinocchio support — NEW
    pub is_pinocchio: bool,
    pub is_no_std: bool,
    pub pinocchio_manual_accounts: Vec<(String, String, String)>, // (function, account_var, type)
    pub uses_pinocchio_log: bool,
    pub uses_pinocchio_cpi: bool,
    pub uses_raw_invoke: Vec<CpiCallInfo>,
    pub pinocchio_program_id_checks: Vec<(String, usize)>, // (function, line)
}

impl ProjectVisitor {
    pub fn new() -> Self {
        ProjectVisitor {
            current_file: String::new(),
            instructions: vec![],
            account_structs: vec![],
            state_accounts: vec![],
            state_account_fields: HashMap::new(),
            cpi_calls: vec![],
            pda_derivations: vec![],
            arithmetic_ops: vec![],
            modules: vec![],
            anchor_version: None,
            program_name: None,
            uses_token_program: false,
            uses_token_2022: false,
            uses_init_if_needed: false,
            overflow_checks_enabled: false,
            dependency_count: 0,
            raw_lines: HashMap::new(),
            is_pinocchio: false,
            is_no_std: false,
            pinocchio_manual_accounts: vec![],
            uses_pinocchio_log: false,
            uses_pinocchio_cpi: false,
            uses_raw_invoke: vec![],
            pinocchio_program_id_checks: vec![],
        }
    }

    // Entry points

    pub fn visit_rs_file(&mut self, path: &str, content: &str) {
        self.current_file = path.to_string();
        self.raw_lines.insert(
            path.to_string(),
            content.lines().map(|l| l.to_string()).collect(),
        );
        self.modules.push(path.to_string());

        // Detectar Pinocchio imports e no_std
        if content.contains("#![no_std]") || content.contains("#[no_std]") {
            self.is_no_std = true;
        }
        if content.contains("use pinocchio") || content.contains("pinocchio::") {
            self.is_pinocchio = true;
        }
        if content.contains("pinocchio::log")
            || content.contains("pinocchio_log")
            || content.contains("sol_log_")
        {
            self.uses_pinocchio_log = true;
        }
        if content.contains("pinocchio::cpi")
            || content.contains("pinocchio_cpi")
        {
            self.uses_pinocchio_cpi = true;
        }

        // Detect Pinocchio entrypoint pattern
        self.detect_pinocchio_entrypoint(path, content);

        match syn::parse_file(content) {
            Ok(file) => {
                for item in &file.items {
                    self.visit_item_dispatch(item);
                }
            }
            Err(_) => {
                // syn couldn't parse — use line-level fallback
                self.line_level_fallback(path, content);
            }
        }
    }

    /// Detect Pinocchio-style entrypoint and manual account parsing
    fn detect_pinocchio_entrypoint(&mut self, path: &str, content: &str) {
        // Pinocchio entrypoint! macro
        if content.contains("entrypoint!(process_instruction)") {
            self.instructions.push(InstructionInfo {
                name: "process_instruction".into(),
                file: path.to_string(),
                line: self.find_line(content, "entrypoint!"),
                params: vec!["program_id".into(), "accounts".into(), "instruction_data".into()],
                ctx_type: "PinocchioEntrypoint".into(),
            });
        }

        // Pinocchio lazy_program_entrypoint
        if content.contains("lazy_program_entrypoint!") {
            self.instructions.push(InstructionInfo {
                name: "process_instruction".into(),
                file: path.to_string(),
                line: self.find_line(content, "lazy_program_entrypoint!"),
                params: vec![],
                ctx_type: "PinocchioLazyEntrypoint".into(),
            });
        }

        // Manual account parsing: accounts.iter() or &accounts[0..] patterns
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();

            // Detect manual account iteration
            if t.contains("let accounts_iter = &mut accounts.iter()")
                || t.contains("let account = &accounts[")
            {
                self.pinocchio_manual_accounts.push((
                    self.get_current_function(content, i),
                    t.to_string(),
                    "Pinocchio".into(),
                ));
            }

            // Detect raw CPI invocation (invoke_signed without Anchor wrappers)
            if (t.contains("sol_invoke(") || t.contains("sol_invoke_signed(")
                || t.contains("syscall::invoke"))
                && !t.trim_start().starts_with("//")
            {
                self.uses_raw_invoke.push(CpiCallInfo {
                    file: path.to_string(),
                    line: i + 1,
                    function_name: "sol_invoke".into(),
                    program: "raw".into(),
                });
            }

            // Detect program_id checks in Pinocchio: require!(program_id == ...)
            if t.contains("program_id") && t.starts_with("if") {
                let has_require = content.lines().skip(i).take(5).any(|l| {
                    l.contains("require!") || l.contains("return Err(")
                });
                if has_require {
                    self.pinocchio_program_id_checks
                        .push((content.lines().nth(i).unwrap_or("").to_string(), i + 1));
                }
            }
        }
    }

    fn find_line(&self, content: &str, pattern: &str) -> usize {
        content.lines().position(|l| l.contains(pattern)).unwrap_or(0) + 1
    }

    fn get_current_function(&self, content: &str, line_idx: usize) -> String {
        let lines: Vec<&str> = content.lines().take(line_idx).collect();
        for line in lines.iter().rev() {
            let t = line.trim();
            if t.starts_with("pub fn ") || t.starts_with("fn ") {
                return t.split('(').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("").to_string();
            }
        }
        String::new()
    }

    pub fn visit_toml_file(&mut self, path: &str, content: &str) {
        let mut in_deps = false;
        let mut in_workspace_deps = false;
        let mut in_release = false;
        let mut in_workspace = false;
        let mut is_workspace_root = false;

        for line in content.lines() {
            let t = line.trim();

            // Track section headers
            if t == "[dependencies]" {
                in_deps = true; in_workspace_deps = false;
                in_release = false; in_workspace = false; continue;
            }
            if t == "[workspace.dependencies]" || t == "[workspace]" {
                in_workspace = true; is_workspace_root = true;
                in_workspace_deps = t == "[workspace.dependencies]";
                in_deps = false; in_release = false; continue;
            }
            if t == "[profile.release]" {
                in_release = true; in_deps = false;
                in_workspace = false; in_workspace_deps = false; continue;
            }
            if t.starts_with('[') {
                in_deps = false; in_release = false;
                // Don't reset workspace flag when we see other sections
                if !t.starts_with("[workspace") {
                    in_workspace = false; in_workspace_deps = false;
                }
                continue;
            }

            // Parse dependencies section
            let in_any_deps = in_deps || in_workspace_deps;
            if in_any_deps && !t.is_empty() && !t.starts_with('#') {
                if in_deps { self.dependency_count += 1; }

                // Detect anchor-lang version — handles multiple formats:
                //   anchor-lang = "0.29.0"
                //   anchor-lang = { version = "0.29.0", ... }
                //   anchor-lang = { workspace = true }  ← version in workspace root
                if t.starts_with("anchor-lang") {
                    if t.contains("workspace = true") {
                        // Version is in [workspace.dependencies] in the root Cargo.toml
                        // We'll pick it up when we visit the workspace root
                        if self.anchor_version.is_none() {
                            self.anchor_version = Some("workspace".to_string());
                        }
                    } else {
                        // Direct version: "0.29.0" or version = "0.29.0"
                        if let Some(v) = extract_version_from_dep(t) {
                            // Workspace deps override "workspace" placeholder
                            if self.anchor_version.as_deref() == Some("workspace")
                                || self.anchor_version.is_none()
                            {
                                self.anchor_version = Some(v);
                            }
                        }
                    }
                }

                if t.contains("init-if-needed") { self.uses_init_if_needed = true; }
                if t.starts_with("pinocchio") { self.is_pinocchio = true; }
                if t.starts_with("pinocchio-log") { self.uses_pinocchio_log = true; }
                if t.starts_with("pinocchio-cpi") || t.starts_with("pinocchio_cpi") { self.uses_pinocchio_cpi = true; }
            }

            // Parse [workspace.dependencies] for anchor version
            if in_workspace_deps && t.starts_with("anchor-lang") {
                if let Some(v) = extract_version_from_dep(t) {
                    // This is the canonical version for workspace projects
                    self.anchor_version = Some(v);
                }
            }

            // Parse [profile.release]
            if in_release && t.contains("overflow-checks") && t.contains("true") {
                self.overflow_checks_enabled = true;
            }

            // Program name from [package]
            if t.starts_with("name") && t.contains('=') && !t.starts_with("name.") {
                if let Some(name) = extract_quoted_value(t) {
                    if self.program_name.is_none() && !name.is_empty()
                        && !name.contains(' ') // avoid matching description lines
                    {
                        self.program_name = Some(name);
                    }
                }
            }
        }

        // If this is the workspace root, prefer its name as a fallback
        if is_workspace_root && path.ends_with("Cargo.toml") {
            // already handled above via in_workspace_deps
        }
    }

    // Item dispatch

    fn visit_item_dispatch(&mut self, item: &Item) {
        match item {
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for i in items { self.visit_item_dispatch(i); }
                }
            }
            Item::Fn(f) => self.process_fn(f),
            Item::Struct(s) => self.process_struct(s),
            Item::Impl(i) => self.process_impl(i),
            Item::Use(u) => self.process_use(u),
            _ => {}
        }
    }

    // Function processing

    fn process_fn(&mut self, f: &ItemFn) {
        let name = f.sig.ident.to_string();
        let ctx_type = extract_context_type(&f.sig);

        if !ctx_type.is_empty() {
            let params: Vec<String> = f.sig.inputs.iter()
                .skip(1)
                .filter_map(|arg| {
                    if let FnArg::Typed(pt) = arg {
                        Some(quote::quote!(#pt).to_string())
                    } else { None }
                })
                .collect();

            self.instructions.push(InstructionInfo {
                name: name.clone(),
                file: self.current_file.clone(),
                line: 0, // syn spans don't give line numbers outside proc-macro context
                params,
                ctx_type,
            });
        }

        // Scan body for CPIs and arithmetic
        self.scan_block_for_patterns(&f.block, &name);
    }

    //   Struct processing                           ─

    fn process_struct(&mut self, s: &ItemStruct) {
        let name = s.ident.to_string();
        let attrs = &s.attrs;

        // #[account] → state type — extract fields for taint + permission analysis
        if has_attr_name(attrs, "account") {
            self.state_accounts.push(name.clone());

            // Extract all fields from the state struct
            // This lets taint analysis understand what fields a state account has
            // e.g. Vault { authority: Pubkey, balance: u64, bump: u8 }
            if let Fields::Named(named) = &s.fields {
                let fields: Vec<(String, String)> = named.named.iter()
                    .filter_map(|f| {
                        let fname = f.ident.as_ref()?.to_string();
                        let ftype = quote::quote!(#f.ty).to_string();
                        // Normalize type string: remove spaces around angle brackets
                        let ftype = ftype.replace(" < ", "<").replace(" > ", ">")
                            .replace(" , ", ", ").trim().to_string();
                        Some((fname, ftype))
                    })
                    .collect();
                if !fields.is_empty() {
                    self.state_account_fields.insert(name.clone(), fields);
                }
            }
        }

        // #[derive(Accounts)] → instruction context struct
        if !has_derive(attrs, "Accounts") { return; }

        let mut fields = vec![];
        let mut has_signer = false;
        let mut has_pda = false;
        let mut has_init = false;
        let mut has_close = false;

        if let Fields::Named(named) = &s.fields {
            for field in &named.named {
                let fname = field.ident.as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let ftype = quote::quote!(#field.ty).to_string();

                let mut constraints = vec![];
                let mut is_signer = false;
                let mut is_mut = false;
                let mut has_has_one = false;
                let mut has_constraint_attr = false;
                let mut seeds: Vec<String> = vec![];
                let mut bump_stored = false;
                let mut is_pda = false;

                // Type-level signer detection
                if ftype.contains("Signer") {
                    is_signer = true;
                    has_signer = true;
                }

                // Parse #[account(...)] constraints
                for attr in &field.attrs {
                    let attr_str = quote::quote!(#attr).to_string();
                    if !attr_str.contains("account") { continue; }

                    constraints.push(attr_str.clone());
                    if attr_str.contains("mut") { is_mut = true; }
                    if attr_str.contains("has_one") { has_has_one = true; }
                    if attr_str.contains("constraint") { has_constraint_attr = true; }
                    if attr_str.contains("init_if_needed") { self.uses_init_if_needed = true; }
                    if attr_str.contains("init") && !attr_str.contains("init_if") {
                        has_init = true;
                    }
                    if attr_str.contains("close") { has_close = true; }
                    if attr_str.contains("seeds") {
                        is_pda = true;
                        has_pda = true;
                        seeds = extract_seeds_from_attr(&attr_str);
                        bump_stored = attr_str.contains("bump =") && !attr_str.contains("bump = bump");
                    }
                }

                if is_pda {
                    self.pda_derivations.push(PdaInfo {
                        file: self.current_file.clone(),
                        line: 0,
                        account_name: fname.clone(),
                        seeds: seeds.clone(),
                        bump_stored,
                        canonical_bump: bump_stored,
                    });
                }

                fields.push(AccountField {
                    name: fname,
                    field_type: ftype,
                    constraints,
                    is_signer,
                    is_mut,
                    has_has_one,
                    has_constraint: has_constraint_attr,
                    seeds,
                    bump_stored,
                });
            }
        }

        self.account_structs.push(AccountStructInfo {
            name,
            file: self.current_file.clone(),
            line: 0,
            fields,
            has_signer,
            has_pda,
            has_init,
            has_close,
        });
    }

    //   Impl block processing                         ─

    fn process_impl(&mut self, imp: &ItemImpl) {
        for item in &imp.items {
            if let ImplItem::Fn(method) = item {
                let name = method.sig.ident.to_string();
                self.scan_block_for_patterns(&method.block, &name);
            }
        }
    }

    //   Use statement processing                        

    fn process_use(&mut self, u: &ItemUse) {
        let s = quote::quote!(#u).to_string();
        if s.contains("token") { self.uses_token_program = true; }
        if s.contains("token_interface") || s.contains("token_2022") {
            self.uses_token_2022 = true;
        }
    }

    //   Block scanner (CPIs + arithmetic)                   ─

    fn scan_block_for_patterns(&mut self, block: &Block, fn_name: &str) {
        for stmt in &block.stmts {
            self.scan_stmt(stmt, fn_name);
        }
    }

    fn scan_stmt(&mut self, stmt: &Stmt, fn_name: &str) {
        match stmt {
            Stmt::Expr(e, _) => self.scan_expr(e, fn_name),
            Stmt::Local(l) => {
                if let Some(init) = &l.init {
                    self.scan_expr(&init.expr, fn_name);
                }
            }
            _ => {}
        }
    }

    fn scan_expr(&mut self, expr: &Expr, fn_name: &str) {
        match expr {
            Expr::Call(c) => {
                let s = quote::quote!(#c).to_string();
                if is_cpi_call(&s) {
                    self.cpi_calls.push(CpiCallInfo {
                        file: self.current_file.clone(),
                        line: 0,
                        function_name: extract_call_name(&s),
                        program: if s.contains("token_interface") { "token_interface" }
                                 else if s.contains("token") { "spl_token" }
                                 else { "unknown" }.to_string(),
                    });
                }
                for arg in &c.args { self.scan_expr(arg, fn_name); }
            }
            Expr::MethodCall(mc) => {
                let s = quote::quote!(#mc).to_string();
                if is_cpi_call(&s) {
                    self.cpi_calls.push(CpiCallInfo {
                        file: self.current_file.clone(),
                        line: 0,
                        function_name: mc.method.to_string(),
                        program: "unknown".to_string(),
                    });
                }
                self.scan_expr(&mc.receiver, fn_name);
                for arg in &mc.args { self.scan_expr(arg, fn_name); }
            }
            Expr::Binary(b) => {
                let op_str = match &b.op {
                    BinOp::Add(_) => Some("+"),
                    BinOp::Sub(_) => Some("-"),
                    BinOp::Mul(_) => Some("*"),
                    BinOp::Div(_) => Some("/"),
                    _ => None,
                };
                if let Some(op) = op_str {
                    let expr_str = quote::quote!(#b).to_string();
                    if looks_like_token_amount(&expr_str) {
                        let uses_checked = expr_str.contains("checked_")
                            || expr_str.contains("saturating_");
                        self.arithmetic_ops.push(ArithmeticOp {
                            file: self.current_file.clone(),
                            line: 0,
                            op: op.to_string(),
                            in_function: fn_name.to_string(),
                            uses_checked,
                        });
                    }
                }
                self.scan_expr(&b.left, fn_name);
                self.scan_expr(&b.right, fn_name);
            }
            Expr::Block(b) => self.scan_block_for_patterns(&b.block, fn_name),
            Expr::If(i) => {
                self.scan_expr(&i.cond, fn_name);
                self.scan_block_for_patterns(&i.then_branch, fn_name);
                if let Some((_, e)) = &i.else_branch { self.scan_expr(e, fn_name); }
            }
            Expr::Assign(a) => {
                self.scan_expr(&a.left, fn_name);
                self.scan_expr(&a.right, fn_name);
            }
            _ => {}
        }
    }

    //   Line-level fallback                          ─
    // Used when syn fails to parse (e.g. macro-heavy files)

    fn line_level_fallback(&mut self, path: &str, content: &str) {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();

            if t.starts_with("pub fn ") && t.contains("Context<") {
                let name = t.split('(').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("unknown").to_string();
                let ctx = extract_between(t, "Context<", ">");
                self.instructions.push(InstructionInfo {
                    name, file: path.to_string(), line: i + 1,
                    params: vec![], ctx_type: ctx,
                });
            }

            // Pinocchio entrypoint detection in line-level fallback
            if t == "pub fn process_instruction(" || t == "fn process_instruction(" {
                let has_pinocchio_input = t.contains("&[AccountInfo]")
                    || t.contains("program_id: &Pubkey")
                    || content.lines().take(i + 5).any(|l| l.contains("&[AccountInfo]"));
                if has_pinocchio_input {
                    self.instructions.push(InstructionInfo {
                        name: "process_instruction".into(),
                        file: path.to_string(), line: i + 1,
                        params: vec!["program_id".into(), "accounts".into(), "instruction_data".into()],
                        ctx_type: "PinocchioEntrypoint".into(),
                    });
                }
            }

            if t.contains("transfer(") || t.contains("transfer_checked(")
                || t.contains("invoke(") || t.contains("close_account(") {
                self.cpi_calls.push(CpiCallInfo {
                    file: path.to_string(), line: i + 1,
                    function_name: extract_call_name(t),
                    program: "unknown".to_string(),
                });
            }

            // Pinocchio raw CPI patterns
            if t.contains("sol_invoke(") || t.contains("sol_invoke_signed(") {
                self.uses_raw_invoke.push(CpiCallInfo {
                    file: path.to_string(), line: i + 1,
                    function_name: "sol_invoke".into(),
                    program: "raw".into(),
                });
            }
        }
    }

    //   Snippet extraction                           

    pub fn snippet(&self, file: &str, line: usize, ctx: usize) -> String {
        let Some(lines) = self.raw_lines.get(file) else { return String::new(); };
        let start = line.saturating_sub(ctx + 1);
        let end = (line + ctx).min(lines.len());
        if start >= end { return String::new(); }
        lines[start..end].join("\n")
    }

    /// Get snippet by searching for a pattern in a file
    pub fn snippet_for_pattern(&self, file: &str, pattern: &str, ctx: usize) -> (String, usize) {
        let Some(lines) = self.raw_lines.get(file) else {
            return (String::new(), 0);
        };
        for (i, line) in lines.iter().enumerate() {
            if line.contains(pattern) {
                let start = i.saturating_sub(ctx);
                let end = (i + ctx + 1).min(lines.len());
                return (lines[start..end].join("\n"), i + 1);
            }
        }
        (String::new(), 0)
    }
}

//   Pure helper functions                           ─

fn has_derive(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        let s = quote::quote!(#a).to_string();
        s.contains("derive") && s.contains(name)
    })
}

fn has_attr_name(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        let s = quote::quote!(#a).to_string();
        // Match #[account] but not #[account(..)] derive
        s.contains(name) && !s.contains("derive")
    })
}

fn extract_context_type(sig: &Signature) -> String {
    for input in &sig.inputs {
        if let FnArg::Typed(pt) = input {
            let s = quote::quote!(#pt.ty).to_string();
            if s.contains("Context") {
                return extract_between(&s, "Context <", ">");
            }
        }
    }
    String::new()
}

fn extract_seeds_from_attr(attr: &str) -> Vec<String> {
    let mut seeds = vec![];
    if let Some(start) = attr.find("seeds = [") {
        let rest = &attr[start + 9..];
        if let Some(end) = rest.find(']') {
            for s in rest[..end].split(',') {
                let t = s.trim().to_string();
                if !t.is_empty() { seeds.push(t); }
            }
        }
    }
    seeds
}

fn is_cpi_call(s: &str) -> bool {
    s.contains("transfer(") || s.contains("transfer_checked(")
        || s.contains("invoke(") || s.contains("invoke_signed(")
        || s.contains("close_account(") || s.contains("mint_to(")
        || s.contains("burn(")
}

fn looks_like_token_amount(s: &str) -> bool {
    s.contains("amount") || s.contains("balance") || s.contains("reserve")
        || s.contains("deposit") || s.contains("reward") || s.contains("fee")
        || s.contains("total") || s.contains("supply") || s.contains("staked")
}

fn extract_call_name(s: &str) -> String {
    if let Some(p) = s.find('(') {
        s[..p].split("::").last().unwrap_or("").trim().to_string()
    } else {
        s.split_whitespace().next().unwrap_or("").to_string()
    }
}

pub fn extract_between(s: &str, start: &str, end: &str) -> String {
    if let Some(si) = s.find(start) {
        let rest = &s[si + start.len()..];
        if let Some(ei) = rest.find(end) {
            return rest[..ei].trim().to_string();
        }
    }
    String::new()
}

pub fn extract_quoted_value(s: &str) -> Option<String> {
    let first = s.find('"')?;
    let rest = &s[first + 1..];
    let second = rest.find('"')?;
    Some(rest[..second].to_string())
}

/// Extract a semver version from a Cargo dependency line.
/// Handles:
///   anchor-lang = "0.29.0"
///   anchor-lang = { version = "0.29.0", features = [...] }
///   anchor-lang.version = "0.29.0"
pub fn extract_version_from_dep(line: &str) -> Option<String> {
    // Find any quoted value that looks like a semver
    let first = line.find('"')?;
    let rest = &line[first + 1..];
    let second = rest.find('"')?;
    let candidate = &rest[..second];

    // Must start with a digit (semver) or 'v' followed by digit
    let candidate = candidate.trim_start_matches('v');
    if candidate.chars().next()?.is_ascii_digit() {
        Some(candidate.to_string())
    } else {
        None
    }
}

pub fn get_line_snippet(content: &str, line_idx: usize, ctx: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line_idx.saturating_sub(ctx);
    let end = (line_idx + ctx + 1).min(lines.len());
    lines[start..end].join("\n")
}
