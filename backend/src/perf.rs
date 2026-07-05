// backend/src/perf.rs
// Performance & compute unit profiling detectors
// Each identifies patterns that waste CU or bloat compute budgets

use crate::{
    ast_visitor::ProjectVisitor,
    types::{InputFile, PerfCategory, PerfIssue, Severity},
};

pub fn detect_perf_issues(visitor: &ProjectVisitor, files: &[InputFile], budgets: &Option<std::collections::HashMap<String, u64>>) -> Vec<PerfIssue> {
    let mut out = vec![];
    out.extend(detect_unbounded_account_loop(visitor, files));
    out.extend(detect_cpi_in_loop(visitor, files));
    out.extend(detect_excessive_realloc(files));
    out.extend(detect_large_deserialization(visitor, files));
    out.extend(detect_redundant_account_read(files));
    out.extend(detect_no_compute_budget(files));
    out.extend(detect_inefficient_data_structure(visitor, files));
    out.extend(detect_deep_cpi_chain(visitor, files));
    out.extend(detect_anchor_padding_waste(visitor, files));
    out.extend(detect_large_cpi_serialization(visitor, files));
    out
}

//   1. UNBOUNDED ACCOUNT LOOP                ─

fn detect_unbounded_account_loop(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.contains("for ") && t.contains(".iter()") && !t.contains(".take(") && !t.contains("//") {
                // Verify this is an account iteration, not a generic Vec
                let ctx = lines[i..lines.len().min(i + 10)].join("\n");
                let is_account_op = ctx.contains(".try_borrow_mut") || ctx.contains(".try_borrow")
                    || ctx.contains("Account::try_from") || ctx.contains("accounts.");
                if is_account_op {
                    out.push(PerfIssue {
                        id: format!("PERF-{:03}", out.len() + 1),
                        severity: Severity::Low,
                        category: PerfCategory::UnboundedLoop,
                        title: "Unbounded loop over accounts — CU may scale with input count".into(),
                        description: format!("Line {}: `{}` iterates over accounts without a `.take(N)` bound. \
                            Each iteration adds ~5K CU. A malicious or large input can exhaust the compute budget.", i + 1, t),
                        recommendation: "Add `.take(MAX_ACCOUNTS)` or validate input count before looping.".into(),
                        file: file.path.clone(), line: Some(i + 1), function: String::new(),
                        cu_impact: 5000,
                    });
                }
            }
        }
    }
    out
}

//   2. CPI INSIDE LOOP                      ─

fn detect_cpi_in_loop(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        let mut in_for = false;
        let mut for_line = 0;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.starts_with("for ") && t.contains(" in ") && t.ends_with('{') {
                in_for = true;
                for_line = i;
            }
            if in_for {
                if t == "}" {
                    in_for = false;
                } else if (t.contains("invoke(") || t.contains("invoke_signed(") || t.contains("cpi::invoke"))
                    && !t.contains("//")
                {
                    out.push(PerfIssue {
                        id: format!("PERF-{:03}", out.len() + 1),
                        severity: Severity::Info,
                        category: PerfCategory::CpiInLoop,
                        title: "CPI call inside loop — CU cost multiplies".into(),
                        description: format!("Line {}: CPI invoke found inside a for-loop (line {}). \
                            Each CPI costs ~20K CU. If the loop runs N times, total CU = N×20K.", i + 1, for_line + 1),
                        recommendation: "Move CPIs outside the loop, or batch operations. \
                            Consider whether each iteration truly needs an external program call.".into(),
                        file: file.path.clone(), line: Some(i + 1), function: String::new(),
                        cu_impact: 20000,
                    });
                }
            }
        }
    }
    out
}

//   3. EXCESSIVE REALLOC                     ─

fn detect_excessive_realloc(files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if t.contains("realloc") && !t.contains("//") {
                // Check realloc size
                let size = t.split(',').nth(1).unwrap_or("0").trim();
                let has_large: bool = size.parse::<u64>().map(|s| s > 10_000).unwrap_or(false);
                let severity = if has_large { Severity::Low } else { Severity::Info };

                // Count realloc calls in same function
                let ctx_start = i.saturating_sub(5);
                let ctx_end = (i + 10).min(lines.len());
                let ctx = lines[ctx_start..ctx_end].join("\n");
                let count = ctx.matches("realloc").count();
                let multi = if count > 1 { " — multiple realloc calls detected" } else { "" };

                out.push(PerfIssue {
                    id: format!("PERF-{:03}", out.len() + 1),
                    severity,
                    category: PerfCategory::ExcessiveRealloc,
                    title: format!("Excessive account realloc{}", if count > 1 { " (multiple calls)" } else { "" }),
                    description: format!("Line {}: `realloc` with size `{}`{}. \
                        Each realloc costs ~10K CU + rent re-calculation. Large reallocs also fragment storage.", i + 1, size, multi),
                    recommendation: "Pre-allocate with the maximum expected size during init. \
                        If dynamic resizing is needed, realloc once with the final size.".into(),
                    file: file.path.clone(), line: Some(i + 1), function: String::new(),
                    cu_impact: 10000,
                });
            }
        }
    }
    out
}

//   4. LARGE ACCOUNT DESERIALIZATION          ─

fn detect_large_deserialization(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for s in &visitor.account_structs {
        if s.fields.len() >= 20 {
            // Find where this struct is deserialized
            let file = files.iter().find(|f| f.path == s.file);
            if let Some(f) = file {
                let lines: Vec<&str> = f.content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    let t = line.trim();
                    if t.contains(&s.name) && (t.contains("try_from") || t.contains("from_account_info")) {
                        out.push(PerfIssue {
                            id: format!("PERF-{:03}", out.len() + 1),
                            severity: Severity::Info,
                            category: PerfCategory::LargeDeserialization,
                            title: format!("Large account deserialization — `{}` has {} fields", s.name, s.fields.len()),
                            description: format!("`{}` has {} fields. Deserializing large accounts in hot \
                                instructions adds ~5K+ CU per op. Consider splitting into smaller structs \
                                or using zero-copy deserialization.", s.name, s.fields.len()),
                            recommendation: "Split the account into multiple smaller accounts with \
                                targeted data. Use `#[account(zero_copy)]` for accounts >16 fields.".into(),
                            file: s.file.clone(), line: Some(i + 1), function: String::new(),
                            cu_impact: 5000,
                        });
                        break;
                    }
                }
            }
        }
    }
    out
}

//   5. REDUNDANT ACCOUNT READ                ─

fn detect_redundant_account_read(files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let lines: Vec<&str> = file.content.lines().collect();
        // Track field reads per function
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // Find a function
            if t.starts_with("pub fn ") {
                let fn_name = t.split('(').next().unwrap_or("").trim();
                let body_end = lines[i..].iter().position(|l| l.trim() == "}" && l.trim().starts_with("}"));
                let end = body_end.map(|p| i + p).unwrap_or(lines.len().saturating_sub(1));
                let body = &lines[i..=end];

                let mut reads: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
                for (j, bl) in body.iter().enumerate() {
                    let b = bl.trim();
                    if b.contains(".amount") || b.contains(".balance") || b.contains(".total_supply")
                        || b.contains(".price") || b.contains(".value")
                    {
                        let key = b.split('.').next().unwrap_or("").trim().to_string();
                        if !key.is_empty() {
                            reads.entry(key).or_default().push(i + j + 1);
                        }
                    }
                }

                for (field, lines_hit) in &reads {
                    if lines_hit.len() > 2 {
                        out.push(PerfIssue {
                            id: format!("PERF-{:03}", out.len() + 1),
                            severity: Severity::Info,
                            category: PerfCategory::RedundantAccountRead,
                            title: format!("Redundant field `.{}` reads in `{}` — cache result", field, fn_name),
                            description: format!("Field `{}` is read {} times in `{}` (lines: {:?}). \
                                Each deserialization access costs ~500 CU. Cache with `let val = account.field;`.", field, lines_hit.len(), fn_name, lines_hit),
                            recommendation: format!("Assign to a local variable at the top: `let {} = account.{};`", field, field),
                            file: file.path.clone(), line: Some(lines_hit[0]), function: fn_name.to_string(),
                            cu_impact: 500 * (lines_hit.len() as u64).saturating_sub(1),
                        });
                    }
                }
            }
        }
    }
    out
}

//   6. NO COMPUTE BUDGET                     ─

fn detect_no_compute_budget(files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        if !file.content.contains("compute_budget") && !file.content.contains("ComputeBudget") {
            // Find any instruction handler
            let lines: Vec<&str> = file.content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim();
                if t.starts_with("pub fn ") && t.contains("ctx: Context<") {
                    out.push(PerfIssue {
                        id: format!("PERF-{:03}", out.len() + 1),
                        severity: Severity::Info,
                        category: PerfCategory::NoComputeBudget,
                        title: "No compute budget set — using default 200K CU limit".into(),
                        description: format!("Line {}: Instruction `{}` does not set a compute budget. \
                            Default is 200K CU. Complex instructions may hit this limit. \
                            Set a higher budget explicitly.", i + 1, t),
                        recommendation: "Add `sol_compute_budget::set_compute_unit_limit(400_000)?` \
                            at the start of the instruction if it needs more than 200K CU.".into(),
                        file: file.path.clone(), line: Some(i + 1), function: String::new(),
                        cu_impact: 0,
                    });
                    break;
                }
            }
        }
    }
    out
}

//   7. INEFFICIENT DATA STRUCTURES           ─

fn detect_inefficient_data_structure(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for s in &visitor.account_structs {
        for f in &s.fields {
            if f.field_type == "String" || f.field_type == "Vec<u8>" || f.field_type.starts_with("Vec<") {
                let file = files.iter().find(|f2| f2.path == s.file);
                if let Some(f2) = file {
                    let lines: Vec<&str> = f2.content.lines().collect();
                    for (i, line) in lines.iter().enumerate() {
                        if line.trim().contains(&f.name) && line.contains(&s.name) {
                            out.push(PerfIssue {
                                id: format!("PERF-{:03}", out.len() + 1),
                                severity: Severity::Info,
                                category: PerfCategory::InefficientDataStructure,
                                title: format!("Inefficient `{}` field `{}` — use fixed-size instead", f.field_type, f.name),
                                description: format!("Field `{}` in `{}` uses `{}`. \
                                    Dynamic types add serialization overhead (~1-3K CU) and complicate \
                                    account sizing. Prefer `[u8; N]` or a fixed-size struct.", f.name, s.name, f.field_type),
                                recommendation: format!("Replace `{}` with `[u8; MAX_SIZE]` or use Anchor's `pub {}: [u8; 32]`", f.field_type, f.name),
                                file: s.file.clone(), line: Some(i + 1), function: String::new(),
                                cu_impact: 2000,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

//   8. DEEP CPI CHAIN                       ─

fn detect_deep_cpi_chain(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    let unique_programs: std::collections::HashSet<&str> = visitor.cpi_calls.iter()
        .map(|c| c.program.as_str())
        .collect();
    if unique_programs.len() >= 3 {
        for file in files {
            if !file.path.ends_with(".rs") { continue; }
            let lines: Vec<&str> = file.content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim();
                if t.starts_with("pub fn ") && t.contains("ctx: Context<") {
                    out.push(PerfIssue {
                        id: format!("PERF-{:03}", out.len() + 1),
                        severity: Severity::Info,
                        category: PerfCategory::DeepCpiChain,
                        title: format!("Deep CPI chain — {} different programs called", unique_programs.len()),
                        description: format!("This program calls into {} different programs via CPI. \
                            Each CPI hop costs ~20K CU and adds latency. Deep chains (A→B→C) reduce the \
                            available CU budget for each program, increasing failure risk.", unique_programs.len()),
                        recommendation: "Minimize CPI dependencies. Consolidate logic into fewer \
                            external calls. Consider whether all CPIs are necessary in a single instruction.".into(),
                        file: file.path.clone(), line: Some(i + 1), function: String::new(),
                        cu_impact: 20000 * unique_programs.len() as u64,
                    });
                    break;
                }
            }
        }
    }
    out
}

//   9. ANCHOR PADDING WASTE                 ─

fn detect_anchor_padding_waste(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for s in &visitor.account_structs {
        for f in &s.fields {
            if f.name.starts_with("_reserved") || f.name.starts_with("reserved") || f.name == "padding" {
                let file = files.iter().find(|f2| f2.path == s.file);
                if let Some(f2) = file {
                    let lines: Vec<&str> = f2.content.lines().collect();
                    for (i, line) in lines.iter().enumerate() {
                        if line.trim().contains(&f.name) && line.contains(&s.name) {
                            let is_array = f.field_type.contains(';');
                            let size = if is_array {
                                f.field_type.split(';').nth(1).and_then(|s| s.trim().trim_end_matches(']').parse::<u64>().ok()).unwrap_or(1)
                            } else { 1 };
                            out.push(PerfIssue {
                                id: format!("PERF-{:03}", out.len() + 1),
                                severity: Severity::Info,
                                category: PerfCategory::AnchorPaddingWaste,
                                title: format!("Reserved/padding field `{}` in `{}` — {} bytes wasted", f.name, s.name, size * 8),
                                description: format!("Field `{}` in `{}` type `{}` is reserved padding. \
                                    Each reserved byte consumes rent and CU during serialization. \
                                    Only add reserved fields when upgrade compatibility is proven necessary.", f.name, s.name, f.field_type),
                                recommendation: "Remove unused reserved fields. Use `zero_copy` instead \
                                    of padding for upgradeable accounts. Each padding byte costs rent forever.".into(),
                                file: s.file.clone(), line: Some(i + 1), function: String::new(),
                                cu_impact: 1000 * size,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

//   10. LARGE CPI SERIALIZATION              ─

fn detect_large_cpi_serialization(visitor: &ProjectVisitor, files: &[InputFile]) -> Vec<PerfIssue> {
    let mut out = vec![];
    for cpi in &visitor.cpi_calls {
        let file = files.iter().find(|f| f.path == cpi.file);
        if let Some(f) = file {
            let lines: Vec<&str> = f.content.lines().collect();
            let ctx_start = cpi.line.saturating_sub(10);
            let ctx_end = (cpi.line + 10).min(lines.len());
            let ctx = lines[ctx_start..ctx_end].join("\n");
            // Estimate data size passed in CPI by counting account args
            let acct_count = ctx.matches("AccountInfo").count() + ctx.matches("Account<").count();
            if acct_count > 5 {
                out.push(PerfIssue {
                    id: format!("PERF-{:03}", out.len() + 1),
                    severity: Severity::Info,
                    category: PerfCategory::LargeCpiSerialization,
                    title: format!("Large CPI at `{}` — {} accounts serialized", cpi.program, acct_count),
                    description: format!("Line {}: CPI to `{}` serializes ~{} accounts. \
                        Each account adds ~1-3K CU for serialization + CPI overhead. \
                        Consider reducing accounts passed or using packed accounts.", cpi.line + 1, cpi.program, acct_count),
                    recommendation: "Reduce accounts passed across CPI. Use packed accounts \
                        or pass only the minimum data needed by the target program.".into(),
                    file: cpi.file.clone(), line: Some(cpi.line + 1), function: cpi.function_name.clone(),
                    cu_impact: 2000 * acct_count as u64,
                });
            }
        }
    }
    out
}
