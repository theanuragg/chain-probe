use crate::types::{Framework, InputFile};
use crate::ast_visitor::ProjectVisitor;

pub fn detect_framework(visitor: &ProjectVisitor, files: &[InputFile]) -> Framework {
    // 1. Check Cargo.toml for dependency-based detection
    for file in files {
        if !file.path.ends_with("Cargo.toml") { continue; }
        let content = &file.content;
        let lower = content.to_lowercase();

        // Pinocchio dependency takes priority
        if lower.contains("pinocchio") {
            return Framework::Pinocchio;
        }
    }

    // 2. Check .rs files for framework-specific patterns
    for file in files {
        if !file.path.ends_with(".rs") { continue; }
        let content = &file.content;

        // Pinocchio entrypoint pattern
        if content.contains("entrypoint!(")
            && !content.contains("anchor_lang")
        {
            // Check if it uses pinocchio imports
            if content.contains("use pinocchio")
                || content.contains("pinocchio::entrypoint")
            {
                return Framework::Pinocchio;
            }
        }

        // Native Solana entrypoint (no framework)
        if content.contains("solana_program::entrypoint!")
            || (content.contains("process_instruction")
                && content.contains("entrypoint!")
                && !content.contains("anchor_lang"))
        {
            return Framework::Native;
        }
    }

    // 3. Check visitor state from AST parsing
    if !visitor.account_structs.is_empty() || visitor.anchor_version.is_some() {
        return Framework::Anchor;
    }

    // 4. Fallback: has .rs files with process_instruction
    let has_process = files.iter().any(|f| {
        f.path.ends_with(".rs") && f.content.contains("process_instruction")
    });
    if has_process {
        return Framework::Native;
    }

    Framework::Unknown
}
