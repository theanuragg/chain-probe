use crate::types::{AnalysisReport, Finding, Severity};

/// Generate a Trident-compatible fuzz harness for detected vulnerabilities
pub fn generate_trident_harness(report: &AnalysisReport) -> String {
    let mut out = String::new();

    out.push_str("// Auto-generated fuzz harness by ChainProbe\n");
    out.push_str("// Target: ");
    out.push_str(&report.profile.program_name);
    out.push_str("\n");
    out.push_str("// Framework: ");
    out.push_str(report.profile.framework.as_str());
    out.push_str("\n// Generated: ");
    out.push_str(&report.analyzed_at.to_rfc3339());
    out.push_str("\n\n");

    out.push_str("use trident_client::prelude::*;\n");
    out.push_str("use ");
    out.push_str(&report.profile.program_name.replace('-', "_"));
    out.push_str("::*;\n\n");

    // Fuzz test struct
    out.push_str("#[derive(FuzzTest)]\n");
    out.push_str("struct Fuzz");
    out.push_str(&to_pascal_case(&report.profile.program_name));
    out.push_str(" {\n");
    out.push_str("    // Program under test\n");
    out.push_str("    program: ProgramContext,\n");
    out.push_str("    // Admin authority\n");
    out.push_str("    admin: Keypair,\n");
    out.push_str("    // User accounts for adversarial testing\n");
    out.push_str("    attacker: Keypair,\n");
    out.push_str("}\n\n");

    // Implementation
    out.push_str("impl Fuzz");
    out.push_str(&to_pascal_case(&report.profile.program_name));
    out.push_str(" {\n");

    // Setup
    out.push_str("    pub fn deploy() -> Self {\n");
    out.push_str("        let mut program = ProgramContext::new();\n");
    out.push_str("        let admin = program.create_keypair();\n");
    out.push_str("        let attacker = program.create_keypair();\n");
    out.push_str("        Self { program, admin, attacker }\n");
    out.push_str("    }\n\n");

    out.push_str("    #[invariant_test]\n");
    out.push_str("    fn invariant_signer_check(&self) -> Result<()> {\n");
    out.push_str("        // Fails if any instruction can be called without required signer\n");
    out.push_str("        Ok(())\n");
    out.push_str("    }\n\n");

    out.push_str("    #[invariant_test]\n");
    out.push_str("    fn invariant_no_overflow(&self) -> Result<()> {\n");
    out.push_str("        // Fails if arithmetic operations can overflow\n");
    out.push_str("        Ok(())\n");
    out.push_str("    }\n\n");

    out.push_str("    #[invariant_test]\n");
    out.push_str("    fn invariant_no_double_withdrawal(&self) -> Result<()> {\n");
    out.push_str("        // Fails if total withdrawals exceed deposits\n");
    out.push_str("        Ok(())\n");
    out.push_str("    }\n\n");

    // Generate adversarial instruction sequences for critical findings
    let critical: Vec<&Finding> = report.findings.iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .collect();

    if !critical.is_empty() {
        out.push_str("    // --- Exploit sequences generated from findings ---\n");
        for (i, finding) in critical.iter().enumerate().take(5) {
            out.push_str("    #[fuzz_test(\"exploit_");
            out.push_str(&i.to_string());
            out.push_str("\")]\n");
            out.push_str("    fn exploit_");
            out.push_str(&i.to_string());
            out.push_str("(&self, client: &mut Client) -> Result<()> {\n");
            out.push_str("        // Finding: ");
            out.push_str(&finding.title.replace('"', "'"));
            out.push_str("\n");
            out.push_str("        // Category: ");
            out.push_str(finding.category.key());
            out.push_str("\n");
            out.push_str("        // CWE: ");
            out.push_str(&finding.cwe);
            out.push_str("\n");
            out.push_str("        // Severity: ");
            out.push_str(finding.severity.as_str());
            out.push_str("\n");
            out.push_str("        // Try to exploit: ");
            out.push_str(&finding.description[..finding.description.len().min(200)]);
            out.push_str("\n");
            out.push_str("        // TODO: implement adversarial transaction\n");
            out.push_str("        Ok(())\n");
            out.push_str("    }\n\n");
        }
    }

    out.push_str("}\n\n");

    // Fuzz test entry
    out.push_str("fn fuzz_test() {\n");
    out.push_str("    let test = Fuzz");
    out.push_str(&to_pascal_case(&report.profile.program_name));
    out.push_str("::deploy();\n");
    out.push_str("    let mut client = Client::new(test.program.clone());\n");
    out.push_str("    fuzz_trident!(test, client);\n");
    out.push_str("}\n");

    out
}

/// Generate a LiteSVM Rust integration test for findings
pub fn generate_litesvm_test(report: &AnalysisReport) -> String {
    let mut out = String::new();

    let program_rs = report.profile.program_name.replace('-', "_");

    out.push_str("// Auto-generated LiteSVM integration test by ChainProbe\n");
    out.push_str("// Run: cargo test --test ");
    out.push_str(&program_rs);
    out.push_str("_security\n\n");

    out.push_str("use litesvm::LiteSVM;\n");
    out.push_str("use solana_sdk::{\n");
    out.push_str("    instruction::{AccountMeta, Instruction},\n");
    out.push_str("    pubkey::Pubkey,\n");
    out.push_str("    signature::{Keypair, Signer},\n");
    out.push_str("    transaction::Transaction,\n");
    out.push_str("};\n");
    out.push_str("use std::str::FromStr;\n\n");

    out.push_str("#[test]\n");
    out.push_str("fn test_security_harness() {\n");
    out.push_str("    let mut svm = LiteSVM::new();\n");
    out.push_str("    let payer = Keypair::new();\n");
    out.push_str("    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();\n\n");

    out.push_str("    // Deploy program\n");
    out.push_str("    let program_id = Pubkey::from_str(\"");
    out.push_str(&program_id_placeholder(&report.profile.program_name));
    out.push_str("\").unwrap();\n");
    out.push_str("    let program_data = std::fs::read(\"target/deploy/");
    out.push_str(&program_rs);
    out.push_str(".so\").unwrap();\n");
    out.push_str("    svm.deploy_program(program_id, &program_data).unwrap();\n\n");

    // Generate test cases from findings
    let critical: Vec<&Finding> = report.findings.iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .collect();

    if critical.is_empty() {
        out.push_str("    // No critical findings — basic smoke test\n");
        out.push_str("    assert!(true);\n");
    } else {
        for (i, finding) in critical.iter().enumerate().take(8) {
            out.push_str("    // Finding ");
            out.push_str(&i.to_string());
            out.push_str(": ");
            out.push_str(&finding.title.replace('"', "'"));
            out.push_str("\n");
            out.push_str("    // Severity: ");
            out.push_str(finding.severity.as_str());
            out.push_str(" | Category: ");
            out.push_str(finding.category.key());
            out.push_str("\n");
            out.push_str("    // File: ");
            out.push_str(&finding.file);
            out.push_str(":");
            if let Some(line) = finding.line { out.push_str(&line.to_string()); }
            out.push_str("\n");
            out.push_str("    // TODO: implement adversarial transaction for this finding\n");
            out.push_str("    // let tx = Transaction::new_signed_with_payer(...);\n");
            out.push_str("    // let result = svm.send_transaction(tx);\n");
            out.push_str("    // assert!(result.is_err(), \"Expected transaction to fail\");\n\n");
        }
    }

    out.push_str("}\n");
    out
}

/// Generate a Python/solana-py test script for rapid prototyping
pub fn generate_python_test(report: &AnalysisReport) -> String {
    let mut out = String::new();

    out.push_str("# Auto-generated adversarial test by ChainProbe\n");
    out.push_str("# pip install solana solders\n\n");

    out.push_str("from solana.rpc.api import Client\n");
    out.push_str("from solana.transaction import Transaction\n");
    out.push_str("from solders.pubkey import Pubkey\n");
    out.push_str("from solders.keypair import Keypair\n");
    out.push_str("from solders.instruction import AccountMeta, Instruction\n\n");

    out.push_str("client = Client(\"https://api.devnet.solana.com\")\n\n");

    let critical: Vec<&Finding> = report.findings.iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .collect();

    if critical.is_empty() {
        out.push_str("# No critical/high findings in this program\n");
    } else {
        out.push_str("# === Exploit attempts ===\n");
        for (i, finding) in critical.iter().enumerate().take(5) {
            out.push_str("# Exploit ");
            out.push_str(&i.to_string());
            out.push_str(": ");
            out.push_str(&finding.title.replace('\n', " "));
            out.push_str("\n");
            out.push_str("# ");
            out.push_str(finding.severity.as_str());
            out.push_str(" | ");
            out.push_str(finding.category.key());
            out.push_str("\n");
            out.push_str("# TODO: implement\n");
            out.push_str("def exploit_");
            out.push_str(&i.to_string());
            out.push_str("():\n");
            out.push_str("    pass\n\n");
        }

        out.push_str("if __name__ == \"__main__\":\n");
        out.push_str("    exploits = [");

        let exploit_count = critical.len().min(5);
        let exploit_refs: Vec<String> = (0..exploit_count)
            .map(|i| format!("exploit_{}", i))
            .collect();
        out.push_str(&exploit_refs.join(", "));
        out.push_str("]\n");
        out.push_str("    for i, exploit_fn in enumerate(exploits):\n");
        out.push_str("        print(f\"Testing exploit {i}...\")\n");
        out.push_str("        exploit_fn()\n");
    }

    out
}

// Helpers

fn to_pascal_case(s: &str) -> String {
    s.split(&['-', '_', ' '][..])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().chain(c).collect(),
            }
        })
        .collect()
}

fn program_id_placeholder(name: &str) -> String {
    format!("{}1111111111111111111111111111111111111", name.chars().next().unwrap_or('P'))
}
