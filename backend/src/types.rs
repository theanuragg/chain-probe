// backend/src/types.rs — v4
// All shared types. Every new type added in v4 is marked NEW.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

//   Request                                  ─

#[derive(Deserialize, Debug)]
pub struct AnalyzeRequest {
    pub files: Vec<InputFile>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct InputFile {
    pub path: String,
    pub content: String,
}

//   Severity                                  

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical, High, Medium, Low, Info,
}

impl Severity {
    pub fn score_penalty(&self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High     => 12,
            Severity::Medium   => 5,
            Severity::Low      => 2,
            Severity::Info     => 0,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Some(Severity::Critical),
            "HIGH"     => Some(Severity::High),
            "MEDIUM"   => Some(Severity::Medium),
            "LOW"      => Some(Severity::Low),
            "INFO"     => Some(Severity::Info),
            _          => None,
        }
    }
}

//   Category                                  

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AccountValidation, ArithmeticOverflow, SignerAuthority,
    PdaSeedCollision, Reentrancy, AccessControl,
    TokenSafety, CpiValidation, RentExemption,
    SysvarUsage, BumpCanonical, InitSafety,
    CloseAuthority, MintAuth, ProgramId,
    MultipleMint, UncheckedParams, FreezeAuth,
    UpdateAuthority, DelegateUsage, TransferHook,
    MetadataUpdate, ScopeValidation, ExecutableAccounts,
    MintConfusion, OwnerConfusion, LamportFlaw,
    AccountRevival, ArbitraryCpi, DataMismatch,
    AccountDataMatch,
    IntegerTruncation, PriceOracle, OracleManip,
    UpgradeAuthority, TreasuryDrain, Liquidation,
    YieldDrain, RateManip, FlashLoan, CrossProgram,
    WormholeStyle, SysvarSpoof, TokenFreeze,
    StakingDrain, DelegationEscrow, ValidatorBribe,
}

impl Category {
    pub fn key(&self) -> &'static str {
        match self {
            Category::AccountValidation  => "account_validation",
            Category::ArithmeticOverflow => "arithmetic_overflow",
            Category::SignerAuthority    => "signer_authority",
            Category::PdaSeedCollision   => "pda_seed_collision",
            Category::Reentrancy         => "reentrancy",
            Category::AccessControl      => "access_control",
            Category::TokenSafety       => "token_safety",
            Category::CpiValidation   => "cpi_validation",
            Category::RentExemption  => "rent_exemption",
            Category::SysvarUsage    => "sysvar_usage",
            Category::BumpCanonical   => "bump_canonical",
            Category::InitSafety     => "init_safety",
            Category::CloseAuthority => "close_authority",
            Category::MintAuth       => "mint_auth",
            Category::ProgramId      => "program_id",
            Category::MultipleMint  => "multiple_mint",
            Category::UncheckedParams => "unchecked_params",
            Category::FreezeAuth    => "freeze_auth",
            Category::UpdateAuthority => "update_authority",
            Category::DelegateUsage => "delegate_usage",
            Category::TransferHook => "transfer_hook",
            Category::MetadataUpdate => "metadata_update",
            Category::ScopeValidation => "scope_validation",
            Category::ExecutableAccounts => "executable_accounts",
            Category::MintConfusion => "mint_confusion",
            Category::OwnerConfusion => "owner_confusion",
            Category::LamportFlaw => "lamport_flaw",
            Category::AccountRevival => "account_revival",
            Category::ArbitraryCpi => "arbitrary_cpi",
            Category::DataMismatch => "data_mismatch",
            Category::AccountDataMatch => "account_data_match",
            Category::IntegerTruncation => "integer_truncation",
            Category::PriceOracle => "price_oracle",
            Category::OracleManip => "oracle_manipulation",
            Category::UpgradeAuthority => "upgrade_authority",
            Category::TreasuryDrain => "treasury_drain",
            Category::Liquidation => "liquidation",
            Category::YieldDrain => "yield_drain",
            Category::RateManip => "rate_manipulation",
            Category::FlashLoan => "flash_loan",
            Category::CrossProgram => "cross_program_attack",
            Category::WormholeStyle => "wormhole_style",
            Category::SysvarSpoof => "sysvar_spoofing",
            Category::TokenFreeze => "token_freeze_bypass",
            Category::StakingDrain => "staking_drain",
            Category::DelegationEscrow => "delegation_escrow",
            Category::ValidatorBribe => "validator_bribe",
        }
    }
}

//   AccountTrust                                

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountTrust {
    ProgramControlled,
    SignerRequired,
    IndirectlyVerified,
    UserSuppliedVerified,
    UserSuppliedUnverified,
}

impl AccountTrust {
    pub fn risk_score(&self) -> u8 {
        match self {
            AccountTrust::ProgramControlled      => 0,
            AccountTrust::SignerRequired          => 1,
            AccountTrust::IndirectlyVerified      => 2,
            AccountTrust::UserSuppliedVerified    => 3,
            AccountTrust::UserSuppliedUnverified  => 10,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            AccountTrust::ProgramControlled      => "program-controlled",
            AccountTrust::SignerRequired          => "signer-required",
            AccountTrust::IndirectlyVerified      => "indirectly-verified",
            AccountTrust::UserSuppliedVerified    => "user-supplied-verified",
            AccountTrust::UserSuppliedUnverified  => "user-supplied-unverified",
        }
    }
}

//   Data flow (from v3)                            ─

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FlowLinkType {
    PdaSeeds, HasOne, StoredPubkey, TypeMatch,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataFlowEdge {
    pub from_instruction: String,
    pub to_instruction: String,
    pub account_name: String,
    pub link_type: FlowLinkType,
    pub trust_at_destination: AccountTrust,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharedAccount {
    pub account_name: String,
    pub account_type: String,
    pub used_in: Vec<String>,
    pub max_trust_risk: AccountTrust,
    pub trust_inconsistent: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataFlowGraph {
    pub edges: Vec<DataFlowEdge>,
    pub trust_map: HashMap<String, HashMap<String, AccountTrust>>,
    pub shared_accounts: Vec<SharedAccount>,
}

//   Taint analysis — NEW in v4                         

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaintSource {
    pub taint_type: String,     // "instruction_param" | "unverified_account" | "tainted_state"
    pub name: String,
    pub file: String,
    pub line: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaintSink {
    pub sink_type: String,      // "token_transfer_amount" | "require_condition" | etc.
    pub description: String,
    pub file: String,
    pub line: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaintHop {
    pub operation: String,      // "assignment" | "arithmetic" | "state_write" | "sink_reached"
    pub description: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

/// A confirmed taint flow: attacker-controlled value reaches a security sink
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaintFlow {
    pub id: String,
    pub instruction: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintHop>,
    pub severity: Severity,
    /// Links to a finding if this confirms or escalates one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
}

//   Invariant mining — NEW in v4                        

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    Holds,          // No bypass path found
    Bypassable,     // Taint reaches the condition — can be violated
    Incomplete,     // Not enforced in all instructions that write the same state
    OrderingRisk,   // Can be bypassed by calling another instruction first
}

/// A program invariant derived from a require!() call
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramInvariant {
    pub id: String,
    pub condition: String,
    pub instruction: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    pub protects: String,
    pub status: InvariantStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_path: Option<String>,
    pub taint_confirmed: bool,
}

//   Call graph — NEW in v4                           

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExploitComplexity {
    Trivial,    // Single tx, no setup
    Low,        // Simple setup
    Medium,     // Multiple txs, some prep
    High,       // Requires deployed program or special conditions
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttackerFootprint {
    pub required_keypairs: u8,
    pub required_sol: f64,
    pub on_chain_setup: bool,
    pub complexity: ExploitComplexity,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallGraphNode {
    pub id: String,
    pub node_type: String,      // "instruction" | "cpi_target"
    pub name: String,
    pub file: String,
    pub line: usize,
    pub attack_surface_score: u32,
    pub attacker_footprint: AttackerFootprint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CpiAccountBinding {
    pub parameter_name: String,
    pub account_name: String,
    pub trust: AccountTrust,
    pub is_writable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallGraphEdge {
    pub from: String,
    pub to: String,
    pub accounts_passed: Vec<CpiAccountBinding>,
    pub uses_pda_signer: bool,
    pub cpi_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

//   Scoring — NEW in v4                            ─

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramScores {
    pub security_score: u32,
    pub attack_surface_score: u32,
    pub hardening_score: u32,
    pub overall_risk: String,
}

//   Vulnerability chains (from v3)                       

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnChain {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub finding_ids: Vec<String>,
    pub description: String,
    pub exploit_steps: Vec<String>,
    pub instructions_involved: Vec<String>,
    pub needs_ai_context: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_explanation: Option<String>,
}

//   Known advisories (from v3)                         

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KnownVuln {
    pub cve_id: Option<String>,
    pub advisory_id: String,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_in: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub url: String,
}

//   Finding                                  ─

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub file: String,
    pub line: Option<usize>,
    pub function: String,
    pub snippet: String,
    pub description: String,
    pub recommendation: String,
    pub anchor_fix: String,
    pub cwe: String,
    pub needs_ai_context: bool,
    /// Exploitability 0–100 — higher = easier to exploit
    pub exploitability: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_explanation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_severity: Option<Severity>,
    /// Taint flow IDs that confirm this finding
    pub confirmed_by_taint: Vec<String>,
}

//   Profile                                  ─

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstructionInfo {
    pub name: String,
    pub file: String,
    pub line: usize,
    pub params: Vec<String>,
    pub ctx_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountField {
    pub name: String,
    pub field_type: String,
    pub constraints: Vec<String>,
    pub is_signer: bool,
    pub is_mut: bool,
    pub has_has_one: bool,
    pub has_constraint: bool,
    pub seeds: Vec<String>,
    pub bump_stored: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountStructInfo {
    pub name: String,
    pub file: String,
    pub line: usize,
    pub fields: Vec<AccountField>,
    pub has_signer: bool,
    pub has_pda: bool,
    pub has_init: bool,
    pub has_close: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CpiCallInfo {
    pub file: String,
    pub line: usize,
    pub function_name: String,
    pub program: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PdaInfo {
    pub file: String,
    pub line: usize,
    pub account_name: String,
    pub seeds: Vec<String>,
    pub bump_stored: bool,
    pub canonical_bump: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArithmeticOp {
    pub file: String,
    pub line: usize,
    pub op: String,
    pub in_function: String,
    pub uses_checked: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProgramProfile {
    pub program_name: String,
    pub anchor_version: String,
    pub files_analyzed: usize,
    pub total_lines: usize,
    pub rs_lines: usize,
    pub instructions: Vec<InstructionInfo>,
    pub instructions_count: usize,
    pub account_structs: Vec<AccountStructInfo>,
    pub account_structs_count: usize,
    pub state_accounts: Vec<String>,
    pub state_accounts_count: usize,
    pub cpi_calls: Vec<CpiCallInfo>,
    pub cpi_calls_count: usize,
    pub pda_derivations: Vec<PdaInfo>,
    pub pda_count: usize,
    pub signer_count: usize,
    pub estimated_compute_units: u64,
    pub complexity: String,
    pub uses_token_program: bool,
    pub uses_token_2022: bool,
    pub uses_init_if_needed: bool,
    pub overflow_checks_enabled: bool,
    pub framework_patterns: Vec<String>,
    pub module_tree: Vec<String>,
    pub dependency_count: usize,
}

//   Summary                                  ─

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CategorySummary {
    pub count: usize,
    pub max_severity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReportSummary {
    pub overall_risk: String,
    pub security_score: u32,
    pub attack_surface_score: u32,
    pub hardening_score: u32,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
    pub chain_count: usize,
    pub taint_flow_count: usize,
    pub invariant_count: usize,
    pub bypassable_invariant_count: usize,
    pub known_vuln_count: usize,
    pub token_flow_anomaly_count: usize,
    pub broken_permission_count: usize,
}

//   AI enrichment                               ─

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CrossFileFlow {
    pub from_file: String,
    pub to_file: String,
    pub via: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AiContext {
    pub findings_needing_ai: Vec<String>,
    pub chain_ids_needing_ai: Vec<String>,
    pub cross_file_flows: Vec<CrossFileFlow>,
    pub business_logic_notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_bundle: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AiFindingEnrichment {
    pub id: String,
    pub explanation: String,
    pub severity_override: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct AiChainEnrichment {
    pub id: String,
    pub explanation: String,
    pub realistic: bool,
}

#[derive(Deserialize, Debug)]
pub struct AiEnrichmentResponse {
    pub findings: Vec<AiFindingEnrichment>,
    pub chains: Vec<AiChainEnrichment>,
    pub program_notes: Vec<String>,
}

//   Token Flow Graph — NEW                           

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenFlowNode {
    pub id: String,
    pub account_name: String,
    pub role: String,            // "vault" | "ata" | "reserve" | "fee_account" | ...
    pub trust: AccountTrust,
    pub is_pda: bool,
    pub mint: Option<String>,
    pub instructions_used_in: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TokenMovementType {
    Deposit,
    Withdrawal,
    Swap,
    InternalTransfer,
    FeeCollection,
    AccountClose,
    Mint,
    Burn,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenAuthCondition {
    pub requires_signer: bool,
    pub signer_name: Option<String>,
    pub requires_pda: bool,
    pub pda_seeds: Vec<String>,
    pub constraint_text: String,
    pub trust_level: AccountTrust,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenFlowEdge {
    pub id: String,
    pub from_account: String,
    pub to_account: String,
    pub movement_type: TokenMovementType,
    pub instruction: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    pub authorization: TokenAuthCondition,
    pub amount_source: String,
    pub preconditions: Vec<String>,
    pub is_guarded: bool,
    pub uses_pda_signer: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenFlowAnomaly {
    pub id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub edge_ids: Vec<String>,
    pub recommendation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenFlowGraph {
    pub nodes: Vec<TokenFlowNode>,
    pub edges: Vec<TokenFlowEdge>,
    pub anomalies: Vec<TokenFlowAnomaly>,
}

//   Permission Model — NEW                           

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    /// Correctly enforced with proper signature + binding
    Allowed,
    /// Code has checks but they don't actually enforce the intended restriction
    IntendedButBroken,
    /// No access control at all — anyone can perform this operation
    Missing,
    /// Read-only operation — no restriction needed
    ReadOnly,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
    Admin,        // Stored admin authority with signature required
    AnySigner,    // Any keypair that signs — no binding to stored authority
    ProgramPDA,   // Program-controlled via PDA seeds
    StoredKey,    // Key equality enforced but no signature — BROKEN
    Anyone,       // Completely open — no restriction
    Unknown,      // Could not determine
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedOp {
    ModifyConfig,
    DrainVault,
    TransferTokens,
    CloseAccount,
    MintTokens,
    Initialize,
    ProgramUpgrade,
    ReadOnly,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PermissionEntry {
    pub id: String,
    pub instruction: String,
    pub operation: PrivilegedOp,
    pub principal: Principal,
    pub status: PermissionStatus,
    pub evidence: String,
    pub gap: Option<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PermissionMatrix {
    pub entries: Vec<PermissionEntry>,
    pub broken_permission_count: usize,
}

//   Final report                                

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisReport {
    pub id: String,
    pub findings: Vec<Finding>,
    pub category_summary: HashMap<String, CategorySummary>,
    pub profile: ProgramProfile,
    pub summary: ReportSummary,
    pub analyzed_at: DateTime<Utc>,
    // v3
    pub data_flow: DataFlowGraph,
    pub vuln_chains: Vec<VulnChain>,
    pub known_vulns: Vec<KnownVuln>,
    // v4
    pub taint_flows: Vec<TaintFlow>,
    pub invariants: Vec<ProgramInvariant>,
    pub call_graph: CallGraph,
    // v4 new features
    pub token_flow: TokenFlowGraph,
    pub permission_matrix: PermissionMatrix,
}
