// frontend/src/types/index.ts — v4

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Category =
  | 'account_validation' | 'arithmetic_overflow' | 'signer_authority'
  | 'pda_seed_collision' | 'reentrancy' | 'access_control';
export type AccountTrust =
  | 'program_controlled' | 'signer_required' | 'indirectly_verified'
  | 'user_supplied_verified' | 'user_supplied_unverified';
export type InvariantStatus = 'holds' | 'bypassable' | 'incomplete' | 'ordering_risk';
export type ExploitComplexity = 'trivial' | 'low' | 'medium' | 'high';
export type FlowLinkType = 'pda_seeds' | 'has_one' | 'stored_pubkey' | 'type_match';

//   Lookup maps                                ─

export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#FF3D5C', HIGH: '#FFAA33', MEDIUM: '#3D8EFF', LOW: '#00D98A', INFO: '#9D7AFF',
};
export const SEV_BG: Record<Severity, string> = {
  CRITICAL: 'rgba(255,61,92,.12)', HIGH: 'rgba(255,170,51,.12)',
  MEDIUM: 'rgba(61,142,255,.12)', LOW: 'rgba(0,217,138,.12)', INFO: 'rgba(157,122,255,.12)',
};
export const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};
export const CATEGORY_LABELS: Record<Category, string> = {
  account_validation: 'Account Validation',
  arithmetic_overflow: 'Arithmetic Overflow',
  signer_authority: 'Signer Authority',
  pda_seed_collision: 'PDA Seed Collision',
  reentrancy: 'Reentrancy',
  access_control: 'Access Control',
};
export const TRUST_COLOR: Record<AccountTrust, string> = {
  program_controlled:      '#00D98A',
  signer_required:         '#3D8EFF',
  indirectly_verified:     '#9D7AFF',
  user_supplied_verified:  '#FFAA33',
  user_supplied_unverified:'#FF3D5C',
};
export const TRUST_LABEL: Record<AccountTrust, string> = {
  program_controlled:      'Program-controlled',
  signer_required:         'Signer required',
  indirectly_verified:     'Indirectly verified',
  user_supplied_verified:  'User-supplied (verified)',
  user_supplied_unverified:'User-supplied (UNVERIFIED)',
};
export const TRUST_RISK: Record<AccountTrust, number> = {
  program_controlled: 0, signer_required: 1, indirectly_verified: 2,
  user_supplied_verified: 3, user_supplied_unverified: 10,
};
export const INVARIANT_COLOR: Record<InvariantStatus, string> = {
  holds: '#00D98A', bypassable: '#FF3D5C', incomplete: '#FFAA33', ordering_risk: '#9D7AFF',
};
export const INVARIANT_LABEL: Record<InvariantStatus, string> = {
  holds: 'Holds', bypassable: 'Bypassable', incomplete: 'Incomplete', ordering_risk: 'Ordering risk',
};
export const COMPLEXITY_LABEL: Record<ExploitComplexity, string> = {
  trivial: 'Trivial', low: 'Low', medium: 'Medium', high: 'High',
};
export const LINK_TYPE_LABEL: Record<FlowLinkType, string> = {
  pda_seeds: 'PDA seeds', has_one: 'has_one', stored_pubkey: 'Stored pubkey', type_match: 'Type match',
};

//   Finding                                  ─

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  title: string;
  file: string;
  line: number | null;
  function: string;
  snippet: string;
  description: string;
  recommendation: string;
  anchor_fix: string;
  cwe: string;
  needs_ai_context: boolean;
  exploitability: number;
  confirmed_by_taint: string[];
  ai_explanation?: string;
  ai_severity?: Severity;
}

//   Taint                                   ─

export interface TaintSource {
  taint_type: string;
  name: string;
  file: string;
  line: number;
}
export interface TaintSink {
  sink_type: string;
  description: string;
  file: string;
  line: number;
}
export interface TaintHop {
  operation: string;
  description: string;
  file: string;
  line: number;
  snippet: string;
}
export interface TaintFlow {
  id: string;
  instruction: string;
  source: TaintSource;
  sink: TaintSink;
  path: TaintHop[];
  severity: Severity;
  finding_id?: string;
}

//   Invariants                                 

export interface ProgramInvariant {
  id: string;
  condition: string;
  instruction: string;
  file: string;
  line: number;
  snippet: string;
  protects: string;
  status: InvariantStatus;
  bypass_path?: string;
  taint_confirmed: boolean;
}

//   Call graph                                 

export interface AttackerFootprint {
  required_keypairs: number;
  required_sol: number;
  on_chain_setup: boolean;
  complexity: ExploitComplexity;
}
export interface CallGraphNode {
  id: string;
  node_type: string;
  name: string;
  file: string;
  line: number;
  attack_surface_score: number;
  attacker_footprint: AttackerFootprint;
}
export interface CpiAccountBinding {
  parameter_name: string;
  account_name: string;
  trust: AccountTrust;
  is_writable: boolean;
}
export interface CallGraphEdge {
  from: string;
  to: string;
  accounts_passed: CpiAccountBinding[];
  uses_pda_signer: boolean;
  cpi_type: string;
}
export interface CallGraph {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

//   Data flow                                 ─

export interface DataFlowEdge {
  from_instruction: string;
  to_instruction: string;
  account_name: string;
  link_type: FlowLinkType;
  trust_at_destination: AccountTrust;
}
export interface SharedAccount {
  account_name: string;
  account_type: string;
  used_in: string[];
  max_trust_risk: AccountTrust;
  trust_inconsistent: boolean;
}
export interface DataFlowGraph {
  edges: DataFlowEdge[];
  trust_map: Record<string, Record<string, AccountTrust>>;
  shared_accounts: SharedAccount[];
}

//   Chains                                   

export interface VulnChain {
  id: string;
  severity: Severity;
  title: string;
  finding_ids: string[];
  description: string;
  exploit_steps: string[];
  instructions_involved: string[];
  needs_ai_context: boolean;
  ai_explanation?: string;
}

//   Known vulns                                ─

export interface KnownVuln {
  cve_id: string | null;
  advisory_id: string;
  affected_package: string;
  affected_versions: string;
  fixed_in: string | null;
  severity: Severity;
  title: string;
  description: string;
  url: string;
}

//   Profile                                  ─

export interface InstructionInfo {
  name: string; file: string; line: number; params: string[]; ctx_type: string;
}
export interface AccountField {
  name: string; field_type: string; constraints: string[];
  is_signer: boolean; is_mut: boolean; has_has_one: boolean;
  has_constraint: boolean; seeds: string[]; bump_stored: boolean;
}
export interface AccountStructInfo {
  name: string; file: string; line: number; fields: AccountField[];
  has_signer: boolean; has_pda: boolean; has_init: boolean; has_close: boolean;
}
export interface ProgramProfile {
  program_name: string;
  anchor_version: string;
  files_analyzed: number;
  total_lines: number;
  rs_lines: number;
  instructions: InstructionInfo[];
  instructions_count: number;
  account_structs: AccountStructInfo[];
  account_structs_count: number;
  state_accounts: string[];
  state_accounts_count: number;
  cpi_calls_count: number;
  pda_count: number;
  signer_count: number;
  estimated_compute_units: number;
  complexity: string;
  uses_token_program: boolean;
  uses_token_2022: boolean;
  uses_init_if_needed: boolean;
  overflow_checks_enabled: boolean;
  framework_patterns: string[];
  module_tree: string[];
}

//   Summary                                  ─

export interface CategorySummary {
  count: number;
  max_severity: string;
}
export interface ReportSummary {
  overall_risk: string;
  security_score: number;
  attack_surface_score: number;
  hardening_score: number;
  critical: number; high: number; medium: number; low: number; info: number;
  total: number;
  chain_count: number;
  taint_flow_count: number;
  invariant_count: number;
  bypassable_invariant_count: number;
  known_vuln_count: number;
  token_flow_anomaly_count: number;
  broken_permission_count: number;
}

//   Token flow display maps                          ─

export const MOVEMENT_LABEL: Record<TokenMovementType, string> = {
  deposit:          'Deposit',
  withdrawal:       'Withdrawal',
  swap:             'Swap',
  internal_transfer:'Internal Transfer',
  fee_collection:   'Fee Collection',
  account_close:    'Close',
  mint:             'Mint',
  burn:             'Burn',
};
export const MOVEMENT_COLOR: Record<TokenMovementType, string> = {
  deposit:          '#3D8EFF',
  withdrawal:       '#FF3D5C',
  swap:             '#9D7AFF',
  internal_transfer:'#7A8599',
  fee_collection:   '#FFAA33',
  account_close:    '#FF7A5A',
  mint:             '#FF3D5C',
  burn:             '#3D4A5C',
};

export const PERMISSION_STATUS_COLOR: Record<PermissionStatus, string> = {
  allowed:             '#00D98A',
  intended_but_broken: '#FFAA33',
  missing:             '#FF3D5C',
  read_only:           '#3D4A5C',
};
export const PERMISSION_STATUS_LABEL: Record<PermissionStatus, string> = {
  allowed:             'Allowed',
  intended_but_broken: 'Broken',
  missing:             'Missing',
  read_only:           'Read-only',
};
export const PRINCIPAL_LABEL: Record<Principal, string> = {
  admin:       'Admin (signed + bound)',
  any_signer:  'Any signer',
  program_pda: 'Program PDA',
  stored_key:  'Stored key (no sig)',
  anyone:      'Anyone',
  unknown:     'Unknown',
};
export const PRINCIPAL_COLOR: Record<Principal, string> = {
  admin:       '#00D98A',
  any_signer:  '#FFAA33',
  program_pda: '#3D8EFF',
  stored_key:  '#FF7A5A',
  anyone:      '#FF3D5C',
  unknown:     '#3D4A5C',
};
export const PRIVILEGED_OP_LABEL: Record<PrivilegedOp, string> = {
  modify_config:  'Modify Config',
  drain_vault:    'Drain Vault',
  transfer_tokens:'Transfer Tokens',
  close_account:  'Close Account',
  mint_tokens:    'Mint Tokens',
  initialize:     'Initialize',
  program_upgrade:'Program Upgrade',
  read_only:      'Read Only',
};

//   Token Flow Graph                              

export type TokenMovementType =
  | 'deposit' | 'withdrawal' | 'swap' | 'internal_transfer'
  | 'fee_collection' | 'account_close' | 'mint' | 'burn';

export interface TokenAuthCondition {
  requires_signer: boolean;
  signer_name: string | null;
  requires_pda: boolean;
  pda_seeds: string[];
  constraint_text: string;
  trust_level: AccountTrust;
}

export interface TokenFlowNode {
  id: string;
  account_name: string;
  role: string;
  trust: AccountTrust;
  is_pda: boolean;
  mint: string | null;
  instructions_used_in: string[];
}

export interface TokenFlowEdge {
  id: string;
  from_account: string;
  to_account: string;
  movement_type: TokenMovementType;
  instruction: string;
  file: string;
  line: number;
  snippet: string;
  authorization: TokenAuthCondition;
  amount_source: string;
  preconditions: string[];
  is_guarded: boolean;
  uses_pda_signer: boolean;
}

export interface TokenFlowAnomaly {
  id: string;
  anomaly_type: string;
  severity: string;
  description: string;
  edge_ids: string[];
  recommendation: string;
}

export interface TokenFlowGraph {
  nodes: TokenFlowNode[];
  edges: TokenFlowEdge[];
  anomalies: TokenFlowAnomaly[];
}

//   Permission Model                              

export type PermissionStatus =
  | 'allowed' | 'intended_but_broken' | 'missing' | 'read_only';

export type Principal =
  | 'admin' | 'any_signer' | 'program_pda' | 'stored_key' | 'anyone' | 'unknown';

export type PrivilegedOp =
  | 'modify_config' | 'drain_vault' | 'transfer_tokens' | 'close_account'
  | 'mint_tokens' | 'initialize' | 'program_upgrade' | 'read_only';

export interface PermissionEntry {
  id: string;
  instruction: string;
  operation: PrivilegedOp;
  principal: Principal;
  status: PermissionStatus;
  evidence: string;
  gap: string | null;
  file: string;
  line: number;
}

export interface PermissionMatrix {
  entries: PermissionEntry[];
  broken_permission_count: number;
}

//   Full report                                ─

export interface AnalysisReport {
  id: string;
  findings: Finding[];
  category_summary: Record<string, CategorySummary>;
  profile: ProgramProfile;
  summary: ReportSummary;
  analyzed_at: string;
  data_flow: DataFlowGraph;
  vuln_chains: VulnChain[];
  known_vulns: KnownVuln[];
  taint_flows: TaintFlow[];
  invariants: ProgramInvariant[];
  call_graph: CallGraph;
  token_flow: TokenFlowGraph;
  permission_matrix: PermissionMatrix;
}

//   Input file utils                              

export interface InputFile { path: string; content: string; }

const BLOCKED = new Set(['node_modules','target','.git','.github','.anchor',
  'migrations','dist','build','.cargo','__pycache__']);
const BLOCKED_FILES = new Set(['Cargo.lock','yarn.lock','package-lock.json',
  'pnpm-lock.yaml','.DS_Store','idl.json']);

export function shouldKeep(path: string): boolean {
  const parts = path.replace(/\\/g,'/').split('/');
  const name = parts[parts.length-1];
  if (BLOCKED_FILES.has(name) || name.startsWith('.')) return false;
  for (const seg of parts.slice(0,-1)) {
    if (BLOCKED.has(seg) || seg.startsWith('.')) return false;
  }
  const ext = name.includes('.') ? name.split('.').pop()!.toLowerCase() : '';
  return ext === 'rs' || ext === 'toml';
}
export function filePriority(p: string): number {
  if (p.endsWith('lib.rs')) return 0;
  if (p.includes('instructions')) return 1;
  if (p.includes('state')) return 2;
  if (p.includes('errors')) return 3;
  if (p.endsWith('.toml')) return 4;
  return 5;
}

//   Diff report                                ─

export type DiffChange = 'fixed' | 'new' | 'regressed' | 'improved' | 'unchanged';
export type DiffVerdict = 'improved' | 'neutral' | 'regressed' | 'critical_regression';

export interface DiffFinding {
  id: string;
  title: string;
  category: string;
  function: string;
  file: string;
  severity_before: string | null;
  severity_after: string | null;
  change: DiffChange;
}

export interface DiffChain {
  id: string;
  title: string;
  severity: string;
}

export interface DiffInvariant {
  id: string;
  condition: string;
  instruction: string;
  status: string;
}

export interface DiffAnomaly {
  id: string;
  anomaly_type: string;
  severity: string;
  description: string;
}

export interface DiffPermission {
  id: string;
  instruction: string;
  operation: string;
  status: string;
  evidence: string;
}

export interface DiffSummary {
  total_fixed: number;
  total_new: number;
  total_regressed: number;
  total_improved: number;
  net_change: number;
  verdict: DiffVerdict;
  verdict_reason: string;
}

export interface DiffReport {
  baseline_id: string;
  current_id: string;
  baseline_program: string;
  current_program: string;
  score_before: number;
  score_after: number;
  score_delta: number;
  risk_before: string;
  risk_after: string;
  findings_fixed: DiffFinding[];
  findings_new: DiffFinding[];
  findings_regressed: DiffFinding[];
  findings_improved: DiffFinding[];
  findings_unchanged: number;
  chains_resolved: string[];
  chains_new: DiffChain[];
  invariants_fixed: string[];
  invariants_newly_bypassable: DiffInvariant[];
  anomalies_resolved: string[];
  anomalies_new: DiffAnomaly[];
  permissions_fixed: string[];
  permissions_newly_broken: DiffPermission[];
  summary: DiffSummary;
}

export const DIFF_CHANGE_COLOR: Record<DiffChange, string> = {
  fixed:     '#00D98A',
  new:       '#FF3D5C',
  regressed: '#FF3D5C',
  improved:  '#3D8EFF',
  unchanged: '#3D4A5C',
};

export const DIFF_VERDICT_COLOR: Record<DiffVerdict, string> = {
  improved:            '#00D98A',
  neutral:             '#7A8599',
  regressed:           '#FFAA33',
  critical_regression: '#FF3D5C',
};
