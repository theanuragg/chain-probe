# ChainProbe v4 — Solana Anchor Static Security Analysis

> Not an AI wrapper. Not a linter. A static analysis engine that understands Anchor semantics.

---

## What this actually is

Most "smart contract auditors" are one of three things:
1. Grep with a UI (pattern matching on source text)
2. An AI that describes what you already know
3. A commercial black box you can't reason about

ChainProbe is none of these. It is a **multi-stage static analysis engine** built specifically for Anchor's account model. It understands what `has_one`, `seeds`, `Signer<>`, `init_if_needed`, and CPI calls actually mean at the constraint level — not as text patterns, but as semantic properties of the program's security model.

This document explains exactly what ChainProbe does, how each analysis stage works, and what it produces.

---

## Table of Contents

1. [Why existing tools miss things](#1-why-existing-tools-miss-things)
2. [ChainProbe's analysis pipeline](#2-chainprobes-analysis-pipeline)
3. [Stage 1 — AST Extraction](#3-stage-1--ast-extraction)
4. [Stage 2 — Trust Classification](#4-stage-2--trust-classification)
5. [Stage 3 — Taint Analysis](#5-stage-3--taint-analysis)
6. [Stage 4 — Invariant Mining](#6-stage-4--invariant-mining)
7. [Stage 5 — Call Graph & CPI Analysis](#7-stage-5--call-graph--cpi-analysis)
8. [Stage 6 — Vulnerability Detection](#8-stage-6--vulnerability-detection)
9. [Stage 7 — Chain Detection](#9-stage-7--chain-detection)
10. [Stage 8 — Exploitability Scoring](#10-stage-8--exploitability-scoring)
11. [What the report contains](#11-what-the-report-contains)
12. [The PoC test generator](#12-the-poc-test-generator)
13. [The fix diff engine](#13-the-fix-diff-engine)
14. [Architecture diagrams](#14-architecture-diagrams)
15. [Data structures reference](#15-data-structures-reference)
16. [Running ChainProbe](#16-running-chainprobe)
17. [What we are building next](#17-what-we-are-building-next)

---

## 1. Why existing tools miss things

### The pattern matching problem

A tool that searches for `AccountInfo` in your source code will find `AccountInfo` in your source code. It will also fire on:
- Comments explaining why you used AccountInfo correctly
- Test files with intentional AccountInfo usage
- Places where AccountInfo is fine (system_program, token_program wrappers)

More importantly, it misses:
- `SystemAccount<'info>` used as an authority (owns by System Program, never signs)
- `has_one = authority` present but `authority` is still `AccountInfo` (key match, no sig)
- Mutable accounts with no constraint that are protected *only* by business logic in a different instruction

### The single-file problem

Every Anchor program splits across `lib.rs`, `instructions/`, `state/`, `errors/`. The vulnerability is almost never in one file. It's in the gap:

- `lib.rs` calls `deposit()` before `withdraw_and_close_vault()` — the ordering matters for reentrancy
- `instructions/make.rs` sets `escrow.authority = ctx.accounts.authority.key()` with no signer check on `authority`
- `instructions/withdraw.rs` uses `has_one = authority` which checks key equality — but the key was set by an unsigned operation

No single-file tool catches this. You need the full program graph.

### The "presence not exploitability" problem

Finding that `overflow-checks` is not set is not the same as finding an overflow that matters. A `u64` add on a field that can never exceed 1000 is not exploitable. A `u64` multiply on `staked_amount * reward_rate` where both are user-influenced is critical.

Most tools report the first as high severity and miss the second entirely.

---

## 2. ChainProbe's analysis pipeline

```
Input: Vec<{path, content}> — all .rs and .toml files in the project

Stage 1: AST Extraction          (ast_visitor.rs)
  syn parses every .rs file → extracts instructions, account structs,
  field constraints, CPI calls, arithmetic ops, state types, PDA derivations

Stage 2: Trust Classification    (trust.rs)
  Per-field trust level from Anchor constraints
  Two-pass: direct classification → has_one propagation

Stage 3: Taint Analysis          (taint.rs)  ← NEW in v4
  Tracks user-controlled values through the AST
  Source: instruction parameters, unverified account fields
  Sink: transfer amounts, authority checks, PDA seeds, arithmetic ops
  Propagation: through assignments, arithmetic, function calls

Stage 4: Invariant Mining        (invariant.rs)  ← NEW in v4
  Extracts every require!() condition
  Identifies what each invariant protects
  Checks whether bypass paths exist given the taint analysis results

Stage 5: Call Graph              (call_graph.rs)  ← NEW in v4
  Builds directed graph: instruction → CPI → external program
  Binds account parameters across CPI boundaries
  Computes minimum attacker-controlled accounts to reach each sink

Stage 6: Pattern Detection       (patterns.rs)
  6 category detectors using AST + trust map + taint results
  Each detector uses the richer context from stages 1-5

Stage 7: Chain Detection         (chain_detector.rs)
  Combines findings into exploitable multi-step chains
  Uses call graph to verify chain reachability (not just co-occurrence)

Stage 8: Exploitability Scoring  (scoring.rs)  ← NEW in v4
  Per-finding: steps to exploit, required trust level, blast radius
  Program-level: attack surface score, hardening score

Output: AnalysisReport {
  findings, chains, profile, trust_map,
  taint_flows, invariants, call_graph,
  known_vulns, scores
}
```

---

## 3. Stage 1 — AST Extraction

**File:** `backend/src/ast_visitor.rs`

Uses the `syn` crate to parse every `.rs` file into a full Rust AST. This is not regex — it is the same parser the Rust compiler uses.

### What is extracted

**Instructions** — every `pub fn` with a `Context<T>` first parameter:
```rust
// Detected as InstructionInfo { name: "deposit", ctx_type: "Deposit", params: ["amount: u64"] }
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> { ... }
```

**Account structs** — every `#[derive(Accounts)]` struct with all field attributes:
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]                    // → is_mut: true
    pub vault: Account<'info, Vault>,  // → field_type: Account<Vault>
    pub authority: AccountInfo<'info>, // → UserSuppliedUnverified
}
```

**CPI calls** — every `transfer()`, `invoke()`, `close_account()` call in function bodies, including which program they call and whether they use `new_with_signer` (PDA authority) vs `new` (user authority).

**Arithmetic operations** — every `+`, `-`, `*`, `/` on values that look like token amounts (field names containing `amount`, `balance`, `reserve`, `reward`, `fee`, `total`, `supply`, `staked`). Tracks whether `checked_*` variants are used.

**PDA derivations** — every `seeds = [...]` attribute, including what values are in the seeds and whether `bump` is stored.

**State accounts** — every `#[account]` struct (the actual on-chain state types, not the Accounts context structs).

### Fallback

If `syn` fails to parse a file (heavy procedural macros, etc.), `line_level_fallback()` runs grep-style extraction. Less accurate but catches the main patterns.

### Why the raw line store matters

`ProjectVisitor` stores `HashMap<path, Vec<line>>` for every file. This is used by `snippet_for_pattern()` which does text search to find the exact source region for each finding. Findings include the actual code, not just a description.

---

## 4. Stage 2 — Trust Classification

**File:** `backend/src/trust.rs`

Classifies every account field in every `#[derive(Accounts)]` struct by how much control an attacker has over it. This is deterministic — derived entirely from the Anchor constraint attributes on each field.

### Classification rules (priority order)

```
1. seeds = [...]          → ProgramControlled   (program owns derivation)
2. Signer<'info>          → SignerRequired       (must have signed tx)
3. Program<> / Sysvar<>   → ProgramControlled   (infrastructure)
4. SystemAccount<'info>   → UserSuppliedVerified (owned by system, not signed)
5. AccountInfo<'info>     → UserSuppliedUnverified (zero verification)
6. has_one or constraint= → UserSuppliedVerified  (some binding exists)
7. Account<T> typed       → UserSuppliedVerified  (discriminator only)
```

### Two-pass propagation

**Pass 1** classifies each field independently by its own attributes.

**Pass 2** propagates trust through `has_one` chains:
```rust
// If vault has `has_one = authority` and authority is SignerRequired...
// then vault is upgraded to IndirectlyVerified
#[account(mut, has_one = authority)]
pub vault: Account<'info, Vault>,

pub authority: Signer<'info>,  // ← trust propagates upward to vault
```

This is why `authority: AccountInfo<'info>` + `has_one = authority` is still dangerous — `has_one` verifies key equality but `AccountInfo` never required a signature, so the key was set by whoever called the instruction first.

### Risk scores

```
ProgramControlled:      0  — attacker cannot influence
SignerRequired:         1  — attacker must possess private key
IndirectlyVerified:     2  — protected via chain from trusted root
UserSuppliedVerified:   3  — caller-chosen but typed/constrained
UserSuppliedUnverified: 10 — fully attacker-controlled
```

The gap between 3 and 10 is intentional. `UserSuppliedUnverified` is categorically different from everything else.

---

## 5. Stage 3 — Taint Analysis

**File:** `backend/src/taint.rs` ← **NEW in v4**

This is the most important new stage. It tracks how attacker-controlled values propagate through the program.

### Taint sources

A value is tainted (attacker-influenced) if it comes from:
- An instruction parameter (user supplies this directly)
- An account field whose trust level is `UserSuppliedUnverified` (raw AccountInfo)
- Arithmetic on a tainted value

### Taint sinks

A tainted value reaching a sink is a potential vulnerability:

| Sink | What it means |
|---|---|
| `token::transfer(amount)` | Attacker controls how many tokens are transferred |
| `authority.key()` comparison | Attacker controls what key is used as authority |
| `seeds = [tainted_value]` | Attacker influences PDA derivation |
| `require!(condition)` where condition uses tainted | Attacker may be able to force the require to pass or fail |
| `Account<T>.field = tainted` | Attacker writes tainted value to persistent state |

### Propagation rules

```
// Direct taint — function parameter
pub fn swap(ctx: Context<Swap>, amount_in: u64, ...) {
    // amount_in is TAINTED (Source::InstructionParam)

    // Arithmetic propagation — result is tainted
    let amount_out = reserve_b * amount_in / reserve_a;
    // amount_out is TAINTED (propagated from amount_in)

    // State write — taint stored
    pool.reserve_a += amount_in;
    // pool.reserve_a now carries taint

    // Sink detection — tainted value reaches transfer
    token::transfer(cpi, amount_out)?;
    // FINDING: tainted value reaches token transfer sink
}
```

### What taint analysis finds that pattern matching cannot

**Fee manipulation:**
```rust
// No pattern matches this — no obvious vulnerability keyword
let fee = amount * fee_rate / 10000;
// But if fee_rate is read from a user-supplied config account (UserSuppliedUnverified)
// then fee is tainted, and if fee is subtracted from a protected amount,
// attacker controls their own fee → fee extraction attack
```

**Overflow through taint chain:**
```rust
let reward = staked_amount * reward_rate;
// If staked_amount is u64 and reward_rate comes from a writable config
// that lacks authority checks → reward_rate is tainted
// → reward calculation is tainted and could overflow to near-zero
```

**Invariant bypass via tainted require! argument:**
```rust
require!(vault.balance >= withdrawal_amount, ErrorCode::Insufficient);
// If vault.balance can be manipulated by a prior instruction (taint reaches it)
// then this require! can be made to pass with any withdrawal_amount
```

### TaintFlow type

```rust
pub struct TaintFlow {
    pub id: String,
    pub source: TaintSource,
    pub source_location: (String, usize),  // (file, line)
    pub sink: TaintSink,
    pub sink_location: (String, usize),
    pub path: Vec<TaintHop>,              // each propagation step
    pub severity: Severity,               // Critical if reaches transfer/authority
}

pub enum TaintSource {
    InstructionParam { param_name: String, param_type: String },
    UnverifiedAccount { account_name: String, instruction: String },
    TaintedStateField { field_path: String },
}

pub enum TaintSink {
    TokenTransferAmount,
    AuthorityKeyComparison,
    PdaSeedComponent,
    RequireCondition { condition: String },
    StateMutation { field_path: String },
}
```

---

## 6. Stage 4 — Invariant Mining

**File:** `backend/src/invariant.rs` ← **NEW in v4**

Extracts the security invariants the program author intended to enforce, then checks whether they can be violated.

### What an invariant is

Every `require!()` call is a security invariant:
```rust
require!(vault.balance >= amount, VaultError::InsufficientFunds);
// Invariant: vault.balance is always >= the withdrawal amount
// Intended protection: prevents over-withdrawal

require!(pool.authority == ctx.accounts.authority.key(), PoolError::Unauthorized);
// Invariant: only the stored authority can perform this action
// Intended protection: access control
```

### What ChainProbe checks for each invariant

**1. Can the condition be tainted?**
Using taint analysis results from Stage 3, check whether any variable in the condition is reachable by an attacker-controlled value. If `vault.balance` can be set by an attacker (because a prior instruction has no authority check), then the invariant is bypassable.

**2. Does the invariant apply in all instructions?**
If `require!(pool.authority == ...)` exists in `withdraw` but not in `update_config`, and both operate on the same `pool` account, then the protection is incomplete.

**3. Are there ordering attacks?**
If invariant A depends on state set by instruction X, and there's no guarantee instruction X has run before A is checked, then A can be bypassed by calling the protected instruction before X.

### InvariantStatus

```rust
pub struct ProgramInvariant {
    pub id: String,
    pub condition: String,          // The actual require!() expression
    pub file: String,
    pub line: usize,
    pub instruction: String,
    pub protects: String,           // What ChainProbe infers this protects
    pub status: InvariantStatus,
    pub bypass_path: Option<String>,// How it can be bypassed, if applicable
}

pub enum InvariantStatus {
    Holds,          // No bypass path found
    Bypassable,     // Taint analysis found a way to violate it
    Incomplete,     // Not enforced in all relevant instructions
    OrderingRisk,   // Can be bypassed by instruction ordering
}
```

---

## 7. Stage 5 — Call Graph & CPI Analysis

**File:** `backend/src/call_graph.rs` ← **NEW in v4**

Builds the actual call graph: which instructions invoke which other programs, what accounts flow through CPIs, and what the minimum attacker footprint is to reach each security-sensitive operation.

### What the call graph contains

**Nodes:** instructions + CPI targets (external programs)

**Edges:** directed, labeled with:
- Which accounts are passed
- What trust level those accounts have at the call site
- Whether the CPI uses `new_with_signer` (PDA authority) or user-provided authority

**Example graph for an escrow program:**
```
make ──[vault:ProgramControlled, maker:SignerRequired]──► token::transfer
take ──[taker_ata_b:UserSupplied]──────────────────────► token::transfer (deposit)
take ──[vault:ProgramControlled]───────────────────────► token::transfer (withdraw)
take ──[vault:ProgramControlled]───────────────────────► token::close_account
refund ──[vault:ProgramControlled]─────────────────────► token::transfer
```

### Attack surface scoring per entry point

For each instruction, ChainProbe computes:

```
attack_surface_score = Σ (account.trust_risk_score) for all accounts
```

An instruction with all `ProgramControlled` accounts scores 0 — fully closed. An instruction with multiple `UserSuppliedUnverified` accounts scores high — many attack vectors.

### Minimum attacker footprint

For each finding, ChainProbe computes: "what is the minimum set of accounts/permissions an attacker needs to control to trigger this vulnerability?"

```rust
pub struct AttackerFootprint {
    pub required_accounts: Vec<AttackerAccount>,
    pub required_keypairs: u8,    // How many private keys attacker needs
    pub required_sol: f64,        // Minimum SOL for rent + tx fees
    pub on_chain_setup: bool,     // Does attacker need to deploy a program?
    pub complexity: ExploitComplexity,
}

pub enum ExploitComplexity {
    Trivial,    // Single transaction, no setup
    Low,        // Setup required but straightforward
    Medium,     // Multiple transactions, some preparation
    High,       // Requires specific conditions or deployed program
}
```

---

## 8. Stage 6 — Vulnerability Detection

**File:** `backend/src/patterns.rs`

The six pattern detectors now use the full context from stages 1–5, making them significantly more accurate than before.

### How each detector is upgraded in v4

**Account Validation** now uses taint results:
- Old: flag `AccountInfo` for authority-named fields
- New: flag `AccountInfo` only when trust analysis shows it's reachable from a security-sensitive path AND taint analysis shows its value propagates to a sink

**Arithmetic Overflow** now uses taint results:
- Old: flag any `u64 +` without `checked_add` on amount-named variables
- New: flag only when the arithmetic result reaches a token transfer or state mutation via taint propagation

**Signer Authority** now uses the full constraint graph:
- Old: flag `AccountInfo` typed authority fields
- New: additionally flag cases where `has_one` is present but the referenced account was set via an unverified instruction

**Access Control** now checks invariant completeness:
- Old: flag admin instructions with no `Signer<>` in the struct
- New: additionally flag cases where invariants protecting critical config are not consistently applied across all instructions that modify the same state

### Finding confidence levels

Each finding now has a `confidence: u8` (0–100):

```
confidence = base_confidence
  + 20 if taint analysis confirms the finding
  + 20 if the vulnerability appears in an active call graph path
  + 15 if a matching invariant is shown to be bypassable
  + 10 if a known exploit pattern matches exactly
  - 30 if business logic elsewhere likely prevents exploitation
```

---

## 9. Stage 7 — Chain Detection

**File:** `backend/src/chain_detector.rs`

Five chain patterns, now verified against the call graph for actual reachability:

| Pattern | What it detects |
|---|---|
| A | Unverified authority + mutable state → account takeover |
| B | Missing signer + admin mutation connected by call graph path |
| C | Arithmetic overflow in taint path that reaches token transfer |
| D | Reentrancy: state mutated after CPI + taint-confirmed stale read |
| E | PDA seed collision + init_if_needed without guard |

The key upgrade in v4: a chain is only reported if **the call graph confirms the attacker can actually reach all component instructions** with a realistic set of controlled accounts.

---

## 10. Stage 8 — Exploitability Scoring

**File:** `backend/src/scoring.rs` ← **NEW in v4**

The final score is not just a penalty matrix. It answers: "how hard is this program to exploit?"

### Per-finding exploitability score

```
exploitability_score = (
    (10 - attacker_footprint.required_keypairs) * 10  // fewer keys = easier
    + (100 - attack_surface_score) / 10               // lower surface = harder
    + (confidence / 10)                                // higher confidence = more likely real
    + (10 if trivial complexity, 5 if low, 2 if medium, 0 if high)
)
```

### Program-level scores

```
attack_surface_score: 0–100
  Derived from: average trust risk across all account fields × instruction count
  Higher = more attacker-controlled inputs

hardening_score: 0–100
  Derived from: % of account fields properly constrained, overflow-checks enabled,
  canonical bump stored, has_one present on mutable accounts

security_score: 0–100
  = 100 - finding_penalties - chain_penalties - advisory_penalties
  Where penalties are weighted by (severity × exploitability)

overall_risk: Critical | High | Medium | Low | Minimal
```

---

## 11. What the report contains

```typescript
interface AnalysisReport {
  id: string
  analyzed_at: string
  
  findings: Finding[]              // All detected vulnerabilities
  chains: VulnChain[]              // Multi-finding exploit chains
  known_vulns: KnownVuln[]         // Version advisory matches
  
  // NEW in v4
  taint_flows: TaintFlow[]         // How attacker-controlled values propagate
  invariants: ProgramInvariant[]   // require!() analysis results
  call_graph: CallGraph            // Instruction → CPI graph
  
  profile: ProgramProfile          // Metrics: lines, CPI count, etc.
  
  data_flow: DataFlowGraph         // Cross-instruction account flows
  trust_map: TrustMap              // Per-field trust classification
  
  scores: {
    security_score: number         // 0–100 final score
    static_score: number           // Before any adjustments
    attack_surface_score: number   // How exposed is the program
    hardening_score: number        // How well-constrained
    overall_risk: string
  }
  
  summary: ReportSummary           // Finding counts, chain count, etc.
}
```

---

## 12. The PoC test generator

**File:** `frontend/src/lib/poc_generator.ts`

For every finding, ChainProbe generates a runnable `#[tokio::test]` that **proves the exploit works**.

### Why this matters

An auditor's job is not to describe a vulnerability — it is to prove it. A PoC test does three things:

1. **Confirms the vulnerability is real** — if the test fails (vulnerability not present), the finding was a false positive
2. **Documents the attack precisely** — the exact transaction, accounts, and data needed
3. **Becomes a regression test** — after fixing, run `cargo test`. If the exploit test now returns `Err(...)`, the fix is verified

### What makes a good PoC

A weak PoC: "An attacker can pass any account as authority."

A strong PoC:
```rust
#[tokio::test]
async fn test_unsigned_authority_accepted() {
    // Setup: program deployed, vault initialized with legitimate_authority
    let legitimate_authority = Keypair::new();
    let attacker = Keypair::new();
    let fake_authority = Keypair::new(); // attacker-controlled, not legitimate_authority
    
    // Attack: pass fake_authority — no signature from legitimate_authority
    let ix = build_withdraw_instruction(
        vault_pda,
        fake_authority.pubkey(), // substitute for legitimate_authority
        attacker_token_account,
        1_000_000,
    );
    
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&attacker.pubkey()),
        &[&attacker],           // attacker signs — legitimate_authority does NOT
        recent_blockhash,
    );
    
    let result = banks_client.process_transaction(tx).await;
    
    // VULNERABILITY: succeeds without legitimate_authority's signature
    assert!(result.is_ok(), "ATTACK SUCCEEDED: funds withdrawn without authority");
    
    // After fix (authority: Signer<'info>):
    // assert!(result.is_err(), "FIXED: requires legitimate authority signature");
}
```

### Generated for every finding category

| Category | What the PoC demonstrates |
|---|---|
| Signer Authority | Transaction succeeds without the authority's private key |
| Account Validation | Attacker's account is accepted where victim's is expected |
| Arithmetic Overflow | u64::MAX or crafted values cause wrap-around |
| PDA Seed Collision | Two different users derive the same PDA address |
| Reentrancy | Double-withdrawal via stale vault.amount read |
| Access Control | Random keypair successfully calls admin instruction |

---

## 13. The fix diff engine

**File:** `frontend/src/lib/fix_diff.ts`

Side-by-side before/after for every finding. Not a suggestion — the actual corrected Anchor code.

### Example: Signer Authority fix

```
BEFORE                                    AFTER
─────────────────────────────────────    ──────────────────────────────────────
 #[derive(Accounts)]                      #[derive(Accounts)]
 pub struct Withdraw<'info> {             pub struct Withdraw<'info> {
-    pub authority: AccountInfo<'info>,  +    pub authority: Signer<'info>,  ← must sign
     #[account(mut)]                          #[account(
     pub vault: Account<'info, Vault>,   +        mut,
                                         +        has_one = authority         ← binds vault to signer
                                         +            @ ErrorCode::Unauthorized
 }                                            )]
                                              pub vault: Account<'info, Vault>,
                                          }
```

### Example: Arithmetic fix with Cargo.toml change

```
BEFORE                                    AFTER
─────────────────────────────────────    ──────────────────────────────────────
 // Cargo.toml [profile.release]          // Cargo.toml [profile.release]
-                                        + overflow-checks = true

 pub fn unstake(...) -> Result<()> {      pub fn unstake(...) -> Result<()> {
-    let reward = amount * rate;         +    let reward = (amount as u128)
                                         +        .checked_mul(rate as u128)
                                         +        .ok_or(ErrorCode::Overflow)?
                                         +        as u64;
```

---

## 14. Architecture diagrams

### Full pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    React Frontend                               │
│                                                                 │
│  Input modes:        Tabs in report:                           │
│  • Folder upload     • Overview (score, profile, categories)   │
│  • GitHub fetch      • Taint Flows (NEW — propagation graph)   │
│  • Paste code        • Attack Surface (trust map per instr)    │
│                      • Invariants (NEW — require! analysis)    │
│                      • Call Graph (NEW — CPI visualization)    │
│                      • Chains (multi-finding exploit paths)    │
│                      • Findings (with PoC + fix diff per item) │
│                      • Advisories (version CVE matches)        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ POST /api/analyze
                            │ { files: [{path, content}] }
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Rust Backend (Axum)                          │
│                                                                 │
│  1. ast_visitor    → ProjectVisitor (all AST nodes)            │
│  2. trust          → TrustMap (per-field trust levels)         │
│  3. taint          → Vec<TaintFlow> (source→sink paths)  NEW   │
│  4. invariant      → Vec<ProgramInvariant> (require! audit) NEW│
│  5. call_graph     → CallGraph (instr→CPI graph)          NEW  │
│  6. patterns       → Vec<Finding> (6 category detectors)       │
│  7. chain_detector → Vec<VulnChain> (multi-finding chains)     │
│  8. scoring        → Scores (exploitability + hardening)  NEW  │
│  9. vuln_db        → Vec<KnownVuln> (advisory match)           │
│  10. report        → AnalysisReport (assembly)                 │
└─────────────────────────────────────────────────────────────────┘
```

### Taint flow example (escrow program)

```
Source: take() — amount_in: u64 (InstructionParam)
  │
  ├─ amount_in used in: pool.reserve_a += amount_in
  │    └─ Taint stored in: pool.reserve_a (StateMutation)
  │
  ├─ amount_out = reserve_b * amount_in / reserve_a
  │    └─ Taint propagated to: amount_out (Arithmetic)
  │         │
  │         ├─ SINK: token::transfer(cpi, amount_out)
  │         │    └─ TaintFlow { severity: Critical, sink: TokenTransferAmount }
  │         │
  │         └─ amount_out < min_out check MISSING
  │              └─ InvariantMissing { condition: "amount_out >= min_out" }
  │
  └─ pool.reserve_b -= amount_out  ← uses tainted amount_out
       └─ Taint stored in: pool.reserve_b (StateMutation)
            └─ Affects future swaps via reserve_b
```

### Trust consistency example

```
Instruction: make()
  authority: AccountInfo → UserSuppliedUnverified (10) ← PROBLEM
  vault: Account<Vault> + seeds → ProgramControlled (0)
  escrow: Account<Escrow> + init → ProgramControlled (0)

stored in escrow: escrow.maker = authority.key()
                                 ↑ tainted source

Instruction: refund()
  authority: Signer → SignerRequired (1) ← correct
  escrow: has_one = authority ← verifies escrow.maker == authority.key()

But escrow.maker was set to an UNSIGNED value in make()
So the has_one in refund() only verifies "you know the pubkey that was set unsafely"
→ CHAIN: unsigned authority in make() + has_one verification in refund() = false security
```

---

## 15. Data structures reference

### TaintFlow

```typescript
interface TaintFlow {
  id: string
  source: {
    type: 'instruction_param' | 'unverified_account' | 'tainted_state'
    name: string
    instruction: string
    file: string
    line: number
  }
  sink: {
    type: 'token_transfer' | 'authority_check' | 'pda_seed' | 'require_condition' | 'state_mutation'
    description: string
    file: string
    line: number
  }
  path: Array<{
    operation: string      // 'assignment', 'arithmetic', 'function_call', 'state_write'
    file: string
    line: number
    snippet: string
  }>
  severity: Severity
  finding_id: string | null  // links to a Finding if this confirms one
}
```

### ProgramInvariant

```typescript
interface ProgramInvariant {
  id: string
  condition: string          // The require!() expression text
  instruction: string
  file: string
  line: number
  protects: string           // Inferred protection (e.g. "prevents over-withdrawal")
  status: 'holds' | 'bypassable' | 'incomplete' | 'ordering_risk'
  bypass_path: string | null // How it can be bypassed
  taint_confirmed: boolean   // Whether taint analysis confirms bypassability
}
```

### CallGraphNode / CallGraphEdge

```typescript
interface CallGraphNode {
  id: string
  type: 'instruction' | 'cpi_target'
  name: string
  program_id: string | null
  attack_surface_score: number
  attacker_footprint: {
    required_keypairs: number
    complexity: 'trivial' | 'low' | 'medium' | 'high'
    on_chain_setup_required: boolean
  }
}

interface CallGraphEdge {
  from: string               // node id
  to: string                 // node id
  accounts_passed: Array<{
    name: string
    trust: AccountTrust
  }>
  uses_pda_signer: boolean   // new_with_signer vs new
  cpi_type: 'transfer' | 'close' | 'mint' | 'burn' | 'custom'
}
```

---

## 16. Running ChainProbe

### Requirements

- Rust stable (1.75+)
- Node.js 18+
- `ANTHROPIC_API_KEY` optional — only used for chain semantic enrichment

### Backend

```bash
cd backend
cargo build --release

# Run server
RUST_LOG=chainprobe=debug ./target/release/chainprobe
# Listens on http://localhost:3001

# Run tests
cargo test  # includes vuln_db semver tests
```

### Frontend

```bash
cd frontend
npm install
npm start  # http://localhost:3000, proxied to backend
```

### API

```
POST /api/analyze
Content-Type: application/json

{
  "files": [
    { "path": "programs/my_program/src/lib.rs", "content": "..." },
    { "path": "programs/my_program/Cargo.toml", "content": "..." }
  ]
}

→ 200 OK: AnalysisReport (JSON)
→ 400 Bad Request: { "error": "No .rs files found" }
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3001` | Backend port |
| `RUST_LOG` | `chainprobe=debug` | Log level |
| `ANTHROPIC_API_KEY` | — | Optional. If set, chains with `needs_ai_context=true` get semantic explanation |

---

## 17. What we are building next

These are concrete, scoped features in priority order.

### 17.1 Symbolic execution for PDA derivation verification

**What:** For each PDA derivation, symbolically evaluate whether the seeds actually uniquely identify the intended account. Check for seed aliasing (two different intended accounts that can derive to the same address under certain inputs).

**Why pattern matching misses this:** Seeds `[b"pool", token_mint.key()]` looks unique, but if `token_mint` can be any mint the attacker creates, they can create a mint that makes this PDA collide with a legitimate pool.

**Implementation:** Symbolic seed evaluation in `taint.rs` — mark seed components as tainted if they come from user-supplied accounts.

### 17.2 Cross-program vulnerability detection

**What:** When a program makes a CPI, ChainProbe should check whether the called program (if it's a known program like SPL Token, Token-2022, Metaplex) has any advisories or known interaction patterns that affect the calling program.

**Why:** The Wormhole exploit was a CPI verification failure. Programs don't exist in isolation.

**Implementation:** Extend `call_graph.rs` + `vuln_db.rs` with known-program interaction patterns.

### 17.3 Compilable PoC test generation

**What:** The current PoC generator produces annotated pseudo-code with TODOs. A proper PoC should compile against the actual program. This requires:
1. Extracting the instruction discriminators from the AST (8-byte sha256 hash of "namespace:function_name")
2. Generating the correct account meta arrays from the Accounts struct
3. Generating valid instruction data encoding for the parameters

**Implementation:** New `poc_compiler.rs` in backend. Takes a `Finding` + `ProjectVisitor` and produces compilable Rust test code with real discriminators and correct account ordering.

### 17.4 Differential auditing (audit vs. audit comparison)

**What:** Accept two reports and produce a diff: what was fixed, what regressed, what is new. Score delta shown. Critical for teams running ChainProbe in CI.

**API:**
```
POST /api/diff
{ "before": AnalysisReport, "after": AnalysisReport }
→ DiffReport { fixed, new, regressed, score_delta, chains_resolved, chains_new }
```

### 17.5 CI/CD binary mode

**What:** `chainprobe-cli --project-path ./programs --min-severity HIGH --fail-on-chains`

Exits 0 if no findings above threshold, 1 otherwise. Outputs report JSON to stdout. Full GitHub Actions integration with step summary.

**Implementation:** New `[[bin]]` target in Cargo.toml. Thin wrapper around existing pipeline.

---

## Appendix: why no AI for detection

ChainProbe does not use AI to detect vulnerabilities. Here is the precise reason for each category:

**Account validation:** Whether a field is `AccountInfo` vs `Signer<>` is a syntactic property of the AST. It is either there or it is not. AI cannot be more accurate than `syn` on this.

**Arithmetic overflow:** Whether `overflow-checks = true` is in `Cargo.toml` is a string search. Whether an arithmetic operation uses `checked_add` is a method call check in the AST. Deterministic.

**Signer authority:** The type of a struct field is in the AST. The presence or absence of `has_one` is in the attribute list. Deterministic.

**PDA seed collision:** The seeds array is in the attribute. Whether it contains the user's pubkey is a content check. Deterministic.

**Reentrancy:** Whether state is mutated before or after a CPI call is a statement ordering question in the function body. Deterministic.

**Access control:** Whether a `Signer<>` field exists in an Accounts struct is a type check. Deterministic.

**Where AI does add value:** explaining what a vulnerability means in the context of *this specific program's business logic*. A missing signer on `update_config` is always a finding. But understanding that `config.fee_bps` flows into a fee calculation that can be set to 10000 (100%) and drain every subsequent swap — that requires understanding the program's purpose. That is the narrow case where we use AI.
