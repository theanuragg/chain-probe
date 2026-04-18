// frontend/src/lib/fix_diff.ts
// Generates side-by-side before/after code diffs for every finding.
// Fully deterministic. No AI. Derived from the finding's anchor_fix and category.
//
// Each diff shows:
//   - The exact vulnerable pattern (from finding.snippet)
//   - The corrected Anchor code
//   - Line-level annotations explaining each change

import { Finding, Category } from '../types';

export interface FixDiff {
  finding_id: string;
  before_label: string;
  after_label: string;
  before_lines: DiffLine[];
  after_lines: DiffLine[];
  change_summary: string;
  // Cargo.toml change needed (if any)
  cargo_change: string | null;
}

export interface DiffLine {
  line_num: number;
  content: string;
  type: 'context' | 'removed' | 'added' | 'annotation';
  annotation?: string;
}

//   Entry point                                ─

export function generateFixDiff(finding: Finding): FixDiff {
  switch (finding.category) {
    case 'signer_authority':    return diffSignerAuthority(finding);
    case 'account_validation':  return diffAccountValidation(finding);
    case 'arithmetic_overflow': return diffArithmetic(finding);
    case 'pda_seed_collision':  return diffPdaSeeds(finding);
    case 'reentrancy':          return diffReentrancy(finding);
    case 'access_control':      return diffAccessControl(finding);
    default:                    return diffGeneric(finding);
  }
}

//   Category diffs                               

function diffSignerAuthority(f: Finding): FixDiff {
  const fieldName = extractFieldName(f.snippet) || 'authority';
  const isSystemAccount = f.title.toLowerCase().includes('systemaccount');

  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      ctx(`#[derive(Accounts)]`),
      ctx(`pub struct ${f.function}<'info> {`),
      ctx(`    // ... other fields`),
      removed(
        `    pub ${fieldName}: ${isSystemAccount ? 'SystemAccount' : 'AccountInfo'}<'info>,`,
        `No signature required — any account accepted`
      ),
      ctx(`    // ... other fields`),
      ctx(`}`),
    ]),
    after_lines: annotate([
      ctx(`#[derive(Accounts)]`),
      ctx(`pub struct ${f.function}<'info> {`),
      ctx(`    // ... other fields`),
      added(
        `    pub ${fieldName}: Signer<'info>,`,
        `Anchor verifies this account signed the transaction`
      ),
      ctx(`    // ... other fields`),
      ctx(`}`),
      ann(`// Also ensure state accounts store and verify this authority:`),
      added(
        `    #[account(mut, has_one = ${fieldName} @ ErrorCode::Unauthorized)]`,
        `Links state account to the verified signer`
      ),
      added(
        `    pub state: Account<'info, YourState>,`,
      ),
    ]),
    change_summary: `Change \`${isSystemAccount ? 'SystemAccount' : 'AccountInfo'}<'info>\` to \`Signer<'info>\`. ` +
      `Add \`has_one = ${fieldName}\` on any state account that stores this authority's pubkey.`,
    cargo_change: null,
  };
}

function diffAccountValidation(f: Finding): FixDiff {
  const isInitIfNeeded = f.title.toLowerCase().includes('init_if_needed');
  const fieldName = extractFieldName(f.snippet) || 'account';

  if (isInitIfNeeded) {
    return {
      finding_id: f.id,
      before_label: `${f.file} — VULNERABLE`,
      after_label: `${f.file} — FIXED`,
      before_lines: annotate([
        ctx(`#[account(`),
        removed(`    init_if_needed,`, `Silently accepts pre-existing accounts`),
        ctx(`    payer = payer,`),
        ctx(`    space = 8 + State::INIT_SPACE,`),
        ctx(`)]`),
        ctx(`pub ${fieldName}: Account<'info, State>,`),
      ]),
      after_lines: annotate([
        ctx(`#[account(`),
        added(`    init_if_needed,`, `Kept — but now guarded`),
        ctx(`    payer = payer,`),
        ctx(`    space = 8 + State::INIT_SPACE,`),
        added(
          `    constraint = ${fieldName}.data_is_empty() @ ErrorCode::AlreadyInitialized,`,
          `Rejects any pre-existing account — attacker's pre-created account is rejected`
        ),
        ctx(`)]`),
        ctx(`pub ${fieldName}: Account<'info, State>,`),
        ann(`// Or: replace init_if_needed with init if account is created exactly once`),
      ]),
      change_summary: `Add \`constraint = ${fieldName}.data_is_empty()\` to guard against reinitialization. ` +
        `If the account is only ever created once, prefer \`init\` over \`init_if_needed\`.`,
      cargo_change: null,
    };
  }

  // Generic mutable account without ownership binding
  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      ctx(`#[account(mut)]`),
      removed(`pub ${fieldName}: Account<'info, State>,`, `No ownership verification — any account of this type accepted`),
    ]),
    after_lines: annotate([
      added(
        `#[account(mut, has_one = authority @ ErrorCode::InvalidOwner)]`,
        `Anchor verifies state.authority == authority.key() — ownership bound`
      ),
      added(`pub ${fieldName}: Account<'info, State>,`),
      ann(`// Alternatively, use PDA seeds that include the authority:`),
      added(`// #[account(mut, seeds = [b"vault", authority.key().as_ref()], bump = ${fieldName}.bump)]`),
    ]),
    change_summary: `Add \`has_one = authority\` to bind the account to a verified authority. ` +
      `Or use PDA seeds that include the authority pubkey to make forgery impossible.`,
    cargo_change: null,
  };
}

function diffArithmetic(f: Finding): FixDiff {
  const isSlippage = f.title.toLowerCase().includes('slippage');
  const fnName = f.function || 'instruction';

  if (isSlippage) {
    return {
      finding_id: f.id,
      before_label: `${f.file} — VULNERABLE`,
      after_label: `${f.file} — FIXED`,
      before_lines: annotate([
        ctx(`pub fn ${fnName}(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {`),
        ctx(`    let pool = &mut ctx.accounts.pool;`),
        ctx(`    let amount_out = pool.token_b_reserve * amount_in / pool.token_a_reserve;`),
        removed(`    // min_out parameter ignored — no slippage check`, `min_out silently ignored`),
        ctx(`    pool.token_a_reserve += amount_in;`),
        ctx(`    pool.token_b_reserve -= amount_out;`),
        ctx(`    token::transfer(..., amount_out)?;`),
        ctx(`    Ok(())`),
        ctx(`}`),
      ]),
      after_lines: annotate([
        ctx(`pub fn ${fnName}(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {`),
        ctx(`    let pool = &mut ctx.accounts.pool;`),
        ctx(`    let amount_out = pool.token_b_reserve * amount_in / pool.token_a_reserve;`),
        added(
          `    require!(amount_out >= min_out, ErrorCode::SlippageExceeded);`,
          `Enforce caller's minimum output — sandwich attacks cannot profit below this threshold`
        ),
        ctx(`    pool.token_a_reserve += amount_in;`),
        ctx(`    pool.token_b_reserve -= amount_out;`),
        ctx(`    token::transfer(..., amount_out)?;`),
        ctx(`    Ok(())`),
        ctx(`}`),
      ]),
      change_summary: `Add \`require!(amount_out >= min_out, ErrorCode::SlippageExceeded)\` ` +
        `immediately after computing amount_out, before mutating any state.`,
      cargo_change: null,
    };
  }

  // Arithmetic overflow fix
  const isAdd = f.title.includes('+') || f.title.toLowerCase().includes('add');
  const isMul = f.title.includes('*') || f.title.toLowerCase().includes('mul');
  const method = isMul ? 'checked_mul' : isAdd ? 'checked_add' : 'checked_sub';

  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      ctx(`// In fn ${fnName}:`),
      removed(
        `    vault.balance += amount;`,
        `Silently wraps at u64::MAX in release builds without overflow-checks`
      ),
      ann(`// OR:`),
      removed(
        `    let reward = staked_amount * reward_rate;`,
        `Multiplication can easily overflow u64 with large values`
      ),
    ]),
    after_lines: annotate([
      ctx(`// Option A: Use checked arithmetic (explicit error on overflow)`),
      added(
        `    vault.balance = vault.balance.checked_add(amount)`,
        `Returns None on overflow instead of wrapping`
      ),
      added(`        .ok_or(ErrorCode::Overflow)?;`),
      ann(``),
      ctx(`// Option B: Use u128 for intermediate calculations`),
      added(
        `    let reward = (staked_amount as u128)`,
        `Widened to u128 — no overflow possible at practical token amounts`
      ),
      added(`        .checked_mul(reward_rate as u128)`),
      added(`        .ok_or(ErrorCode::Overflow)? as u64;`),
      ann(``),
      ctx(`// Option C: Enable overflow-checks in Cargo.toml (catches all operations)`),
    ]),
    change_summary: `Use \`checked_add\` / \`checked_mul\` with \`.ok_or(ErrorCode::Overflow)?\`, ` +
      `or cast to u128 for intermediate calculations. ` +
      `Also add \`overflow-checks = true\` to \`[profile.release]\` in Cargo.toml as a safety net.`,
    cargo_change: `[profile.release]\noverflow-checks = true  # ADD THIS LINE`,
  };
}

function diffPdaSeeds(f: Finding): FixDiff {
  const isBump = f.title.toLowerCase().includes('bump');
  const fieldName = extractFieldName(f.snippet) || 'account';

  if (isBump) {
    return {
      finding_id: f.id,
      before_label: `${f.file} — VULNERABLE`,
      after_label: `${f.file} — FIXED`,
      before_lines: annotate([
        ctx(`// In the state struct:`),
        removed(`pub struct MyAccount {`, `Missing bump field`),
        removed(`    pub authority: Pubkey,`, ``),
        removed(`    pub amount: u64,`, ``),
        removed(`    // NO bump field stored`, `Bump is re-searched on every use`),
        removed(`}`, ``),
        ann(``),
        ctx(`// In the Accounts struct:`),
        removed(
          `    #[account(init, payer=payer, seeds=[b"vault"], bump)]`,
          `Canonical bump not stored — any bump value accepted on subsequent calls`
        ),
        removed(`    pub vault: Account<'info, MyAccount>,`),
      ]),
      after_lines: annotate([
        ctx(`// In the state struct:`),
        added(`pub struct MyAccount {`),
        added(`    pub authority: Pubkey,`),
        added(`    pub amount: u64,`),
        added(`    pub bump: u8,  // Store the canonical bump`, `Canonical bump persisted in account`),
        added(`}`),
        ann(``),
        ctx(`// In the init instruction:`),
        added(`    #[account(init, payer=payer, seeds=[b"vault"], bump)]`),
        added(`    pub vault: Account<'info, MyAccount>,`),
        ann(``),
        ctx(`// In the init handler:`),
        added(`    vault.bump = ctx.bumps.vault;  // Store it`, `Bumps.vault = canonical bump from Anchor`),
        ann(``),
        ctx(`// In ALL subsequent instructions:`),
        added(
          `    #[account(seeds=[b"vault"], bump = vault.bump)]`,
          `Anchor validates: only canonical bump accepted, non-canonical rejected`
        ),
      ]),
      change_summary: `Add \`pub bump: u8\` to the state struct. ` +
        `Store \`ctx.bumps.account_name\` on init. ` +
        `Use \`bump = account.bump\` in all subsequent instructions.`,
      cargo_change: null,
    };
  }

  // Seed uniqueness fix
  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      removed(
        `    #[account(init, payer=payer, seeds=[b"vault"], bump)]`,
        `Static seeds — all users derive the same PDA address`
      ),
      removed(`    pub vault: Account<'info, Vault>,`),
    ]),
    after_lines: annotate([
      added(
        `    #[account(init, payer=payer, seeds=[b"vault", authority.key().as_ref()], bump)]`,
        `Authority pubkey in seeds — each user gets a unique PDA`
      ),
      added(`    pub vault: Account<'info, Vault>,`),
      ann(`// Each user's vault address is now: PDA(["vault", user_pubkey], program_id)`),
      ann(`// This is unguessable and unique — seed collision impossible`),
    ]),
    change_summary: `Include \`authority.key().as_ref()\` in the seeds array. ` +
      `This ensures each user derives a unique PDA — seed collision between users is impossible.`,
    cargo_change: null,
  };
}

function diffReentrancy(f: Finding): FixDiff {
  const fnName = f.function || 'instruction';
  const isStateAfterCpi = f.title.toLowerCase().includes('checks-effects');

  if (isStateAfterCpi) {
    return {
      finding_id: f.id,
      before_label: `${f.file} — VULNERABLE (CEI violated)`,
      after_label: `${f.file} — FIXED (Checks-Effects-Interactions)`,
      before_lines: annotate([
        ctx(`pub fn ${fnName}(ctx: ...) -> Result<()> {`),
        ctx(`    // CHECKS first (good)`),
        ctx(`    require!(vault.balance >= amount, ErrorCode::InsufficientFunds);`),
        ann(``),
        removed(`    // INTERACTION before EFFECT — wrong order`, `CPI fires before state update`),
        removed(`    token::transfer(cpi_ctx, amount)?;`),
        removed(`    vault.balance -= amount;  // TOO LATE — CPI already fired`, `State update after CPI`),
        ctx(`    Ok(())`),
        ctx(`}`),
      ]),
      after_lines: annotate([
        ctx(`pub fn ${fnName}(ctx: ...) -> Result<()> {`),
        ctx(`    // CHECKS`),
        ctx(`    require!(vault.balance >= amount, ErrorCode::InsufficientFunds);`),
        ann(``),
        added(`    // EFFECTS — mutate state BEFORE any CPI`, `State committed before external call`),
        added(`    vault.balance -= amount;`),
        ann(``),
        added(`    // INTERACTIONS — CPI fires after state is already committed`, `CPI sees updated state`),
        added(`    token::transfer(cpi_ctx, amount)?;`),
        ctx(`    Ok(())`),
        ctx(`}`),
      ]),
      change_summary: `Move all state mutations BEFORE CPI calls. ` +
        `The Checks-Effects-Interactions pattern ensures that even if a CPI re-enters this function, ` +
        `it sees the already-updated state and cannot double-claim.`,
      cargo_change: null,
    };
  }

  // Stale vault.amount read
  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE (stale read)`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      ctx(`pub fn ${fnName}(ctx: ...) -> Result<()> {`),
      ctx(`    // some CPI fires here...`),
      ctx(`    token::transfer(first_cpi_ctx, some_amount)?;`),
      ann(``),
      removed(
        `    transfer_checked(second_cpi_ctx, self.vault.amount, decimals)?;`,
        `vault.amount not reloaded — reads pre-CPI value from account cache`
      ),
      ctx(`    Ok(())`),
      ctx(`}`),
    ]),
    after_lines: annotate([
      ctx(`pub fn ${fnName}(ctx: ...) -> Result<()> {`),
      added(`    // Cache amount BEFORE any CPI fires`, `Read before any external call`),
      added(`    let vault_amount = self.vault.amount;`),
      ann(``),
      ctx(`    token::transfer(first_cpi_ctx, some_amount)?;`),
      ann(``),
      added(`    // Use cached value — not affected by CPI hooks`, `Uses pre-captured value`),
      added(`    transfer_checked(second_cpi_ctx, vault_amount, decimals)?;`),
      ann(``),
      ctx(`    // Alternative: reload after CPI`),
      added(`    // self.vault.reload()?;`),
      ctx(`    Ok(())`),
      ctx(`}`),
    ]),
    change_summary: `Cache \`self.vault.amount\` in a local variable before the first CPI. ` +
      `Or call \`self.vault.reload()?\` after each CPI to refresh the account data. ` +
      `This prevents Token-2022 transfer hooks from manipulating the value between reads.`,
    cargo_change: null,
  };
}

function diffAccessControl(f: Finding): FixDiff {
  const structName = f.function || 'AdminInstruction';

  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: annotate([
      ctx(`#[derive(Accounts)]`),
      ctx(`pub struct ${structName}<'info> {`),
      removed(
        `    #[account(mut)]`,
        `No signer, no authority check — anyone can call this`
      ),
      removed(`    pub config: Account<'info, Config>,`),
      removed(`    pub authority: AccountInfo<'info>,  // NOT a signer`),
      ctx(`}`),
      ann(``),
      ctx(`pub fn update_fee(ctx: Context<${structName}>, new_fee: u64) -> Result<()> {`),
      ctx(`    ctx.accounts.config.fee_bps = new_fee;  // any caller can set this`),
      ctx(`    Ok(())`),
      ctx(`}`),
    ]),
    after_lines: annotate([
      ctx(`#[derive(Accounts)]`),
      ctx(`pub struct ${structName}<'info> {`),
      added(
        `    #[account(mut, has_one = authority @ ErrorCode::Unauthorized)]`,
        `Anchor verifies config.authority == authority.key()`
      ),
      added(`    pub config: Account<'info, Config>,`),
      added(
        `    pub authority: Signer<'info>,`,
        `Must have signed — attacker cannot forge this`
      ),
      ctx(`}`),
      ann(``),
      ctx(`// Also ensure Config stores the authority:`),
      added(`pub struct Config {`),
      added(`    pub authority: Pubkey,  // Set during initialize`),
      added(`    pub fee_bps: u64,`),
      added(`}`),
      ann(``),
      ctx(`pub fn update_fee(ctx: Context<${structName}>, new_fee: u64) -> Result<()> {`),
      ctx(`    ctx.accounts.config.fee_bps = new_fee;`),
      ctx(`    Ok(())`),
      ctx(`}`),
    ]),
    change_summary: `Add \`pub authority: Signer<'info>\` to the Accounts struct. ` +
      `Add \`has_one = authority\` on the config account. ` +
      `Ensure the \`Config\` state struct stores \`pub authority: Pubkey\` set during initialization.`,
    cargo_change: null,
  };
}

function diffGeneric(f: Finding): FixDiff {
  return {
    finding_id: f.id,
    before_label: `${f.file} — VULNERABLE`,
    after_label: `${f.file} — FIXED`,
    before_lines: f.snippet
      ? f.snippet.split('\n').map((line, i) => removed(line, i === 0 ? f.title : undefined))
      : [removed('// See snippet in finding details', f.title)],
    after_lines: f.anchor_fix
      ? f.anchor_fix.split('\n').map(line => added(line))
      : [added(`// Apply: ${f.recommendation}`)],
    change_summary: f.recommendation,
    cargo_change: null,
  };
}

//   Line constructors                             ─

let _lineNum = 0;
function resetLines() { _lineNum = 0; }

function ctx(content: string): DiffLine {
  return { line_num: ++_lineNum, content, type: 'context' };
}
function removed(content: string, annotation?: string): DiffLine {
  return { line_num: ++_lineNum, content, type: 'removed', annotation };
}
function added(content: string, annotation?: string): DiffLine {
  return { line_num: ++_lineNum, content, type: 'added', annotation };
}
function ann(content: string): DiffLine {
  return { line_num: ++_lineNum, content, type: 'annotation' };
}

function annotate(lines: DiffLine[]): DiffLine[] {
  // Re-number from 1
  return lines.map((l, i) => ({ ...l, line_num: i + 1 }));
}

function extractFieldName(snippet: string): string | null {
  const match = snippet.match(/pub\s+(\w+)\s*:/);
  return match ? match[1] : null;
}
