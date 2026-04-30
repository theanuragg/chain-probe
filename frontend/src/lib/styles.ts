import { C } from './constants';

export const Sb: Record<string,React.CSSProperties> = {
  field: {
    width:'100%',
    background:'#fff',
    border:`1px solid ${C.bdr}`,
    borderRadius:12,
    padding:'10px 14px',
    fontFamily:"'Inter',sans-serif",
    fontSize:14,
    color:C.txt,
    outline:'none',
    marginBottom:8,
    transition:'border-color .2s',
  },
  btnSm: {
    width:'100%',
    fontSize:13,
    fontWeight:600,
    color:'#fff',
    background:C.cyan,
    padding:'10px 16px',
    borderRadius:12,
    border:'none',
    cursor:'pointer',
    fontFamily:"'Inter',sans-serif",
    transition:'opacity .2s',
  },
  btnP: {
    display:'inline-flex',
    alignItems:'center',
    fontSize:14,
    fontWeight:600,
    color:'#fff',
    background:C.cyan,
    padding:'12px 24px',
    borderRadius:'9999px',
    border:'none',
    cursor:'pointer',
    fontFamily:"'Inter',sans-serif",
  },
  exBtn: {
    fontSize:12,
    padding:'6px 12px',
    borderRadius:'9999px',
    border:`1px solid ${C.bdr}`,
    background:'#fff',
    cursor:'pointer',
    color:C.t3,
    fontFamily:"'Inter',sans-serif",
    fontWeight:500,
    transition:'all .2s',
  },
  runBtn: {
    width:'100%',
    fontSize:14,
    fontWeight:600,
    color:'#fff',
    background:C.cyan,
    padding:'14px 20px',
    borderRadius:'9999px',
    border:'none',
    cursor:'pointer',
    fontFamily:"'Inter',sans-serif",
  },
  rbBtn: {
    fontSize:13,
    fontWeight:500,
    padding:'8px 16px',
    borderRadius:'9999px',
    cursor:'pointer',
    fontFamily:"'Inter',sans-serif",
    transition:'all .2s',
  },
  card: {
    background:'#fff',
    border:`1px solid ${C.bdr}`,
    borderRadius:20,
    padding:20,
  },
};

export const DEMO_ESCROW = `// ===== FILE: anchor-escrow/programs/anchor-escrow/Cargo.toml =====
[package]
name = "anchor-escrow"
version = "0.1.0"
[dependencies]
anchor-lang = { version = "0.29.0", features = ["init-if-needed"] }
anchor-spl = "0.29.0"

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/lib.rs =====
use anchor_lang::prelude::*;
pub mod instructions; pub mod state; use instructions::*;
declare_id!("5UFZzEt5vU9fxtUAgsD11z63ApZEHJ5bH7Z4QpFwZ2CQ");
#[program]
pub mod anchor_escrow {
    use super::*;
    pub fn make(ctx: Context<Make>, seed: u64, deposit: u64, receive: u64) -> Result<()> { ctx.accounts.deposit(deposit)?; ctx.accounts.init_escrow(seed, receive, &ctx.bumps) }
    pub fn refund(ctx: Context<Refund>) -> Result<()> { ctx.accounts.refund_and_close_vault() }
    pub fn take(ctx: Context<Take>) -> Result<()> { ctx.accounts.deposit()?; ctx.accounts.withdraw_and_close_vault() }
}

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/state/mod.rs =====
use anchor_lang::prelude::*;
#[account] #[derive(InitSpace)]
pub struct Escrow { pub seed: u64, pub maker: Pubkey, pub mint_a: Pubkey, pub mint_b: Pubkey, pub receive: u64, pub bump: u8 }

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/instructions/take.rs =====
use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken,token_interface::{close_account,transfer_checked,CloseAccount,Mint,TokenAccount,TokenInterface,TransferChecked}};
use crate::Escrow;
#[derive(Accounts)]
pub struct Take<'info> {
    #[account(mut)] pub taker: Signer<'info>,
    #[account(mut)] pub maker: SystemAccount<'info>,
    pub mint_a: InterfaceAccount<'info, Mint>,
    pub mint_b: InterfaceAccount<'info, Mint>,
    #[account(init_if_needed,payer=taker,associated_token::mint=mint_a,associated_token::authority=taker,associated_token::token_program=token_program)] pub taker_ata_a: InterfaceAccount<'info, TokenAccount>,
    #[account(mut,associated_token::mint=mint_b,associated_token::authority=taker,associated_token::token_program=token_program)] pub taker_ata_b: InterfaceAccount<'info, TokenAccount>,
    #[account(init_if_needed,payer=taker,associated_token::mint=mint_b,associated_token::authority=maker,associated_token::token_program=token_program)] pub maker_ata_b: InterfaceAccount<'info, TokenAccount>,
    #[account(mut,close=maker,has_one=mint_a,has_one=mint_b,has_one=maker,seeds=[b"escrow",maker.key().as_ref(),&escrow.seed.to_le_bytes()],bump=escrow.bump)] pub escrow: Account<'info, Escrow>,
    #[account(mut,associated_token::mint=mint_a,associated_token::authority=escrow,associated_token::token_program=token_program)] pub vault: InterfaceAccount<'info, TokenAccount>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
impl<'info> Take<'info> {
    pub fn deposit(&mut self) -> Result<()> {
        let cpi = CpiContext::new(self.token_program.to_account_info(), TransferChecked { from: self.taker_ata_b.to_account_info(), mint: self.mint_b.to_account_info(), to: self.maker_ata_b.to_account_info(), authority: self.taker.to_account_info() });
        transfer_checked(cpi, self.escrow.receive, self.mint_b.decimals)
    }
    pub fn withdraw_and_close_vault(&mut self) -> Result<()> {
        let ss: &[&[&[u8]]] = &[&[b"escrow", self.maker.to_account_info().key.as_ref(), &self.escrow.seed.to_le_bytes(), &[self.escrow.bump]]];
        let cpi = CpiContext::new_with_signer(self.token_program.to_account_info(), TransferChecked { from: self.vault.to_account_info(), mint: self.mint_a.to_account_info(), to: self.taker_ata_a.to_account_info(), authority: self.escrow.to_account_info() }, ss);
        transfer_checked(cpi, self.vault.amount, self.mint_a.decimals)?;
        close_account(CpiContext::new_with_signer(self.token_program.to_account_info(), CloseAccount { account: self.vault.to_account_info(), destination: self.maker.to_account_info(), authority: self.escrow.to_account_info() }, ss))
    }
}`;

export const DEMO_SWAP = `// ===== FILE: anchor-swap/programs/anchor-swap/Cargo.toml =====
[package]
name = "anchor-swap"
version = "0.1.0"
[dependencies]
anchor-lang = "0.28.0"
anchor-spl = "0.28.0"
`;
