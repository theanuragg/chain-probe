import React from 'react';

export const C = {
  bg: '#05070A', bg2: '#080C12', surf: '#111820',
  txt: '#DDE4F0', t2: '#7A8599', t3: '#3D4A5C',
  bdr: 'rgba(255,255,255,.06)',
  cyan: '#00C8E8', grn: '#00D98A', red: '#FF3D5C',
  amb: '#FFAA33', blu: '#3D8EFF', pur: '#9D7AFF',
};

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ background: C.bg, color: C.txt, fontFamily: "'Outfit',sans-serif", minHeight: '100vh', overflowX: 'hidden' }}>
      {children}
    </div>
  );
}

export function TopBar({ onHome, onDiff }: { onHome?: () => void; onDiff?: () => void } = {}) {
  return (
    <nav style={{ position: 'fixed', top: 0, left: 0, right: 0, zIndex: 200, padding: '13px 44px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', backdropFilter: 'blur(24px)', background: 'rgba(5,7,10,.92)', borderBottom: `1px solid ${C.bdr}` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }} onClick={onHome}>
        <div style={{ width: 27, height: 27, border: `1.5px solid ${C.cyan}`, borderRadius: 5, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontFamily: "'Bebas Neue',sans-serif", fontSize: 12, color: C.cyan }}>CP</span>
        </div>
        <span style={{ fontFamily: "'Bebas Neue',sans-serif", fontSize: 18, letterSpacing: '.08em' }}>Chain<span style={{ color: C.cyan }}>Probe</span></span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {onDiff && (
          <button style={{ fontSize: 9, fontWeight: 700, padding: '4px 12px', borderRadius: 4, border: `1px solid ${C.pur}40`, background: 'transparent', cursor: 'pointer', color: C.pur, fontFamily: "'Outfit',sans-serif" }} onClick={onDiff}>
            ⇄ Compare
          </button>
        )}
        <span style={{ fontSize: 9, color: C.t3, fontFamily: 'monospace', padding: '3px 10px', border: `1px solid ${C.bdr}`, borderRadius: 100 }}>v4 · no AI detection</span>
      </div>
    </nav>
  );
}

export const Sb: Record<string, React.CSSProperties> = {
  field: { width: '100%', background: C.bg, border: `1px solid ${C.bdr}`, borderRadius: 4, padding: '8px 10px', fontFamily: 'monospace', fontSize: 11, color: C.txt, outline: 'none', marginBottom: 6 },
  btnSm: { width: '100%', fontSize: 10, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: C.bg, background: C.cyan, padding: 8, borderRadius: 4, border: 'none', cursor: 'pointer', fontFamily: "'Outfit',sans-serif" },
  btnP: { display: 'inline-flex', alignItems: 'center', fontSize: 12, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: C.bg, background: C.cyan, padding: '13px 26px', borderRadius: 4, border: 'none', cursor: 'pointer', fontFamily: "'Outfit',sans-serif" },
  exBtn: { fontSize: 9, padding: '3px 9px', borderRadius: 3, border: `1px solid ${C.bdr}`, background: 'transparent', cursor: 'pointer', color: C.t3, fontFamily: 'monospace' },
  runBtn: { width: '100%', fontSize: 11, fontWeight: 800, letterSpacing: '.1em', textTransform: 'uppercase', color: C.bg, background: C.cyan, padding: 11, borderRadius: 4, border: 'none', cursor: 'pointer', fontFamily: "'Outfit',sans-serif" },
  rbBtn: { fontSize: 10, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', padding: '8px 13px', borderRadius: 4, cursor: 'pointer', fontFamily: "'Outfit',sans-serif" },
};

export function SLabel({ children, extra }: { children: React.ReactNode; extra?: React.ReactNode }) {
  return (
    <div style={{ fontFamily: 'monospace', fontSize: 9, color: C.t3, letterSpacing: '.12em', textTransform: 'uppercase', marginBottom: 8, display: 'flex', alignItems: 'center' }}>
      {children}{extra}
    </div>
  );
}

export function Sec({ title, sub, children }: { title: string; sub?: string; children?: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ fontFamily: 'monospace', fontSize: 9, fontWeight: 500, color: C.t3, letterSpacing: '.12em', textTransform: 'uppercase', marginBottom: sub ? 2 : 10, paddingBottom: 8, borderBottom: `1px solid ${C.bdr}` }}>{title}</div>
      {sub && <div style={{ fontSize: 10, color: C.t3, fontFamily: 'monospace', marginBottom: 10 }}>{sub}</div>}
      {children}
    </div>
  );
}

export function Empty({ icon, text }: { icon: string; text: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '60px 20px', color: C.t3, fontFamily: 'monospace' }}>
      <div style={{ fontSize: 28, opacity: 0.12, marginBottom: 10 }}>{icon}</div>
      {text}
    </div>
  );
}