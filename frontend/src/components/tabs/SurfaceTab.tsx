import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec } from '@/components/ui';
import { AnalysisReport, COMPLEXITY_LABEL, TRUST_COLOR, TRUST_LABEL, TRUST_RISK } from '@/types';

export function SurfaceTab({report}:{report:AnalysisReport}) {
  const [selInstr,setSelInstr]=useState<string|null>(null);
  const instrNodes=report.call_graph.nodes.filter(n=>n.node_type==='instruction');
  const active=selInstr||instrNodes[0]?.id||null;
  const trustForInstr=active?(report.data_flow.trust_map[active]||{}):{};
  const edges=report.call_graph.edges.filter(e=>e.from===active||e.to===active);
  const shared=report.data_flow.shared_accounts;

  return (<div>
    <Sec title="Attack Surface Map" sub="Per-instruction trust classification + call graph"/>

    <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:24}}>
      {instrNodes.map(n=>{
        const scoreCol=n.attack_surface_score>30?C.red:n.attack_surface_score>15?C.amb:C.grn;
        return <button key={n.id}
          style={{
            fontSize:12,fontWeight:600,padding:'7px 14px',borderRadius:12,
            border:`1px solid ${n.id===active?C.cyan:C.bdr}`,
            background:n.id===active?`${C.cyan}10`:'#fff',
            cursor:'pointer',
            color:n.id===active?C.cyan:C.t2,
            transition:'all .2s',
            display:'flex',alignItems:'center',gap:8
          }}
          onClick={()=>setSelInstr(n.id)}>
          {n.id}
          <span style={{fontSize:10,color:scoreCol,fontWeight:600}}>⬆{n.attack_surface_score}</span>
        </button>;
      })}
    </div>

    {active&&<>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,marginBottom:24}}>
        <div style={{background:'#fff',borderRadius:20,border:`1px solid ${C.bdr}`,padding:20}}>
          <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:12,fontWeight:600}}>Account Trust — `{active}`</div>
          {Object.keys(trustForInstr).length===0
            ? <div style={{fontSize:13,color:C.t3,padding:16,background:'#F8F9FB',borderRadius:12,textAlign:'center'}}>No trust data</div>
            : <div style={{display:'flex',flexDirection:'column',gap:6}}>
              {Object.entries(trustForInstr).sort(([,a],[,b])=>TRUST_RISK[b]-TRUST_RISK[a]).map(([acct,trust])=>(
                <div key={acct} style={{
                  display:'flex',alignItems:'center',gap:10,padding:'8px 12px',
                  background:'#F8F9FB',borderRadius:10,
                  borderLeft:`3px solid ${TRUST_COLOR[trust]}`
                }}>
                  <span style={{fontSize:13,flex:1,fontFamily:"'JetBrains Mono',monospace"}}>{acct}</span>
                  <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${TRUST_COLOR[trust]}12`,color:TRUST_COLOR[trust],fontWeight:600,whiteSpace:'nowrap'}}>{TRUST_LABEL[trust]}</span>
                </div>
              ))}
            </div>
          }
        </div>
        <div style={{background:'#fff',borderRadius:20,border:`1px solid ${C.bdr}`,padding:20}}>
          <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:12,fontWeight:600}}>CPI Calls from `{active}`</div>
          {edges.filter(e=>e.from===active).length===0
            ? <div style={{fontSize:13,color:C.t3,padding:16,background:'#F8F9FB',borderRadius:12,textAlign:'center'}}>No CPI calls detected</div>
            : edges.filter(e=>e.from===active).map((e,i)=>(
              <div key={i} style={{
                padding:'10px 12px',background:'#F8F9FB',borderRadius:10,marginBottom:6,
                border:`1px solid ${C.bdr}`
              }}>
                <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:6}}>
                  <span style={{fontSize:12,fontWeight:600,color:C.cyan}}>{e.to.split('::').pop()}</span>
                  <span style={{fontSize:10,padding:'2px 7px',borderRadius:8,background:`${C.cyan}10`,color:C.cyan,fontWeight:500}}>{e.cpi_type}</span>
                  {e.uses_pda_signer&&<span style={{fontSize:10,color:C.grn,fontWeight:500}}>PDA signer</span>}
                </div>
                <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                  {e.accounts_passed.slice(0,4).map(a=>(
                    <span key={a.account_name} style={{fontSize:9,padding:'1px 6px',borderRadius:6,background:`${TRUST_COLOR[a.trust]}10`,color:TRUST_COLOR[a.trust]}}>{a.account_name}</span>
                  ))}
                </div>
              </div>
            ))
          }
        </div>
      </div>

      {instrNodes.find(n=>n.id===active)&&(() => {
        const node=instrNodes.find(n=>n.id===active)!;
        const fp=node.attacker_footprint;
        return <div style={{padding:'16px 18px',background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:20,marginBottom:24}}>
          <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:12,fontWeight:600}}>Minimum attacker footprint for `{active}`</div>
          <div style={{display:'flex',gap:28,flexWrap:'wrap'}}>
            {[
              {l:'Keypairs required',v:fp.required_keypairs,col:C.red},
              {l:'Minimum SOL',v:`~${fp.required_sol.toFixed(3)}`,col:C.amb},
              {l:'Exploit complexity',v:COMPLEXITY_LABEL[fp.complexity],col:fp.complexity==='trivial'?C.red:fp.complexity==='low'?C.amb:fp.complexity==='medium'?C.cyan:C.grn},
              {l:'On-chain setup',v:fp.on_chain_setup?'Required':'No',col:fp.on_chain_setup?C.red:C.grn},
            ].map(f=>(
              <div key={f.l}>
                <div style={{fontSize:11,color:C.t3,marginBottom:3}}>{f.l}</div>
                <div style={{fontSize:20,fontWeight:700,color:f.col,fontFamily:"'Playfair Display',serif"}}>{f.v}</div>
              </div>
            ))}
          </div>
        </div>;
      })()}
    </>}

    {shared.length>0&&<>
      <Sec title="Shared Accounts" sub="Used across multiple instructions — trust inconsistency = privilege escalation risk"/>
      {shared.map(sa=>(
        <div key={sa.account_name} style={{
          padding:'14px 16px',background:'#fff',
          border:`1px solid ${sa.trust_inconsistent?C.amb:C.bdr}`,
          borderRadius:16,marginBottom:8
        }}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
            <span style={{fontSize:15,fontWeight:600,color:C.txt}}>{sa.account_name}</span>
            {sa.trust_inconsistent&&<span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${C.amb}12`,color:C.amb,fontWeight:600}}>⚠ trust inconsistent</span>}
            <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${TRUST_COLOR[sa.max_trust_risk]}10`,color:TRUST_COLOR[sa.max_trust_risk],fontWeight:500}}>max: {TRUST_LABEL[sa.max_trust_risk]}</span>
          </div>
          <div style={{display:'flex',gap:5,flexWrap:'wrap'}}>
            {sa.used_in.map(i=><span key={i} style={{fontSize:11,padding:'3px 10px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500,border:`1px solid ${C.cyan}15`}}>{i}</span>)}
          </div>
          {sa.trust_inconsistent&&<p style={{fontSize:13,color:C.amb,marginTop:8,lineHeight:1.6}}>Attacker exploiting a weaker instruction may position for a stronger one.</p>}
        </div>
      ))}
    </>}
  </div>);
}
