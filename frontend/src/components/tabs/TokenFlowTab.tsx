import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec, Empty } from '@/components/ui';
import { AnalysisReport, TRUST_COLOR, SEV_COLOR, SEV_BG } from '@/types';

export function TokenFlowTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  const tf = report.token_flow;
  if (!tf) return <Empty icon="⟳" text="No token flow data — no token accounts detected"/>;

  const movColor: Record<string,string> = {
    deposit:C.grn, withdrawal:C.red, swap:C.cyan, internal_transfer:C.t2,
    fee_collection:C.amb, account_close:'#FF8717', mint:C.red, burn:C.pur,
  };
  const movLabel: Record<string,string> = {
    deposit:'Deposit', withdrawal:'Withdrawal', swap:'Swap', internal_transfer:'Internal',
    fee_collection:'Fee', account_close:'Close', mint:'Mint', burn:'Burn',
  };

  return (<div>
    {tf.anomalies.length>0&&<>
      <Sec title={`${tf.anomalies.length} Flow Anomal${tf.anomalies.length>1?'ies':'y'}`} sub="Patterns in the token lifecycle that indicate potential vulnerabilities"/>
      {tf.anomalies.map(a=>{
        const col = a.severity==='CRITICAL'?C.red:a.severity==='HIGH'?C.amb:C.cyan;
        return <div key={a.id} style={{
          padding:'16px',background:'#fff',border:`1px solid ${col}25`,
          borderLeft:`3px solid ${col}`,borderRadius:16,marginBottom:10
        }}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
            <span style={{fontSize:10,fontWeight:700,padding:'3px 8px',borderRadius:100,background:`${col}12`,color:col}}>{a.severity}</span>
            <span style={{fontSize:12,color:C.t3,fontWeight:500}}>{a.anomaly_type.replace(/_/g,' ')}</span>
            <span style={{fontSize:11,color:C.t3,marginLeft:'auto'}}>{a.edge_ids.join(', ')}</span>
          </div>
          <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:10}}>{a.description}</p>
          <div style={{
            padding:'8px 12px',background:`${C.grn}08`,border:`1px solid ${C.grn}20`,
            borderRadius:12,fontSize:13,color:C.grn,lineHeight:1.5
          }}>
            ✓ {a.recommendation}
          </div>
        </div>;
      })}
    </>}

    <Sec title={`${tf.nodes.length} Token Account${tf.nodes.length!==1?'s':''}`} sub="Every token account detected — role, trust level, which instructions use it"/>
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12,marginBottom:28}}>
      {tf.nodes.map(n=>(
        <div key={n.id} style={{
          background:'#fff',border:`1px solid ${C.bdr}`,
          borderLeft:`3px solid ${TRUST_COLOR[n.trust as keyof typeof TRUST_COLOR]||C.t3}`,
          borderRadius:16,padding:'14px 16px'
        }}>
          <div style={{fontSize:15,fontWeight:600,color:C.txt,marginBottom:6}}>{n.account_name}</div>
          <div style={{fontSize:12,color:C.t3,marginBottom:6}}>
            {n.role} {n.is_pda?'· PDA':''}
          </div>
          {n.mint&&<div style={{fontSize:12,color:C.t3,marginBottom:6}}>mint: {n.mint}</div>}
          <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
            {n.instructions_used_in.map(i=>(
              <span key={i} style={{fontSize:10,padding:'2px 8px',borderRadius:8,background:`${C.cyan}10`,color:C.cyan,fontWeight:500}}>{i}</span>
            ))}
          </div>
        </div>
      ))}
    </div>

    <Sec title={`${tf.edges.length} Token Movement${tf.edges.length!==1?'s':''}`} sub="Every transfer, mint, burn, and close — with full authorization context"/>
    <div style={{display:'flex',flexDirection:'column',gap:6}}>
      {tf.edges.map(e=>{
        const isOpen=expanded===e.id;
        const mCol=movColor[e.movement_type]||C.t2;
        const mLbl=movLabel[e.movement_type]||e.movement_type;
        return <div key={e.id} style={{
          border:`1px solid ${C.bdr}`,borderLeft:`3px solid ${mCol}`,
          borderRadius:16,overflow:'hidden',background:'#fff'
        }}>
          <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 16px',cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:e.id)}>
            <span style={{fontSize:10,color:C.t3,fontWeight:500,flexShrink:0}}>{e.id}</span>
            <span style={{fontSize:10,fontWeight:700,padding:'3px 8px',borderRadius:100,background:`${mCol}12`,color:mCol,whiteSpace:'nowrap'}}>{mLbl}</span>
            <div style={{display:'flex',alignItems:'center',gap:6,flex:1,overflow:'hidden',minWidth:0}}>
              <span style={{fontSize:12,color:C.t2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.from_account}</span>
              <span style={{color:C.t3,flexShrink:0}}>→</span>
              <span style={{fontSize:12,color:C.t2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.to_account}</span>
            </div>
            <span style={{fontSize:11,color:C.t3,whiteSpace:'nowrap',flexShrink:0}}>{e.instruction}</span>
            {!e.is_guarded&&!e.uses_pda_signer&&matches(e.movement_type,['withdrawal','account_close'])&&(
              <span style={{fontSize:9,padding:'2px 7px',borderRadius:100,background:`${C.red}10`,color:C.red,fontWeight:600,flexShrink:0}}>⚠ unguarded</span>
            )}
            <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s',flexShrink:0}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'16px',borderTop:`1px solid ${C.bdr}`}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,marginBottom:12}}>
              <div>
                <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.06em',marginBottom:8,fontWeight:600}}>Authorization</div>
                <div style={{fontSize:13,color:C.t2,lineHeight:1.6}}>
                  {e.authorization.constraint_text}
                </div>
                <div style={{marginTop:8,display:'flex',gap:6,flexWrap:'wrap'}}>
                  {e.uses_pda_signer&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.grn}10`,color:C.grn,fontWeight:500}}>PDA signer</span>}
                  {e.authorization.requires_signer&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500}}>signature required</span>}
                  {e.is_guarded&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.grn}10`,color:C.grn,fontWeight:500}}>require! guarded</span>}
                  {!e.is_guarded&&!e.uses_pda_signer&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.red}10`,color:C.red,fontWeight:500}}>no guard</span>}
                </div>
              </div>
              <div>
                <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.06em',marginBottom:8,fontWeight:600}}>Amount Source</div>
                <div style={{fontSize:13,color:C.t2}}>{e.amount_source}</div>
                {e.preconditions.length>0&&<div style={{marginTop:10}}>
                  <div style={{fontSize:11,color:C.t3,marginBottom:6,fontWeight:600}}>Guards:</div>
                  {e.preconditions.map((p,i)=><code key={i} style={{display:'block',fontSize:12,fontFamily:"'JetBrains Mono',monospace",color:C.grn,marginBottom:3}}>{p}</code>)}
                </div>}
              </div>
            </div>
            {e.snippet&&<pre style={{
              background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:12,
              padding:'10px 12px',fontSize:12,overflow:'auto',maxHeight:160,
              whiteSpace:'pre-wrap',lineHeight:1.6,fontFamily:"'JetBrains Mono',monospace"
            }}>{e.snippet}</pre>}
          </div>}
        </div>;
      })}
    </div>
  </div>);
}

function matches(val: string, list: string[]): boolean {
  return list.includes(val);
}
