import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec, Empty } from '@/components/ui';
import { AnalysisReport, Severity, SEV_COLOR, SEV_BG } from '@/types';
import { generateChainPoC } from '@/lib/poc_generator';
import { Sb } from '@/lib/styles';

export function ChainsTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  const [showPoC,setShowPoC]=useState<string|null>(null);
  const [copied,setCopied]=useState<string|null>(null);
  const copy=(txt:string,k:string)=>{navigator.clipboard.writeText(txt);setCopied(k);setTimeout(()=>setCopied(null),1600);};

  if (!report.vuln_chains.length) return <Empty icon="⛓" text="No vulnerability chains — findings are not cross-exploitable"/>;
  return (<div>
    <Sec title={`${report.vuln_chains.length} Vulnerability Chain${report.vuln_chains.length>1?'s':''}`} sub="Multi-finding exploit paths — these are not individual bugs, they are complete attack scenarios"/>
    {report.vuln_chains.map(chain=>{
      const isOpen=expanded===chain.id;
      const poc=showPoC===chain.id?generateChainPoC(chain,report.findings):null;
      return <div key={chain.id} style={{
        border:`1px solid ${SEV_COLOR[chain.severity]}25`,
        borderLeft:`3px solid ${SEV_COLOR[chain.severity]}`,
        borderRadius:16,overflow:'hidden',marginBottom:8,background:'#fff'
      }}>
        <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 16px',cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:chain.id)}>
          <span style={{fontSize:10,color:C.t3,fontWeight:500}}>{chain.id}</span>
          <Pill sev={chain.severity}/>
          <span style={{fontSize:14,fontWeight:600,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:C.txt}}>{chain.title}</span>
          <span style={{fontSize:11,color:C.t3}}>{chain.finding_ids.join('+')} · {chain.instructions_involved.length} instrs</span>
          <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
        </div>
        {isOpen&&<div style={{padding:'16px',borderTop:`1px solid ${C.bdr}`}}>
          <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:16}}>{chain.description}</p>
          <div style={{marginBottom:16}}>
            <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:10,fontWeight:600}}>Exploit Path</div>
            {chain.exploit_steps.map((step,i)=>(
              <div key={i} style={{display:'flex',gap:12,padding:'6px 0',borderBottom:i<chain.exploit_steps.length-1?`1px solid ${C.bdr}`:'none'}}>
                <span style={{fontSize:11,color:SEV_COLOR[chain.severity],flexShrink:0,fontWeight:700}}>Step {i+1}</span>
                <span style={{fontSize:13,color:C.t2,lineHeight:1.5}}>{step}</span>
              </div>
            ))}
          </div>
          <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:14}}>
            {chain.finding_ids.map(id=>{
              const f=report.findings.find(f=>f.id===id);
              return <span key={id} style={{
                fontSize:11,padding:'3px 10px',borderRadius:100,
                background:f?SEV_BG[f.severity]:'#F8F9FB',
                color:f?SEV_COLOR[f.severity]:C.t3,
                border:`1px solid ${f?SEV_COLOR[f.severity]+'20':C.bdr}`
              }}>
                {id}{f?`: ${f.title.slice(0,35)}…`:''}
              </span>;
            })}
          </div>
          {chain.ai_explanation&&<div style={{
            padding:'10px 12px',background:`${C.pur}08`,border:`1px solid ${C.pur}20`,
            borderRadius:12,fontSize:13,color:C.pur,lineHeight:1.6,marginBottom:12
          }}>
            <span style={{fontSize:10,padding:'2px 8px',borderRadius:8,background:`${C.pur}15`,marginRight:10,fontWeight:600}}>AI context</span>{chain.ai_explanation}
          </div>}
          <button style={{
            ...Sb.btnSm,fontSize:12,padding:'8px 16px',width:'auto',
            background:`${SEV_COLOR[chain.severity]}12`,color:SEV_COLOR[chain.severity],
            border:`1px solid ${SEV_COLOR[chain.severity]}25`
          }}
            onClick={()=>setShowPoC(showPoC===chain.id?null:chain.id)}>
            {showPoC===chain.id?'Hide':'Generate'} Chain PoC Test
          </button>
          {poc&&<div style={{marginTop:14}}>
            <div style={{display:'flex',justifyContent:'space-between',padding:'8px 12px',background:'#F8F9FB',borderRadius:'12px 12px 0 0',border:`1px solid ${C.bdr}`,borderBottom:'none'}}>
              <span style={{fontSize:11,color:C.t3,fontFamily:"'JetBrains Mono',monospace"}}>{poc.test_name}.rs</span>
              <button style={Sb.exBtn} onClick={()=>copy(poc.code,chain.id)}>{copied===chain.id?'✓ Copied':'Copy'}</button>
            </div>
            <pre style={{
              background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderTop:'none',
              borderRadius:'0 0 12px 12px',padding:14,fontSize:12,
              overflow:'auto',maxHeight:360,whiteSpace:'pre-wrap',margin:0,
              fontFamily:"'JetBrains Mono',monospace",color:C.t2,lineHeight:1.6
            }}>{poc.code}</pre>
          </div>}
        </div>}
      </div>;
    })}
  </div>);
}

function Pill({sev}:{sev:Severity}) {
  return <span style={{fontSize:9,fontWeight:700,letterSpacing:'.04em',textTransform:'uppercase',padding:'3px 8px',borderRadius:100,whiteSpace:'nowrap',background:SEV_BG[sev],color:SEV_COLOR[sev],border:`1px solid ${SEV_COLOR[sev]}20`}}>{sev}</span>;
}
