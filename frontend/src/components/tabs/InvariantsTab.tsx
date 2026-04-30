import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec, Empty } from '@/components/ui';
import { AnalysisReport, InvariantStatus, INVARIANT_COLOR, INVARIANT_LABEL } from '@/types';

export function InvariantsTab({report}:{report:AnalysisReport}) {
  const [filter,setFilter]=useState<string>('all');
  const [expanded,setExpanded]=useState<string|null>(null);
  if (!report.invariants.length) return <Empty icon="∀" text="No require!() calls found — or no files were analyzed"/>;

  const filtered = filter==='all' ? report.invariants
    : report.invariants.filter(i=>i.status===filter);

  const counts = {
    bypassable: report.invariants.filter(i=>i.status==='bypassable').length,
    incomplete: report.invariants.filter(i=>i.status==='incomplete').length,
    ordering_risk: report.invariants.filter(i=>i.status==='ordering_risk').length,
    holds: report.invariants.filter(i=>i.status==='holds').length,
  };

  return (<div>
    <Sec title={`${report.invariants.length} Invariants`} sub="Every require!() in the program — with bypass analysis"/>
    <div style={{display:'flex',gap:6,marginBottom:20,flexWrap:'wrap'}}>
      {(['all','bypassable','incomplete','ordering_risk','holds'] as const).map(s=>{
        const cnt=s==='all'?report.invariants.length:counts[s]??0;
        const isActive=filter===s;
        const isAll=s==='all';
        return <button key={s} style={{
          fontSize:12,fontWeight:600,textTransform:'none',letterSpacing:'-.01em',
          padding:'6px 12px',borderRadius:100,
          border:`1px solid ${isActive?'transparent':C.bdr}`,
          background:isActive?(isAll?C.cyan:INVARIANT_COLOR[s]):'transparent',
          color:isActive?'#fff':C.t3,
          cursor:'pointer',fontFamily:"'Inter',sans-serif",
          transition:'all .2s'
        }} onClick={()=>setFilter(s)}>
          {s.replace('_',' ')} ({cnt})
        </button>;
      })}
    </div>
    <div style={{display:'flex',flexDirection:'column',gap:6}}>
      {filtered.map(inv=>{
        const isOpen=expanded===inv.id;
        const col=INVARIANT_COLOR[inv.status];
        return <div key={inv.id} style={{
          border:`1px solid ${col}20`,
          borderLeft:`3px solid ${col}`,
          borderRadius:16,overflow:'hidden',background:'#fff'
        }}>
          <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 16px',cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:inv.id)}>
            <span style={{fontSize:10,color:C.t3,fontWeight:500}}>{inv.id}</span>
            <span style={{fontSize:9,fontWeight:700,padding:'2px 8px',borderRadius:100,background:`${col}12`,color:col,whiteSpace:'nowrap'}}>{INVARIANT_LABEL[inv.status]}</span>
            {inv.taint_confirmed&&<span style={{fontSize:9,padding:'2px 7px',borderRadius:100,background:`${C.red}10`,color:C.red,fontWeight:600}}>taint confirmed</span>}
            <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:C.t2}}>{inv.condition}</span>
            <span style={{fontSize:11,color:C.t3,whiteSpace:'nowrap'}}>{inv.instruction}</span>
            <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'16px',borderTop:`1px solid ${C.bdr}`}}>
            <div style={{fontSize:12,color:C.t3,marginBottom:10}}>
              {inv.file.split('/').pop()}:{inv.line} · protects: {inv.protects}
            </div>
            <pre style={{
              background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:12,
              padding:'10px 12px',fontSize:12,marginBottom:12,whiteSpace:'pre-wrap',
              fontFamily:"'JetBrains Mono',monospace"
            }}>{inv.snippet}</pre>
            {inv.bypass_path&&<div style={{
              padding:'12px 14px',background:`${C.red}08`,border:`1px solid ${C.red}20`,
              borderRadius:12,fontSize:14,color:C.red,lineHeight:1.6
            }}>
              ⚠ {inv.bypass_path}
            </div>}
          </div>}
        </div>;
      })}
    </div>
  </div>);
}
