import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec } from '@/components/ui';
import { AnalysisReport, Severity, Finding, SEV_COLOR, SEV_BG, SEV_ORDER, CATEGORY_LABELS, Category } from '@/types';
import { generatePoC } from '@/lib/poc_generator';
import { generateFixDiff, FixDiff } from '@/lib/fix_diff';
import { Sb } from '@/lib/styles';

type FindingView = 'details' | 'poc' | 'diff';

export function FindingsTab({report}:{report:AnalysisReport}) {
  const [filter,setFilter]=useState('all');
  const [sortBy,setSortBy]=useState<'severity'|'exploitability'>('severity');
  const [expanded,setExpanded]=useState<string|null>(null);
  const [fView,setFView]=useState<FindingView>('details');
  const [copied,setCopied]=useState<string|null>(null);
  const copy=(txt:string,k:string)=>{navigator.clipboard.writeText(txt);setCopied(k);setTimeout(()=>setCopied(null),1600);};

  const sorted=[...report.findings].sort((a,b)=>
    sortBy==='exploitability'?b.exploitability-a.exploitability:SEV_ORDER[a.severity]-SEV_ORDER[b.severity]
  );
  const visible=filter==='all'?sorted:sorted.filter(f=>f.severity.toLowerCase()===filter);

  return (<div>
    <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:18,flexWrap:'wrap'}}>
      <div style={{display:'flex',gap:4}}>
        {['all','critical','high','medium','low','info'].map(s=>{
          const cnt=s==='all'?report.summary.total:(report.summary as any)[s] as number;
          return <button key={s} style={{
            fontSize:12,fontWeight:600,letterSpacing:'-.01em',padding:'6px 12px',borderRadius:100,
            border:`1px solid ${filter===s?'transparent':C.bdr}`,
            background:filter===s?C.cyan:'transparent',
            color:filter===s?'#fff':C.t3,
            cursor:'pointer',fontFamily:"'Inter',sans-serif",
            transition:'all .2s'
          }} onClick={()=>setFilter(s)}>{s} ({cnt})</button>;
        })}
      </div>
      <div style={{marginLeft:'auto',display:'flex',gap:6,alignItems:'center'}}>
        <span style={{fontSize:12,color:C.t3}}>Sort:</span>
        <button style={{
          fontSize:12,padding:'5px 10px',borderRadius:8,
          border:`1px solid ${C.bdr}`,
          background:sortBy==='severity'?'#fff':'transparent',
          color:sortBy==='severity'?C.txt:C.t3,
          cursor:'pointer',fontWeight:500,
          transition:'all .2s'
        }} onClick={()=>setSortBy('severity')}>Severity</button>
        <button style={{
          fontSize:12,padding:'5px 10px',borderRadius:8,
          border:`1px solid ${C.bdr}`,
          background:sortBy==='exploitability'?'#fff':'transparent',
          color:sortBy==='exploitability'?C.txt:C.t3,
          cursor:'pointer',fontWeight:500,
          transition:'all .2s'
        }} onClick={()=>setSortBy('exploitability')}>Exploitability</button>
      </div>
    </div>

    {visible.length===0?<div style={{
      textAlign:'center',padding:40,color:C.t3,fontSize:14,
      border:`2px dashed ${C.bdr}`,borderRadius:20
    }}>No findings in this category</div>
    :<div style={{display:'flex',flexDirection:'column',gap:6}}>
      {visible.map(f=>{
        const isOpen=expanded===f.id;
        const poc=isOpen&&fView==='poc'?generatePoC(f):null;
        const diff=isOpen&&fView==='diff'?generateFixDiff(f):null;
        return <div key={f.id} style={{
          border:`1px solid ${C.bdr}`,
          borderLeft:`3px solid ${SEV_COLOR[f.severity]}`,
          borderRadius:16,overflow:'hidden',
          background:'#fff',
          transition:'all .2s'
        }}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'12px 16px',cursor:'pointer'}} onClick={()=>{setExpanded(isOpen?null:f.id);setFView('details');}}>
            <span style={{fontSize:10,color:C.t3,flexShrink:0,fontWeight:500}}>{f.id}</span>
            <Pill sev={f.severity}/>
            <span style={{fontSize:14,fontWeight:500,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:C.txt}}>{f.title}</span>
            {f.confirmed_by_taint.length>0&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.red}10`,color:C.red,fontWeight:600}}>taint ✓</span>}
            <span style={{fontSize:12,color:C.amb,flexShrink:0,fontWeight:600}}>⬆{f.exploitability}</span>
            <span style={{fontSize:11,color:C.t3,whiteSpace:'nowrap'}}>{CATEGORY_LABELS[f.category]}</span>
            <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s',flexShrink:0}}>▼</span>
          </div>
          {isOpen&&<div style={{borderTop:`1px solid ${C.bdr}`}}>
            <div style={{display:'flex',padding:'0 12px',background:'#F8F9FB'}}>
              {(['details','poc','diff'] as FindingView[]).map(v=>(
                <button key={v} style={{
                  fontSize:13,fontWeight:500,padding:'10px 14px',border:'none',background:'none',
                  cursor:'pointer',color:fView===v?C.cyan:C.t3,
                  borderBottom:`2px solid ${fView===v?C.cyan:'transparent'}`,
                  transition:'all .2s'
                }} onClick={()=>setFView(v)}>
                  {v==='poc'?'PoC Test':v==='diff'?'Fix Diff':'Details'}
                </button>
              ))}
            </div>
            <div style={{padding:'16px'}}>
              {fView==='details'&&<FindingDetails f={f} copy={copy}/>}
              {fView==='poc'&&(poc
                ? <PoCView poc={poc} id={f.id} copy={copy} copied={copied}/>
                : <div style={{padding:24,textAlign:'center',color:C.t3,fontSize:14}}>PoC not available for this finding category</div>
              )}
              {fView==='diff'&&diff&&<FixDiffView diff={diff} onCopy={copy} copied={copied}/>}
            </div>
          </div>}
        </div>;
      })}
    </div>}
  </div>);
}

function FindingDetails({f,copy}:{f:Finding;copy:(t:string,k:string)=>void}) {
  return (<>
    {f.line&&<div style={{fontSize:12,color:C.t3,marginBottom:8}}>Line {f.line} · {f.file}</div>}
    <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:14}}>{f.description}</p>
    {f.ai_explanation&&<div style={{padding:'10px 14px',background:`${C.pur}08`,border:`1px solid ${C.pur}20`,borderRadius:12,fontSize:13,color:C.pur,lineHeight:1.6,marginBottom:12}}>
      <span style={{fontSize:10,padding:'2px 8px',borderRadius:8,background:`${C.pur}15`,marginRight:10,fontWeight:600}}>AI context</span>{f.ai_explanation}
    </div>}
    {f.snippet&&<pre style={{
      background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:12,padding:'12px 14px',
      fontSize:13,marginBottom:12,whiteSpace:'pre-wrap',wordBreak:'break-all',lineHeight:1.6,
      fontFamily:"'JetBrains Mono',monospace"
    }}>{f.snippet}</pre>}
    <div style={{
      background:`${C.grn}08`,border:`1px solid ${C.grn}20`,borderRadius:12,padding:'10px 14px',
      fontSize:13,color:C.grn,lineHeight:1.6,whiteSpace:'pre-wrap',marginBottom:8
    }}>
      ✓ Fix: {f.recommendation}{f.anchor_fix?`\n\nAnchor: ${f.anchor_fix}`:''}
    </div>
    <div style={{display:'flex',gap:10,flexWrap:'wrap',marginTop:8}}>
      {f.function&&<span style={{fontSize:11,color:C.t3}}>fn: {f.function}</span>}
      {f.cwe&&<span style={{fontSize:11,padding:'2px 8px',borderRadius:8,background:`${C.cyan}10`,border:`1px solid ${C.cyan}20`,color:C.cyan,fontWeight:500}}>{f.cwe}</span>}
      <span style={{fontSize:11,color:C.amb,fontWeight:600}}>exploitability: {f.exploitability}/100</span>
    </div>
  </>);
}

function PoCView({poc,id,copy,copied}:{poc:ReturnType<typeof generatePoC>;id:string;copy:(t:string,k:string)=>void;copied:string|null}) {
  return (
    <div>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:12}}>
        <div>
          <p style={{fontSize:14,fontWeight:600,marginBottom:4}}>Proves: {poc!.proves}</p>
          <p style={{fontSize:13,color:C.grn}}>After fix → {poc!.fix_assertion}</p>
        </div>
        <button style={Sb.exBtn} onClick={()=>copy(poc!.code,id)}>{copied===id?'✓ Copied':'Copy'}</button>
      </div>
      <pre style={{
        background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:12,padding:16,
        fontSize:13,overflow:'auto',maxHeight:400,whiteSpace:'pre-wrap',margin:0,
        fontFamily:"'JetBrains Mono',monospace",color:C.t2,lineHeight:1.6
      }}>{poc!.code}</pre>
      <div style={{marginTop:10}}>
        <p style={{fontSize:12,color:C.t3,marginBottom:4}}>Add to Cargo.toml [dev-dependencies]:</p>
        {poc!.deps.map(d=><code key={d} style={{
          display:'block',fontSize:12,fontFamily:"'JetBrains Mono',monospace",
          color:C.t2,background:'#F8F9FB',padding:'3px 10px',borderRadius:6,marginBottom:3
        }}>{d}</code>)}
      </div>
    </div>
  );
}

function FixDiffView({diff,onCopy,copied}:{diff:FixDiff;onCopy:(c:string,k:string)=>void;copied:string|null}) {
  const lineStyle=(type:string):React.CSSProperties=>({
    background:type==='removed'?`${C.red}08`:type==='added'?`${C.grn}08`:type==='annotation'?`${C.cyan}06`:'transparent',
    borderLeft:`3px solid ${type==='removed'?C.red:type==='added'?C.grn:type==='annotation'?C.cyan:'transparent'}`,
    color:type==='removed'?C.red:type==='added'?C.grn:type==='annotation'?C.cyan:C.t2,
    padding:'2px 10px 2px 12px',fontSize:13,lineHeight:1.6,
    display:'flex',gap:10,alignItems:'flex-start',whiteSpace:'pre-wrap',wordBreak:'break-all',
    fontFamily:"'JetBrains Mono',monospace"
  });
  const pfx=(t:string)=>t==='removed'?'-':t==='added'?'+':t==='annotation'?'#':' ';
  const afterCode=diff.after_lines.map(l=>`${pfx(l.type)} ${l.content}`).join('\n');
  return (<div>
    <p style={{fontSize:14,color:C.t2,lineHeight:1.6,marginBottom:16}}>{diff.change_summary}</p>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:12}}>
      {[{lines:diff.before_lines,label:diff.before_label,col:C.red},{lines:diff.after_lines,label:diff.after_label,col:C.grn}].map((side,si)=>(
        <div key={si}>
          <div style={{display:'flex',justifyContent:'space-between',padding:'8px 12px',background:`${side.col}08`,borderRadius:'12px 12px 0 0',border:`1px solid ${side.col}20`,borderBottom:'none'}}>
            <span style={{fontSize:11,color:side.col,fontWeight:700}}>{side.label}</span>
            {si===1&&<button style={Sb.exBtn} onClick={()=>onCopy(afterCode,'diff-'+diff.finding_id)}>{copied==='diff-'+diff.finding_id?'✓ Copied':'Copy fixed'}</button>}
          </div>
          <div style={{
            background:'#F8F9FB',border:`1px solid ${side.col}20`,borderTop:'none',
            borderRadius:'0 0 12px 12px',overflow:'auto',maxHeight:300
          }}>
            {side.lines.map((line,i)=>(
              <div key={i} style={lineStyle(line.type)}>
                <span style={{opacity:.4,flexShrink:0,minWidth:14}}>{pfx(line.type)}</span>
                <span style={{flex:1}}>{line.content}</span>
                {line.annotation&&<span style={{fontSize:10,fontStyle:'italic',whiteSpace:'nowrap',marginLeft:10,opacity:.8}}>← {line.annotation}</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
    {diff.cargo_change&&<div style={{padding:'12px 14px',background:`${C.cyan}08`,border:`1px solid ${C.cyan}20`,borderRadius:12,fontSize:13,color:C.cyan,whiteSpace:'pre-wrap',fontFamily:"'JetBrains Mono',monospace",lineHeight:1.6}}>📦 Also update Cargo.toml:\n{diff.cargo_change}</div>}
  </div>);
}

function Pill({sev}:{sev:Severity}) {
  return <span style={{
    fontSize:9,fontWeight:700,letterSpacing:'.04em',textTransform:'uppercase',
    padding:'3px 8px',borderRadius:100,whiteSpace:'nowrap',
    background:SEV_BG[sev],color:SEV_COLOR[sev],
    border:`1px solid ${SEV_COLOR[sev]}20`
  }}>{sev}</span>;
}
