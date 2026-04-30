import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec, Empty } from '@/components/ui';
import { AnalysisReport, Severity, SEV_COLOR, SEV_BG } from '@/types';

export function TaintTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  if (!report.taint_flows.length) return <Empty icon="~" text="No taint flows detected — no attacker-controlled values reached security sinks"/>;

  const sorted=[...report.taint_flows].sort((a,b)=>SEV_ORDER[a.severity]-SEV_ORDER[b.severity]);
  return (<div>
    <Sec title={`${sorted.length} Taint Flow${sorted.length>1?'s':''}`} sub="Attacker-controlled values propagating from sources to security-sensitive sinks"/>
    {sorted.map(tf=>{
      const isOpen=expanded===tf.id;
      const linkedFinding=tf.finding_id?report.findings.find(f=>f.id===tf.finding_id):null;
      return <div key={tf.id} style={{
        border:`1px solid ${SEV_COLOR[tf.severity]}25`,
        borderLeft:`3px solid ${SEV_COLOR[tf.severity]}`,
        borderRadius:16,overflow:'hidden',marginBottom:8,background:'#fff'
      }}>
        <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 16px',cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:tf.id)}>
          <span style={{fontSize:10,color:C.t3,fontWeight:500}}>{tf.id}</span>
          <Pill sev={tf.severity}/>
          <div style={{flex:1,overflow:'hidden'}}>
            <div style={{fontSize:14,fontWeight:500,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:C.txt}}>
              {tf.source.name} → {tf.sink.sink_type.replace(/_/g,' ')}
            </div>
            <div style={{fontSize:12,color:C.t3}}>in {tf.instruction}</div>
          </div>
          {linkedFinding&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.amb}12`,color:C.amb,fontWeight:500}}>→ {linkedFinding.id}</span>}
          <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
        </div>
        {isOpen&&<div style={{padding:'16px',borderTop:`1px solid ${C.bdr}`}}>
          <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:16}}>{tf.sink.description}</p>
          <div style={{display:'flex',flexDirection:'column',gap:0}}>
            {tf.path.map((hop,i)=>(
              <div key={i} style={{display:'flex',gap:12,padding:'8px 0',borderBottom:i<tf.path.length-1?`1px solid ${C.bdr}`:'none'}}>
                <div style={{display:'flex',flexDirection:'column',alignItems:'center',width:24,flexShrink:0}}>
                  <div style={{width:10,height:10,borderRadius:'50%',border:`2px solid ${i===tf.path.length-1?SEV_COLOR[tf.severity]:C.cyan}`,background:i===tf.path.length-1?SEV_COLOR[tf.severity]:'#fff',flexShrink:0}}/>
                  {i<tf.path.length-1&&<div style={{flex:1,width:1,background:C.bdr,margin:'2px 0'}}/>}
                </div>
                <div style={{flex:1}}>
                  <div style={{fontSize:11,color:C.t3,marginBottom:3}}>{hop.operation.replace(/_/g,' ')} · {hop.file.split('/').pop()}:{hop.line}</div>
                  <div style={{fontSize:13,color:i===tf.path.length-1?SEV_COLOR[tf.severity]:C.t2}}>{hop.description}</div>
                  {hop.snippet&&<pre style={{fontSize:11,background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:8,padding:'5px 10px',marginTop:6,overflow:'auto',whiteSpace:'pre-wrap',fontFamily:"'JetBrains Mono',monospace"}}>{hop.snippet}</pre>}
                </div>
              </div>
            ))}
          </div>
        </div>}
      </div>;
    })}
  </div>);
}

function Pill({sev}:{sev:Severity}) {
  return <span style={{fontSize:9,fontWeight:700,letterSpacing:'.04em',textTransform:'uppercase',padding:'3px 8px',borderRadius:100,whiteSpace:'nowrap',background:SEV_BG[sev],color:SEV_COLOR[sev],border:`1px solid ${SEV_COLOR[sev]}20`}}>{sev}</span>;
}

const SEV_ORDER: Record<string,number> = {
  CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,
};
