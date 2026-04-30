import React from 'react';
import { C } from '@/lib/constants';
import { Sec } from '@/components/ui';
import { AnalysisReport, Severity, SEV_COLOR, SEV_BG } from '@/types';

export function AdvisoriesTab({report}:{report:AnalysisReport}) {
  if (!report.known_vulns.length) return (
    <div style={{
      textAlign:'center',padding:60,color:C.t3,
      background:'#fff',borderRadius:24,border:`1px solid ${C.bdr}`
    }}>
      <div style={{fontSize:40,opacity:.15,marginBottom:12}}>✓</div>
      <p style={{fontSize:15,maxWidth:400,margin:'0 auto',lineHeight:1.6}}>
        Anchor {report.profile.anchor_version} has no known advisories in the database
      </p>
    </div>
  );
  return (<div>
    <Sec title={`${report.known_vulns.length} Known Advisor${report.known_vulns.length>1?'ies':'y'}`} sub={`Detected for anchor-lang ${report.profile.anchor_version}`}/>
    {report.known_vulns.map(v=>(
      <div key={v.advisory_id} style={{
        border:`1px solid ${SEV_COLOR[v.severity]}20`,
        borderLeft:`3px solid ${SEV_COLOR[v.severity]}`,
        borderRadius:20,padding:'18px 20px',background:'#fff',marginBottom:10
      }}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:10,flexWrap:'wrap'}}>
          <Pill sev={v.severity}/>
          <span style={{fontSize:16,fontWeight:600,color:C.txt}}>{v.title}</span>
          <span style={{fontSize:11,color:C.t3,fontWeight:500}}>{v.advisory_id}</span>
          {v.cve_id&&<span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500}}>{v.cve_id}</span>}
        </div>
        <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:12}}>{v.description}</p>
        <div style={{display:'flex',alignItems:'center',gap:16,flexWrap:'wrap',marginBottom:12}}>
          <span style={{fontSize:12,color:C.t3}}>Affected: <span style={{color:C.red,fontWeight:600}}>{v.affected_versions}</span></span>
          {v.fixed_in&&<span style={{fontSize:12,color:C.t3}}>Fixed: <span style={{color:C.grn,fontWeight:600}}>{v.fixed_in}</span></span>}
          <a href={v.url} target="_blank" rel="noopener noreferrer" style={{fontSize:12,color:C.cyan,textDecoration:'none',fontWeight:500}}>Advisory ↗</a>
        </div>
        <div style={{
          padding:'10px 14px',background:`${C.amb}08`,border:`1px solid ${C.amb}20`,
          borderRadius:12
        }}>
          <span style={{fontSize:13,color:C.amb,fontWeight:600}}>⬆ Upgrade to anchor-lang = &quot;{v.fixed_in||'latest'}&quot; to resolve.</span>
        </div>
      </div>
    ))}
  </div>);
}

function Pill({sev}:{sev:Severity}) {
  return <span style={{fontSize:9,fontWeight:700,letterSpacing:'.04em',textTransform:'uppercase',padding:'3px 8px',borderRadius:100,whiteSpace:'nowrap',background:SEV_BG[sev],color:SEV_COLOR[sev],border:`1px solid ${SEV_COLOR[sev]}20`}}>{sev}</span>;
}
