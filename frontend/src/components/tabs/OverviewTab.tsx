import React from 'react';
import { C } from '@/lib/constants';
import { Sec } from '@/components/ui';
import { AnalysisReport, Severity, Category, CategorySummary, CATEGORY_LABELS, SEV_BG, SEV_COLOR } from '@/types';

export function OverviewTab({report}:{report:AnalysisReport}) {
  const sc = report.summary.security_score;
  const col = sc>=70?C.grn:sc>=50?C.amb:C.red;
  const r=38,circ=2*Math.PI*r;
  return (
    <div>
      {/* Score Card */}
      <div style={{
        display:'grid',gridTemplateColumns:'auto 1fr auto',gap:32,alignItems:'center',
        background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:24,padding:32,marginBottom:28,
        boxShadow:'0 0 60px rgba(85,106,220,0.05)'
      }}>
        <div style={{position:'relative',width:100,height:100}}>
          <svg width="100" height="100" viewBox="0 0 100 100" style={{transform:'rotate(-90deg)'}}>
            <circle cx="50" cy="50" r={r} fill="none" stroke="#F0F2FF" strokeWidth="8"/>
            <circle cx="50" cy="50" r={r} fill="none" stroke={col} strokeWidth="8" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={circ-(sc/100)*circ} style={{transition:'stroke-dashoffset 1.2s ease'}}/>
          </svg>
          <div style={{position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
            <span style={{fontFamily:"'Playfair Display',serif",fontSize:30,fontWeight:700,color:col}}>{sc}</span>
            <span style={{fontSize:10,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em'}}>security</span>
          </div>
        </div>
        <div>
          <h3 style={{fontFamily:"'Playfair Display',serif",fontSize:24,fontWeight:700,marginBottom:6,color:C.txt}}>{report.summary.overall_risk} Risk</h3>
          <p style={{fontSize:14,color:C.t2,lineHeight:1.6,marginBottom:14}}>
            {report.summary.total} findings · {report.summary.chain_count} chains · {report.summary.taint_flow_count} taint flows · {report.summary.bypassable_invariant_count} bypassable invariants
          </p>
          <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
            {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as Severity[]).map(s=>{
              const cnt=(report.summary as any)[s.toLowerCase()] as number;
              if(!cnt) return null;
              return <div key={s} style={{display:'flex',alignItems:'center',gap:4,padding:'4px 12px',borderRadius:100,fontSize:12,fontWeight:600,background:SEV_BG[s],color:SEV_COLOR[s],border:`1px solid ${SEV_COLOR[s]}20`}}><b style={{fontSize:15}}>{cnt}</b>{s.charAt(0)+s.slice(1).toLowerCase()}</div>;
            })}
          </div>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:14,minWidth:180}}>
          {[
            {l:'Attack Surface',v:report.summary.attack_surface_score,col:C.red},
            {l:'Hardening',v:report.summary.hardening_score,col:C.grn},
          ].map(s=>(
            <div key={s.l}>
              <div style={{display:'flex',justifyContent:'space-between',fontSize:12,color:C.t3,marginBottom:5}}>
                <span>{s.l}</span><span style={{color:s.col,fontWeight:600}}>{s.v}/100</span>
              </div>
              <div style={{height:6,background:'#F0F2FF',borderRadius:3,overflow:'hidden'}}>
                <div style={{height:'100%',width:`${s.v}%`,background:s.col,borderRadius:3}}/>
              </div>
            </div>
          ))}
        </div>
      </div>

      <Sec title="Vulnerability Categories">
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
          {Object.entries(report.category_summary).map(([k,v])=>{
            const maxC=Math.max(...Object.values(report.category_summary).map((x:CategorySummary)=>x.count),1);
            const col2=v.max_severity==='NONE'?C.t3:SEV_COLOR[v.max_severity as Severity]||C.t3;
            return <div key={k} style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:18}}>
              <div style={{fontSize:14,fontWeight:600,marginBottom:8}}>{CATEGORY_LABELS[k as Category]||k}</div>
              <div style={{height:4,background:'#F0F2FF',borderRadius:2,overflow:'hidden',marginBottom:6}}>
                <div style={{height:'100%',width:`${Math.round(v.count/maxC*100)}%`,background:col2,borderRadius:2}}/>
              </div>
              <div style={{fontSize:12,color:C.t3}}>{v.count} · {v.max_severity}</div>
            </div>;
          })}
        </div>
      </Sec>

      <Sec title="Program Profile">
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
          {[
            {l:'Instructions',v:report.profile.instructions_count,col:C.cyan},
            {l:'Account Structs',v:report.profile.account_structs_count,col:C.amb},
            {l:'CPI Calls',v:report.profile.cpi_calls_count,col:'#FF8717'},
            {l:'Taint Flows',v:report.summary.taint_flow_count,col:report.summary.taint_flow_count>0?C.red:C.grn},
            {l:'Broken Permissions',v:report.summary.broken_permission_count,col:report.summary.broken_permission_count>0?C.red:C.grn},
            {l:'Token Anomalies',v:report.summary.token_flow_anomaly_count,col:report.summary.token_flow_anomaly_count>0?C.amb:C.grn},
            {l:'Bypassable Invariants',v:report.summary.bypassable_invariant_count,col:report.summary.bypassable_invariant_count>0?C.red:C.grn},
            {l:'PDA Derivations',v:report.profile.pda_count,col:C.pur},
            {l:'Invariants Total',v:report.summary.invariant_count,col:C.t2},
          ].map(c=>(
            <div key={c.l} style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:18}}>
              <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.06em',marginBottom:4,fontWeight:600}}>{c.l}</div>
              <div style={{fontSize:24,fontWeight:700,color:c.col,fontFamily:"'Playfair Display',serif"}}>{c.v}</div>
            </div>
          ))}
        </div>
        {report.profile.framework_patterns.length>0&&<div style={{marginTop:12,display:'flex',gap:6,flexWrap:'wrap'}}>
          {report.profile.framework_patterns.map((p:string)=><span key={p} style={{fontSize:12,padding:'4px 12px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500,border:`1px solid ${C.cyan}20`}}>{p}</span>)}
        </div>}
      </Sec>
    </div>
  );
}
