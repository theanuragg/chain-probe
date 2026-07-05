"use client";
import React from 'react';
import { C } from '@/lib/constants';
import { Sb } from '@/lib/styles';
import { AnalysisReport, SEV_COLOR, SEV_BG, PERF_CATEGORY_LABELS } from '@/types';
import { ChevronDown, ChevronRight, Zap } from 'lucide-react';
import type { PerfCategory } from '@/types';

interface Props { report: AnalysisReport; }

function Gauge({ value, label }: { value: number; label: string }) {
  const r = 40;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  const color = value >= 80 ? '#00D98A' : value >= 60 ? '#3D8EFF' : value >= 40 ? '#FFAA33' : '#FF3D5C';
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:6}}>
      <svg width={100} height={100} viewBox="0 0 100 100">
        <circle cx={50} cy={50} r={r} fill="none" stroke="#F0F2FF" strokeWidth={8}/>
        <circle cx={50} cy={50} r={r} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={circ} strokeDashoffset={offset}
          transform="rotate(-90 50 50)" strokeLinecap="round"
          style={{transition:'stroke-dashoffset 1s ease'}}
        />
        <text x={50} y={52} textAnchor="middle" dominantBaseline="central"
          fill={C.txt} fontSize={18} fontWeight={700} fontFamily="'Inter',sans-serif">
          {value}
        </text>
      </svg>
      <span style={{fontSize:12,fontWeight:500,color:C.t3}}>{label}</span>
    </div>
  );
}

function CuBar({ estimate, maxCu }: { estimate: {name:string;total_cu:number;cpi_cu:number;compute_cu:number;account_cu:number;budget_pct:number}; maxCu: number }) {
  const pct = Math.min(estimate.budget_pct, 100);
  const color = pct > 80 ? '#FF3D5C' : pct > 50 ? '#FFAA33' : '#3D8EFF';
  const width = maxCu > 0 ? (estimate.total_cu / maxCu) * 100 : 0;
  return (
    <div style={{marginBottom:8}}>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:4}}>
        <span style={{fontSize:12,fontWeight:600,color:C.txt,fontFamily:"'Inter',sans-serif"}}>{estimate.name}</span>
        <span style={{fontSize:11,color:C.t3}}>{estimate.total_cu.toLocaleString()} CU ({pct.toFixed(0)}%)</span>
      </div>
      <div style={{height:20,background:'#F0F2FF',borderRadius:6,overflow:'hidden',display:'flex'}}>
        {estimate.cpi_cu > 0 && <div style={{width:`${(estimate.cpi_cu/estimate.total_cu)*100}%`,background:'#FF3D5C',height:'100%',minWidth:4}} title={`CPI: ${estimate.cpi_cu.toLocaleString()} CU`}/>}
        {estimate.compute_cu > 0 && <div style={{width:`${(estimate.compute_cu/estimate.total_cu)*100}%`,background:'#3D8EFF',height:'100%',minWidth:4}} title={`Compute: ${estimate.compute_cu.toLocaleString()} CU`}/>}
        {estimate.account_cu > 0 && <div style={{width:`${(estimate.account_cu/estimate.total_cu)*100}%`,background:'#9D7AFF',height:'100%',minWidth:4}} title={`Account: ${estimate.account_cu.toLocaleString()} CU`}/>}
      </div>
      <div style={{display:'flex',gap:16,marginTop:2}}>
        <span style={{fontSize:10,color:C.t3}}>CPI: {estimate.cpi_cu.toLocaleString()}</span>
        <span style={{fontSize:10,color:C.t3}}>Compute: {estimate.compute_cu.toLocaleString()}</span>
        <span style={{fontSize:10,color:C.t3}}>Account: {estimate.account_cu.toLocaleString()}</span>
      </div>
    </div>
  );
}

function PerfCard({ issue, expanded, onToggle }: {
  issue: import('@/types').PerfIssue;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div style={{
      background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:12,
      marginBottom:8,overflow:'hidden',transition:'all .2s'
    }}>
      <button onClick={onToggle} style={{
        display:'flex',alignItems:'center',gap:8,padding:'12px 16px',
        width:'100%',border:'none',background:'none',cursor:'pointer',
        fontFamily:"'Inter',sans-serif",textAlign:'left',fontSize:13
      }}>
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span style={{
          fontSize:10,fontWeight:600,padding:'2px 8px',borderRadius:100,
          background:SEV_BG[issue.severity],color:SEV_COLOR[issue.severity],
          fontFamily:"'Inter',sans-serif"
        }}>{issue.severity}</span>
        <span style={{flex:1,fontWeight:600,color:C.txt,fontSize:13}}>{issue.title}</span>
        <span style={{fontSize:10,color:C.t3}}>
          {PERF_CATEGORY_LABELS[issue.category as PerfCategory] || issue.category}
        </span>
        <span style={{fontSize:10,color:C.red,fontWeight:600}}>~{issue.cu_impact.toLocaleString()} CU</span>
      </button>
      {expanded && (
        <div style={{padding:'8px 16px 14px 42px'}}>
          <p style={{fontSize:12,color:C.t2,lineHeight:1.6,marginBottom:8}}>{issue.description}</p>
          <div style={{
            background:'#F8F9FB',borderRadius:8,padding:10,
            fontFamily:"'JetBrains Mono',monospace",fontSize:11,
            color:C.t3,border:`1px solid ${C.bdr}`,
            lineHeight:1.5,whiteSpace:'pre-wrap'
          }}>{issue.file}{issue.line ? `:${issue.line}` : ''}</div>
          <p style={{fontSize:12,color:C.cyan,marginTop:8,fontWeight:500}}>{issue.recommendation}</p>
        </div>
      )}
    </div>
  );
}

export function ProfilerTab({ report }: Props) {
  const [expanded, setExpanded] = React.useState<Record<string,boolean>>({});
  const toggle = (id: string) => setExpanded(p => ({...p, [id]: !p[id]}));

  const { profile, performance_issues } = report;
  const perInstr = profile.per_instruction_cu || [];
  const maxCu = perInstr.length > 0 ? Math.max(...perInstr.map(i => i.total_cu)) : 0;
  const avgPct = perInstr.length > 0
    ? perInstr.reduce((s,i) => s + i.budget_pct, 0) / perInstr.length
    : 0;

  return (
    <div>
      {/* Header */}
      <div style={{marginBottom:24}}>
        <h2 style={{fontFamily:"var(--font-serif)",fontSize:22,fontWeight:700,color:C.txt,marginBottom:4}}>
          Compute & Performance
        </h2>
        <p style={{fontSize:13,color:C.t3}}>
          Estimated compute unit consumption and optimization opportunities
        </p>
      </div>

      {/* Score + Summary Cards */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 2fr',gap:16,marginBottom:24}}>
        <div style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:24,display:'flex',flexDirection:'column',alignItems:'center'}}>
          <Gauge value={profile.performance_score} label="Performance Score" />
          <div style={{marginTop:12,textAlign:'center'}}>
            <div style={{fontSize:24,fontWeight:700,color:C.txt,fontFamily:"'Inter',sans-serif"}}>
              {(profile.estimated_compute_units ?? 0).toLocaleString()}
            </div>
            <div style={{fontSize:11,color:C.t3}}>Estimated Total CU</div>
          </div>
        </div>

        <div style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:20}}>
          <h3 style={{fontSize:13,fontWeight:600,color:C.txt,marginBottom:12,fontFamily:"'Inter',sans-serif"}}>
            Instruction CU Breakdown
          </h3>
          {perInstr.length === 0 ? (
            <p style={{fontSize:12,color:C.t3}}>No instruction data available</p>
          ) : (
            perInstr.map(est => <CuBar key={est.name} estimate={est} maxCu={maxCu} />)
          )}
          {perInstr.length > 0 && (
            <div style={{marginTop:8,borderTop:`1px solid ${C.bdr}`,paddingTop:8}}>
              <div style={{display:'flex',gap:16,fontSize:11,color:C.t3}}>
                <span><span style={{color:'#FF3D5C',fontWeight:600}}>■</span> CPI calls</span>
                <span><span style={{color:'#3D8EFF',fontWeight:600}}>■</span> Compute ops</span>
                <span><span style={{color:'#9D7AFF',fontWeight:600}}>■</span> Account ops</span>
              </div>
              <div style={{fontSize:11,color:C.t3,marginTop:4}}>
                Avg budget usage: {avgPct.toFixed(1)}% | 
                Budget: 200K CU per instruction
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Top Consumers */}
      {profile.top_cu_consumers?.length > 0 && (
        <div style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:20,marginBottom:24}}>
          <h3 style={{fontSize:13,fontWeight:600,color:C.txt,marginBottom:8,fontFamily:"'Inter',sans-serif"}}>
            Top CU Consumers
          </h3>
          <div style={{display:'flex',flexWrap:'wrap',gap:8}}>
            {profile.top_cu_consumers.map((c,i) => (
              <span key={i} style={{
                fontSize:11,padding:'4px 12px',borderRadius:100,
                background:'rgba(61,142,255,0.08)',color:'#3D8EFF',fontWeight:600,
                border:'1px solid rgba(61,142,255,0.15)',
                fontFamily:"'Inter',sans-serif"
              }}>
                <Zap size={10} style={{display:'inline',marginRight:4}}/>
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Performance Issues */}
      <div style={{background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:20}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:12}}>
          <h3 style={{fontSize:13,fontWeight:600,color:C.txt,fontFamily:"'Inter',sans-serif"}}>
            Performance Issues
          </h3>
          <span style={{fontSize:11,color:C.t3,background:'#F0F2FF',padding:'2px 10px',borderRadius:100,fontWeight:500}}>
            {performance_issues.length} found
          </span>
        </div>
        {performance_issues.length === 0 ? (
          <p style={{fontSize:13,color:C.t3,textAlign:'center',padding:24}}>
            No performance issues detected
          </p>
        ) : (
          performance_issues.map(issue => (
            <PerfCard key={issue.id} issue={issue} expanded={!!expanded[issue.id]} onToggle={() => toggle(issue.id)} />
          ))
        )}
      </div>
    </div>
  );
}
