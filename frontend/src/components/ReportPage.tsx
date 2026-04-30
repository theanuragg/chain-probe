"use client";
import React, { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { C } from '@/lib/constants';
import { Shell, TopBar } from '@/components/ui';
import { Sb } from '@/lib/styles';
import { OverviewTab } from '@/components/tabs/OverviewTab';
import { TaintTab } from '@/components/tabs/TaintTab';
import { InvariantsTab } from '@/components/tabs/InvariantsTab';
import { TokenFlowTab } from '@/components/tabs/TokenFlowTab';
import { PermissionsTab } from '@/components/tabs/PermissionsTab';
import { SurfaceTab } from '@/components/tabs/SurfaceTab';
import { ChainsTab } from '@/components/tabs/ChainsTab';
import { FindingsTab } from '@/components/tabs/FindingsTab';
import { AdvisoriesTab } from '@/components/tabs/AdvisoriesTab';
import { AnalysisReport } from '@/types';

type ReportTab = 'overview' | 'taint' | 'invariants' | 'tokens' | 'permissions' | 'surface' | 'chains' | 'findings' | 'advisories';

export default function ReportPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [tab, setTab] = useState<ReportTab>('overview');

  useEffect(() => {
    const data = searchParams?.get('data');
    let parsed: AnalysisReport | null = null;

    if (data) {
      try {
        parsed = JSON.parse(decodeURIComponent(data));
      } catch {}
    }

    if (!parsed) {
      const stored = sessionStorage.getItem('chainprobe-report');
      if (stored) {
        try {
          parsed = JSON.parse(stored);
        } catch {}
      }
    }

    if (parsed) {
      setReport(parsed);
    } else {
      router.replace('/');
    }
  }, [searchParams, router]);

  if (!report) return null;

  const TABS: {key:ReportTab;label:string;badge?:number;warn?:boolean}[] = [
    {key:'overview',label:'Overview'},
    {key:'taint',label:'Taint',badge:report.taint_flows.length,warn:report.taint_flows.some(f=>f.severity==='CRITICAL')},
    {key:'invariants',label:'Invariants',badge:report.summary.bypassable_invariant_count,warn:report.summary.bypassable_invariant_count>0},
    {key:'tokens',label:'Token Flow',badge:report.token_flow?.anomalies?.length,warn:(report.token_flow?.anomalies?.length??0)>0},
    {key:'permissions',label:'Permissions',badge:report.permission_matrix?.broken_permission_count,warn:(report.permission_matrix?.broken_permission_count??0)>0},
    {key:'surface',label:'Attack Surface'},
    {key:'chains',label:'Chains',badge:report.vuln_chains.length,warn:report.vuln_chains.length>0},
    {key:'findings',label:'Findings'},
    {key:'advisories',label:'Advisories',badge:report.known_vulns.length},
  ];

  return (
    <Shell>
      <TopBar onHome={()=>router.push('/')}/>

      {/* Report Header */}
      <div style={{paddingTop:80,background:'linear-gradient(180deg,#fff 0%,#F8F9FB 100%)'}}>
        <div style={{maxWidth:1440,margin:'0 auto',padding:'0 24px'}}>
          <div className="report-header" style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',flexWrap:'wrap',gap:16,paddingBottom:24}}>
            <div>
              <button style={{
                fontSize:13,fontWeight:500,padding:'6px 16px',borderRadius:'9999px',
                border:`1px solid ${C.bdr}`,background:'#fff',cursor:'pointer',
                color:C.t2,fontFamily:"'Inter',sans-serif",marginBottom:12,
                transition:'all .2s'
              }} onClick={()=>router.push('/?page=audit')}>
                ← Back to Audit
              </button>
              <h2 style={{fontFamily:"'Playfair Display',serif",fontSize:28,fontWeight:700,letterSpacing:'-0.02em',color:C.txt,marginBottom:6}}>
                {report.profile.program_name} — Security Report
              </h2>
              <p style={{fontSize:14,color:C.t3}}>
                {report.profile.files_analyzed} files · {report.profile.total_lines.toLocaleString()} lines · Anchor {report.profile.anchor_version}
              </p>
            </div>
            <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
              <button style={{
                ...Sb.rbBtn,background:'transparent',color:C.t2,border:`1px solid ${C.bdr}`,
                fontSize:13,fontWeight:500
              }} onClick={()=>router.push('/?page=audit')}>← Back</button>
              <button style={{
                ...Sb.rbBtn,background:C.cyan,color:'#fff',border:'none',
                fontSize:13,fontWeight:600
              }} onClick={()=>{const b=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=`chainprobe-${report.profile.program_name}.json`;a.click();}}>Export JSON</button>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Bar */}
      <div style={{
        position:'sticky',top:60,zIndex:100,
        background:'rgba(248,249,251,0.95)',backdropFilter:'blur(12px)',
        borderBottom:`1px solid ${C.bdr}`
      }}>
        <div style={{maxWidth:1440,margin:'0 auto',padding:'0 24px',display:'flex',overflowX:'auto'}}>
          {TABS.map(t=>(
            <button key={t.key} style={{
              fontSize:13,fontWeight:500,letterSpacing:'-0.01em',
              padding:'14px 16px',border:'none',background:'none',
              cursor:'pointer',
              color:tab===t.key?C.cyan:C.t3,
              fontFamily:"'Inter',sans-serif",
              borderBottom:`2px solid ${tab===t.key?C.cyan:'transparent'}`,
              display:'flex',alignItems:'center',gap:6,whiteSpace:'nowrap',
              transition:'all .2s',
            }} onClick={()=>setTab(t.key)}>
              {t.label}
              {t.badge!==undefined&&t.badge>0&&<span style={{
                fontSize:10,padding:'1px 7px',borderRadius:100,
                background:t.warn?'rgba(255,61,92,0.12)':'#F0F2FF',
                color:t.warn?C.red:C.t3,fontWeight:600
              }}>{t.badge}</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div style={{maxWidth:1440,margin:'0 auto',padding:'32px 24px 60px'}}>
        {tab==='overview'     && <OverviewTab report={report}/>}
        {tab==='taint'        && <TaintTab report={report}/>}
        {tab==='invariants'   && <InvariantsTab report={report}/>}
        {tab==='tokens'       && <TokenFlowTab report={report}/>}
        {tab==='permissions'  && <PermissionsTab report={report}/>}
        {tab==='surface'      && <SurfaceTab report={report}/>}
        {tab==='chains'       && <ChainsTab report={report}/>}
        {tab==='findings'     && <FindingsTab report={report}/>}
        {tab==='advisories'   && <AdvisoriesTab report={report}/>}
      </div>
    </Shell>
  );
}
