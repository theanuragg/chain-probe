// frontend/src/App.tsx — ChainProbe v4
// 7 report tabs: Overview · Taint · Invariants · Attack Surface · Chains · Findings · Advisories
// No AI in UI. Three core differentiators shown visually:
//   1. Taint flows — source→sink propagation paths
//   2. Invariant table — require!() analysis with bypass status
//   3. Call graph — entry points with attack surface scores
//   4. Per-finding PoC test + fix diff

import React, { useState, useRef, useEffect } from 'react';
import './styles.css';
import {
  AnalysisReport, Finding, VulnChain, TaintFlow, ProgramInvariant,
  Severity, Category, AccountTrust, InvariantStatus,
  CATEGORY_LABELS, SEV_COLOR, SEV_BG, SEV_ORDER,
  TRUST_COLOR, TRUST_LABEL, TRUST_RISK,
  INVARIANT_COLOR, INVARIANT_LABEL, COMPLEXITY_LABEL, LINK_TYPE_LABEL,
  DiffReport, DiffFinding, DIFF_CHANGE_COLOR, DIFF_VERDICT_COLOR,
  shouldKeep, filePriority,
} from './types';
import { generatePoC, generateChainPoC } from './lib/poc_generator';
import { generateFixDiff, FixDiff } from './lib/fix_diff';

type Page = 'landing' | 'audit' | 'report' | 'diff';
type InputMode = 'folder' | 'github' | 'paste';
type ReportTab = 'overview' | 'taint' | 'invariants' | 'surface' | 'tokens' | 'permissions' | 'chains' | 'findings' | 'advisories';
type Stage = 'idle' | 'loading' | 'analyzing' | 'done' | 'error';
type FindingView = 'details' | 'poc' | 'diff';

const API = process.env.REACT_APP_API_URL || '/api';

//   Design tokens                               ─
const C = {
  bg:'#05070A', bg2:'#080C12', surf:'#111820',
  txt:'#DDE4F0', t2:'#7A8599', t3:'#3D4A5C',
  bdr:'rgba(255,255,255,.06)',
  cyan:'#00C8E8', grn:'#00D98A', red:'#FF3D5C',
  amb:'#FFAA33', blu:'#3D8EFF', pur:'#9D7AFF',
};

export default function App() {
  const [page, setPage] = useState<Page>('landing');
  const [stage, setStage] = useState<Stage>('idle');
  const [stageMsg, setStageMsg] = useState('');
  const [progress, setProgress] = useState(0);
  const [files, setFiles] = useState<Record<string,string>>({});
  const [skipped, setSkipped] = useState(0);
  const [report, setReport] = useState<AnalysisReport|null>(null);
  const [diffResult, setDiffResult] = useState<DiffReport|null>(null);
  const [error, setError] = useState<string|null>(null);
  const [mode, setMode] = useState<InputMode>('folder');
  const [ghUrl, setGhUrl] = useState('');
  const [paste, setPaste] = useState('');
  const [drag, setDrag] = useState(false);
  const [selectedFile, setSelectedFile] = useState<string|null>(null);
  const [tab, setTab] = useState<ReportTab>('overview');
  const folderRef = useRef<HTMLInputElement>(null);

  // Keyboard navigation for tabs
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLInputElement) return;
      const tabs: ReportTab[] = ['overview','taint','invariants','tokens','permissions','surface','chains','findings','advisories'];
      const idx = parseInt(e.key) - 1;
      if (idx >= 0 && idx < tabs.length) setTab(tabs[idx]);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  const paths = Object.keys(files).sort((a,b)=>filePriority(a)-filePriority(b));

  const loadFolder = async (fl: FileList) => {
    setStage('loading'); setStageMsg('Reading files…'); setProgress(5);
    const loaded: Record<string,string> = {}; let sk = 0;
    const toRead: {f:File,p:string}[] = [];
    Array.from(fl).forEach(f => {
      const p = ((f as any).webkitRelativePath||f.name).replace(/\\/g,'/');
      shouldKeep(p) ? toRead.push({f,p}) : sk++;
    });
    if (!toRead.length) { setError('No .rs or .toml files found'); setStage('error'); return; }
    await Promise.all(toRead.map(({f,p})=>new Promise<void>(res=>{
      const r=new FileReader(); r.onload=e=>{loaded[p]=e.target!.result as string;res();}; r.readAsText(f);
    })));
    setFiles(loaded); setSkipped(sk); setStage('idle'); setError(null);
  };

  const fetchGH = async () => {
    const url = ghUrl.trim().replace('github.com','raw.githubusercontent.com').replace('/blob/','/');
    setStage('loading'); setStageMsg('Fetching…'); setProgress(20);
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const p = url.split('/').slice(7).join('/')||'fetched.rs';
      setFiles({[p]:text}); setSkipped(0); setStage('idle');
    } catch(e){ setError(`Fetch failed: ${(e as Error).message}`); setStage('error'); }
  };

  const loadPasted = () => {
    const loaded: Record<string,string> = {};
    const rx = /\/\/ ={3,} FILE: (.+?) ={3,}/g;
    let matches: RegExpExecArray[] = [];
    let match: RegExpExecArray | null;
    while ((match = rx.exec(paste)) !== null) {
      matches.push(match);
    }
    if (matches.length>0) {
      matches.forEach((m: RegExpExecArray, i: number) => {
        const path=m[1].trim(), start=m.index!+m[0].length, end=matches[i+1]?.index??paste.length;
        loaded[path]=paste.slice(start,end).trim();
      });
    } else { loaded['program/src/lib.rs']=paste; }
    setFiles(loaded); setSkipped(0); setStage('idle');
  };

  const runAnalysis = async () => {
    if (!paths.filter(p=>p.endsWith('.rs')).length) { setError('No .rs files'); return; }
    setStage('analyzing'); setError(null); setProgress(10);
    const msgs: [number,string,number][] = [
      [600,'Parsing AST with syn…',18],[1400,'Building trust map…',32],
      [2200,'Running taint analysis…',48],[3000,'Mining invariants…',62],
      [3800,'Detecting vulnerability chains…',76],[4500,'Scoring exploitability…',88],
    ];
    const timers = msgs.map(([ms,msg,pct])=>setTimeout(()=>{setStageMsg(msg);setProgress(pct);},ms));
    try {
      const sorted = paths.map(p=>({path:p,content:files[p]}));
      const res = await fetch(`${API}/analyze`,{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({files:sorted}),
      });
      timers.forEach(clearTimeout);
      if (!res.ok) { const e=await res.json().catch(()=>({error:res.statusText})); throw new Error(e.error||`${res.status}`); }
      const data:AnalysisReport = await res.json();
      setReport(data); setStage('done'); setProgress(100);
      setPage('report'); setTab('overview');
    } catch(e){
      timers.forEach(clearTimeout);
      setError(`Analysis failed: ${(e as Error).message}`);
      setStage('error'); setProgress(0);
    }
  };

  if (page==='landing') return <Landing onStart={()=>setPage('audit')} onDiff={()=>setPage('diff')}/>;

  if (page==='audit') return (
    <Shell>
      <TopBar onHome={()=>setPage('landing')} onDiff={()=>setPage('diff')}/>
      <div style={{paddingTop:60}}>
        <div style={{padding:'24px 44px 18px',borderBottom:`1px solid ${C.bdr}`}}>
          <h2 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:24,letterSpacing:'.04em',marginBottom:4}}>NEW AUDIT</h2>
          <p style={{fontSize:11,color:C.t2,fontFamily:'monospace'}}>8-stage static analysis: AST → trust → taint → invariants → call graph → patterns → chains → scoring</p>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'260px 1fr',minHeight:'calc(100vh-142px)'}}>
          {/* Sidebar */}
          <div style={{borderRight:`1px solid ${C.bdr}`,padding:18,background:C.bg2,display:'flex',flexDirection:'column',gap:16,overflowY:'auto'}}>
            <div>
              <SLabel>Input</SLabel>
              <div style={{display:'flex',gap:2,background:C.bg,borderRadius:4,padding:2,marginBottom:12}}>
                {(['folder','github','paste'] as InputMode[]).map((m,i)=>(
                  <button key={m} style={{flex:1,fontSize:10,fontWeight:700,padding:'6px 4px',borderRadius:3,border:'none',background:m===mode?C.surf:'transparent',cursor:'pointer',color:m===mode?C.txt:C.t3,fontFamily:"'Outfit',sans-serif",textTransform:'uppercase',letterSpacing:'.06em'}} onClick={()=>setMode(m)}>
                    {['Folder','GitHub','Paste'][i]}
                  </button>
                ))}
              </div>
              {mode==='folder'&&<>
                <div style={{border:`1px dashed ${drag?C.cyan:'rgba(255,255,255,.1)'}`,borderRadius:6,padding:'16px 12px',textAlign:'center',cursor:'pointer',background:drag?`${C.cyan}06`:'transparent'}}
                  onDragOver={e=>{e.preventDefault();setDrag(true)}} onDragLeave={()=>setDrag(false)}
                  onDrop={e=>{e.preventDefault();setDrag(false);e.dataTransfer.files.length&&loadFolder(e.dataTransfer.files)}}
                  onClick={()=>folderRef.current?.click()}>
                  <div style={{fontSize:20,marginBottom:5}}>📁</div>
                  <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.6}}>Drop Anchor project folder</p>
                  <small style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>keeps .rs .toml · drops target/ .git/ locks</small>
                </div>
                <input ref={folderRef} type="file" multiple {...{webkitdirectory:''}} style={{display:'none'}} onChange={e=>e.target.files&&loadFolder(e.target.files)}/>
                <div style={{display:'flex',gap:5,marginTop:8,flexWrap:'wrap'}}>
                  <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',alignSelf:'center'}}>Demos:</span>
                  <button style={Sb.exBtn} onClick={()=>{setPaste(DEMO_ESCROW);setMode('paste');}}>Escrow</button>
                  <button style={Sb.exBtn} onClick={()=>{setPaste(DEMO_SWAP);setMode('paste');}}>DeFi swap</button>
                </div>
              </>}
              {mode==='github'&&<>
                <input style={Sb.field} value={ghUrl} onChange={e=>setGhUrl(e.target.value)} placeholder="https://github.com/.../blob/main/src/lib.rs"/>
                <button style={Sb.btnSm} onClick={fetchGH}>Fetch</button>
              </>}
              {mode==='paste'&&<>
                <textarea style={{...Sb.field,height:110,resize:'vertical'}} value={paste} onChange={e=>setPaste(e.target.value)} placeholder={'// Paste .rs\n// Separate files:\n// ===== FILE: path/to/file.rs ====='}/>
                <button style={Sb.btnSm} onClick={loadPasted}>Use this code</button>
              </>}
            </div>

            {paths.length>0&&<div>
              <SLabel extra={<span style={{marginLeft:'auto',fontSize:9,color:C.cyan,fontFamily:'monospace'}}>{paths.filter(p=>p.endsWith('.rs')).length} .rs</span>}>Files</SLabel>
              <div style={{background:C.bg,border:`1px solid ${C.bdr}`,borderRadius:5,maxHeight:180,overflowY:'auto'}}>
                {paths.map(p=>(
                  <div key={p} style={{display:'flex',alignItems:'center',gap:5,padding:'3px 10px',cursor:'pointer',fontFamily:'monospace',fontSize:10,whiteSpace:'nowrap',overflow:'hidden',color:selectedFile===p?C.cyan:C.t2,background:selectedFile===p?'#111620':'transparent'}} onClick={()=>setSelectedFile(p)} title={p}>
                    <span style={{opacity:.5}}>{p.endsWith('.rs')?'◈':'≡'}</span>
                    <span style={{overflow:'hidden',textOverflow:'ellipsis'}}>{p.split('/').pop()}</span>
                  </div>
                ))}
              </div>
              {skipped>0&&<div style={{marginTop:4,fontSize:9,padding:'2px 8px',background:`${C.amb}08`,border:`1px solid ${C.amb}20`,borderRadius:100,color:C.amb,fontFamily:'monospace',textAlign:'center'}}>{skipped} files filtered</div>}
            </div>}

            <div>
              {(stage==='analyzing'||stage==='loading')&&<div style={{marginBottom:10}}>
                <div style={{height:2,background:`rgba(255,255,255,.06)`,borderRadius:1,overflow:'hidden'}}>
                  <div style={{height:'100%',width:`${progress}%`,background:C.cyan,borderRadius:1,transition:'width .3s'}}/>
                </div>
                <div style={{fontSize:10,color:C.t2,fontFamily:'monospace',marginTop:5}}>{stageMsg}</div>
              </div>}
              {error&&<div style={{fontSize:10,color:C.red,fontFamily:'monospace',marginBottom:8,lineHeight:1.5}}>{error}</div>}
              <button style={{...Sb.runBtn,...(!paths.length||stage==='analyzing'?{opacity:.3,cursor:'not-allowed'}:{})}}
                disabled={!paths.length||stage==='analyzing'||stage==='loading'} onClick={runAnalysis}>
                {stage==='analyzing'?'Running 8-stage pipeline…':'Run Full Audit →'}
              </button>
            </div>
          </div>

          {/* Right panel */}
          <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',padding:40,gap:20}}>
            {paths.length===0?<>
              <div style={{fontSize:32,opacity:.1}}>◈</div>
              <p style={{fontSize:12,color:C.t3,fontFamily:'monospace'}}>Load a project to begin</p>
            </>:<>
              <div style={{fontSize:28,fontFamily:"'Bebas Neue',sans-serif",letterSpacing:'.04em'}}>{paths.filter(p=>p.endsWith('.rs')).length} FILES READY</div>
              <p style={{fontSize:12,color:C.t2,fontFamily:'monospace'}}>{Object.values(files).join('').split('\n').length.toLocaleString()} lines</p>
              <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginTop:8}}>
                {[['◈','Trust map'],['~','Taint flows'],['∀','Invariants'],['⛓','Chains']].map(([i,l])=>(
                  <div key={l} style={{textAlign:'center'}}>
                    <div style={{fontSize:20,marginBottom:4,color:C.cyan}}>{i}</div>
                    <div style={{fontSize:10,color:C.t3,fontFamily:'monospace'}}>{l}</div>
                  </div>
                ))}
              </div>
            </>}
          </div>
        </div>
      </div>
    </Shell>
  );

  if (page==='report'&&report) return <ReportPage report={report} activeTab={tab} onTab={setTab} onBack={()=>setPage('audit')} onHome={()=>setPage('landing')} onDiff={()=>setPage('diff')}/>;

  if (page==='diff') return <DiffPage report={report} initialDiff={diffResult} onSetDiff={setDiffResult} onBack={()=>setPage(report?'report':'audit')} onHome={()=>setPage('landing')}/>;

  return <Shell><TopBar onHome={()=>setPage('landing')}/></Shell>;
}

//   REPORT PAGE                                ─

function ReportPage({report,activeTab,onTab,onBack,onHome,onDiff}:{report:AnalysisReport;activeTab:ReportTab;onTab:(t:ReportTab)=>void;onBack:()=>void;onHome:()=>void;onDiff:()=>void}) {
  const TABS: {key:ReportTab;label:string;badge?:number;warn?:boolean}[] = [
    {key:'overview',label:'Overview'},
    {key:'taint',label:'Taint',badge:report.taint_flows.length,warn:report.taint_flows.some(f=>f.severity==='CRITICAL')},
    {key:'invariants',label:'Invariants',badge:report.summary.bypassable_invariant_count,warn:report.summary.bypassable_invariant_count>0},
    {key:'tokens',label:'Token Flow',badge:report.token_flow?.anomalies?.length,warn:(report.token_flow?.anomalies?.length??0)>0},
    {key:'permissions',label:'Permissions',badge:report.permission_matrix?.broken_permission_count,warn:(report.permission_matrix?.broken_permission_count??0)>0},
    {key:'surface',label:'Attack Surface'},
    {key:'chains',label:'Chains',badge:report.vuln_chains.length,warn:report.vuln_chains.length>0},
    {key:'findings',label:`Findings (${report.summary.total})`},
    {key:'advisories',label:'Advisories',badge:report.known_vulns.length},
  ];

  return (
    <Shell>
      <TopBar onHome={onHome}/>
      <div style={{paddingTop:60}}>
        <div style={{padding:'22px 44px 0',borderBottom:`1px solid ${C.bdr}`,display:'flex',alignItems:'flex-start',justifyContent:'space-between',flexWrap:'wrap',gap:12}}>
          <div>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:5}}>
              <button style={{...Sb.rbBtn,color:C.t2,border:`1px solid ${C.bdr}`,background:'transparent'}} onClick={onBack}>← Back</button>
              <h2 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:22,letterSpacing:'.04em'}}>{report.profile.program_name.toUpperCase()} — SECURITY REPORT</h2>
            </div>
            <p style={{fontSize:11,color:C.t2,fontFamily:'monospace'}}>{report.profile.files_analyzed} files · {report.profile.total_lines.toLocaleString()} lines · Anchor {report.profile.anchor_version}</p>
          </div>
          <div style={{display:'flex',gap:7}}>
            <button style={{...Sb.rbBtn,background:'transparent',color:C.t2,border:`1px solid ${C.bdr}`}} onClick={onBack}>← Back</button>
            <button style={{...Sb.rbBtn,background:`${C.pur}15`,color:C.pur,border:`1px solid ${C.pur}30`}} onClick={onDiff}>⇄ Compare</button>
            <button style={{...Sb.rbBtn,background:C.cyan,color:C.bg,border:'none'}} onClick={()=>{const b=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=`chainprobe-${report.profile.program_name}.json`;a.click();}}>Export JSON</button>
            <button style={{...Sb.rbBtn,border:`1px solid ${C.bdr}`,color:C.t2,background:'transparent'}} onClick={()=>window.print()}>Print</button>
          </div>
        </div>

        {/* Tab bar */}
        <div style={{display:'flex',borderBottom:`1px solid ${C.bdr}`,padding:'0 44px',background:C.bg2,overflowX:'auto'}}>
          {TABS.map(t=>(
            <button key={t.key} style={{fontSize:10,fontWeight:600,letterSpacing:'.06em',textTransform:'uppercase',padding:'11px 16px',border:'none',background:'none',cursor:'pointer',color:activeTab===t.key?C.txt:C.t3,fontFamily:"'Outfit',sans-serif",borderBottom:`2px solid ${activeTab===t.key?C.cyan:'transparent'}`,display:'flex',alignItems:'center',gap:5,whiteSpace:'nowrap'}} onClick={()=>onTab(t.key)}>
              {t.label}
              {t.badge!==undefined&&t.badge>0&&<span style={{fontSize:9,padding:'1px 5px',borderRadius:100,background:t.warn?C.red:C.surf,color:t.warn?'#fff':C.t2}}>{t.badge}</span>}
            </button>
          ))}
        </div>

        <div style={{maxWidth:1060,margin:'0 auto',padding:'28px 44px'}}>
          {activeTab==='overview'     && <OverviewTab report={report}/>}
          {activeTab==='taint'        && <TaintTab report={report}/>}
          {activeTab==='invariants'   && <InvariantsTab report={report}/>}
          {activeTab==='tokens'       && <TokenFlowTab report={report}/>}
          {activeTab==='permissions'  && <PermissionsTab report={report}/>}
          {activeTab==='surface'      && <SurfaceTab report={report}/>}
          {activeTab==='chains'       && <ChainsTab report={report}/>}
          {activeTab==='findings'     && <FindingsTab report={report}/>}
          {activeTab==='advisories'   && <AdvisoriesTab report={report}/>}
        </div>
      </div>
    </Shell>
  );
}

//   OVERVIEW                                  

function OverviewTab({report}:{report:AnalysisReport}) {
  const sc = report.summary.security_score;
  const col = sc>=70?C.grn:sc>=50?C.amb:C.red;
  const r=38,circ=2*Math.PI*r;
  return (<div>
    <div style={{display:'grid',gridTemplateColumns:'auto 1fr auto',gap:28,alignItems:'center',background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:8,padding:24,marginBottom:22}}>
      {/* Score ring */}
      <div style={{position:'relative',width:90,height:90}}>
        <svg width="90" height="90" viewBox="0 0 90 90" style={{transform:'rotate(-90deg)'}}>
          <circle cx="45" cy="45" r={r} fill="none" stroke={C.surf} strokeWidth="7"/>
          <circle cx="45" cy="45" r={r} fill="none" stroke={col} strokeWidth="7" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={circ-(sc/100)*circ} style={{transition:'stroke-dashoffset 1.2s ease'}}/>
        </svg>
        <div style={{position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'}}>
          <span style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:26,color:col}}>{sc}</span>
          <span style={{fontSize:8,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.1em'}}>security</span>
        </div>
      </div>
      {/* Text */}
      <div>
        <h3 style={{fontSize:17,fontWeight:700,marginBottom:4}}>{report.summary.overall_risk} Risk</h3>
        <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.6,marginBottom:12}}>
          {report.summary.total} findings · {report.summary.chain_count} chains · {report.summary.taint_flow_count} taint flows · {report.summary.bypassable_invariant_count} bypassable invariants
        </p>
        <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
          {(['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as Severity[]).map(s=>{
            const cnt=(report.summary as any)[s.toLowerCase()] as number;
            if(!cnt) return null;
            return <div key={s} style={{display:'flex',alignItems:'center',gap:4,padding:'4px 9px',borderRadius:4,fontSize:11,fontWeight:600,background:SEV_BG[s],color:SEV_COLOR[s],border:`1px solid ${SEV_COLOR[s]}30`}}><b style={{fontSize:14}}>{cnt}</b>{s.charAt(0)+s.slice(1).toLowerCase()}</div>;
          })}
        </div>
      </div>
      {/* Three sub-scores */}
      <div style={{display:'flex',flexDirection:'column',gap:10,minWidth:160}}>
        {[
          {l:'Attack Surface',v:report.summary.attack_surface_score,col:C.red,inv:true},
          {l:'Hardening',v:report.summary.hardening_score,col:C.grn,inv:false},
        ].map(s=>(
          <div key={s.l}>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:4}}>
              <span>{s.l}</span><span style={{color:s.col}}>{s.v}/100</span>
            </div>
            <div style={{height:3,background:C.surf,borderRadius:2,overflow:'hidden'}}>
              <div style={{height:'100%',width:`${s.v}%`,background:s.col,borderRadius:2}}/>
            </div>
          </div>
        ))}
      </div>
    </div>

    <Sec title="Vulnerability Categories">
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:6}}>
        {Object.entries(report.category_summary).map(([k,v])=>{
          const maxC=Math.max(...Object.values(report.category_summary).map(x=>x.count),1);
          const col2=v.max_severity==='NONE'?C.t3:SEV_COLOR[v.max_severity as Severity]||C.t3;
          return <div key={k} style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5,padding:11}}>
            <div style={{fontSize:10,fontWeight:600,marginBottom:5}}>{CATEGORY_LABELS[k as Category]||k}</div>
            <div style={{height:2,background:C.surf,borderRadius:1,overflow:'hidden',marginBottom:4}}>
              <div style={{height:'100%',width:`${Math.round(v.count/maxC*100)}%`,background:col2,borderRadius:1}}/>
            </div>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>{v.count} · {v.max_severity}</div>
          </div>;
        })}
      </div>
    </Sec>

    <Sec title="Program Profile">
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:6}}>
        {[
          {l:'Instructions',v:report.profile.instructions_count,col:C.blu},
          {l:'Account Structs',v:report.profile.account_structs_count,col:C.amb},
          {l:'CPI Calls',v:report.profile.cpi_calls_count,col:'#FF7A5A'},
          {l:'Taint Flows',v:report.summary.taint_flow_count,col:report.summary.taint_flow_count>0?C.red:C.grn},
          {l:'Broken Permissions',v:report.summary.broken_permission_count,col:report.summary.broken_permission_count>0?C.red:C.grn},
          {l:'Token Flow Anomalies',v:report.summary.token_flow_anomaly_count,col:report.summary.token_flow_anomaly_count>0?C.amb:C.grn},
          {l:'Bypassable Invariants',v:report.summary.bypassable_invariant_count,col:report.summary.bypassable_invariant_count>0?C.red:C.grn},
          {l:'PDA Derivations',v:report.profile.pda_count,col:C.pur},
          {l:'Invariants Total',v:report.summary.invariant_count,col:C.t2},
        ].map(c=>(
          <div key={c.l} style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5,padding:11}}>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:2}}>{c.l}</div>
            <div style={{fontSize:18,fontWeight:700,color:c.col}}>{c.v}</div>
          </div>
        ))}
      </div>
      {report.profile.framework_patterns.length>0&&<div style={{marginTop:8,display:'flex',gap:5,flexWrap:'wrap'}}>
        {report.profile.framework_patterns.map(p=><span key={p} style={{fontSize:9,padding:'2px 8px',borderRadius:3,background:`${C.cyan}10`,color:C.cyan,fontFamily:'monospace',border:`1px solid ${C.cyan}20`}}>{p}</span>)}
      </div>}
    </Sec>
  </div>);
}

//   TAINT FLOWS                                ─

function TaintTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  if (!report.taint_flows.length) return <Empty icon="~" text="No taint flows detected — no attacker-controlled values reached security sinks"/>;

  const sorted=[...report.taint_flows].sort((a,b)=>SEV_ORDER[a.severity]-SEV_ORDER[b.severity]);
  return (<div>
    <Sec title={`${sorted.length} Taint Flow${sorted.length>1?'s':''}`} sub="Attacker-controlled values propagating from sources to security-sensitive sinks"/>
    {sorted.map(tf=>{
      const isOpen=expanded===tf.id;
      const linkedFinding=tf.finding_id?report.findings.find(f=>f.id===tf.finding_id):null;
      return <div key={tf.id} style={{border:`1px solid ${SEV_COLOR[tf.severity]}30`,borderLeft:`3px solid ${SEV_COLOR[tf.severity]}`,borderRadius:5,overflow:'hidden',marginBottom:6}}>
        <div style={{display:'flex',alignItems:'center',gap:8,padding:'10px 14px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:tf.id)}>
          <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{tf.id}</span>
          <Pill sev={tf.severity}/>
          <div style={{flex:1,overflow:'hidden'}}>
            <div style={{fontSize:11,fontWeight:600,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
              {tf.source.name} → {tf.sink.sink_type.replace(/_/g,' ')}
            </div>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>in {tf.instruction}</div>
          </div>
          {linkedFinding&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.amb}15`,color:C.amb,fontFamily:'monospace',border:`1px solid ${C.amb}30`}}>→ {linkedFinding.id}</span>}
          <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
        </div>
        {isOpen&&<div style={{padding:'12px 14px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
          <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.7,marginBottom:12}}>{tf.sink.description}</p>
          <div style={{display:'flex',flexDirection:'column',gap:0}}>
            {tf.path.map((hop,i)=>(
              <div key={i} style={{display:'flex',gap:10,padding:'6px 0',borderBottom:i<tf.path.length-1?`1px solid ${C.bdr}`:'none'}}>
                <div style={{display:'flex',flexDirection:'column',alignItems:'center',width:20,flexShrink:0}}>
                  <div style={{width:8,height:8,borderRadius:'50%',border:`2px solid ${i===tf.path.length-1?SEV_COLOR[tf.severity]:C.cyan}`,background:i===tf.path.length-1?SEV_COLOR[tf.severity]:C.bg,flexShrink:0}}/>
                  {i<tf.path.length-1&&<div style={{flex:1,width:1,background:C.bdr,margin:'2px 0'}}/>}
                </div>
                <div style={{flex:1}}>
                  <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:2}}>{hop.operation.replace(/_/g,' ')} · {hop.file.split('/').pop()}:{hop.line}</div>
                  <div style={{fontSize:11,color:i===tf.path.length-1?SEV_COLOR[tf.severity]:C.t2,fontFamily:'monospace'}}>{hop.description}</div>
                  {hop.snippet&&<pre style={{fontSize:9,background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:3,padding:'4px 8px',marginTop:4,overflow:'auto',whiteSpace:'pre-wrap'}}>{hop.snippet}</pre>}
                </div>
              </div>
            ))}
          </div>
        </div>}
      </div>;
    })}
  </div>);
}

//   INVARIANTS                                 

function InvariantsTab({report}:{report:AnalysisReport}) {
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
    <div style={{display:'flex',gap:6,marginBottom:16,flexWrap:'wrap'}}>
      {(['all','bypassable','incomplete','ordering_risk','holds'] as const).map(s=>{
        const cnt=s==='all'?report.invariants.length:counts[s]??0;
        return <button key={s} style={{fontSize:9,fontWeight:700,textTransform:'uppercase',letterSpacing:'.08em',padding:'4px 10px',borderRadius:3,border:`1px solid ${filter===s?'transparent':C.bdr}`,background:filter===s?(s==='all'?C.cyan:INVARIANT_COLOR[s as InvariantStatus]):'transparent',color:filter===s?(s==='all'?C.bg:'#fff'):C.t3,cursor:'pointer',fontFamily:"'Outfit',sans-serif"}} onClick={()=>setFilter(s)}>
          {s.replace('_',' ')} ({cnt})
        </button>;
      })}
    </div>
    <div style={{display:'flex',flexDirection:'column',gap:5}}>
      {filtered.map(inv=>{
        const isOpen=expanded===inv.id;
        const col=INVARIANT_COLOR[inv.status];
        return <div key={inv.id} style={{border:`1px solid ${col}25`,borderLeft:`3px solid ${col}`,borderRadius:5,overflow:'hidden'}}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'9px 13px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:inv.id)}>
            <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{inv.id}</span>
            <span style={{fontSize:8,fontWeight:700,padding:'1px 6px',borderRadius:3,background:`${col}15`,color:col,fontFamily:'monospace',whiteSpace:'nowrap'}}>{INVARIANT_LABEL[inv.status]}</span>
            {inv.taint_confirmed&&<span style={{fontSize:8,padding:'1px 5px',borderRadius:3,background:`${C.red}12`,color:C.red,fontFamily:'monospace',border:`1px solid ${C.red}25`}}>taint confirmed</span>}
            <span style={{fontFamily:'monospace',fontSize:10,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',color:C.t2}}>{inv.condition}</span>
            <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',whiteSpace:'nowrap'}}>{inv.instruction}</span>
            <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'12px 14px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
            <div style={{fontSize:10,color:C.t3,fontFamily:'monospace',marginBottom:8}}>
              {inv.file.split('/').pop()}:{inv.line} · protects: {inv.protects}
            </div>
            <pre style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:4,padding:'8px 10px',fontSize:10,fontFamily:'monospace',marginBottom:10,whiteSpace:'pre-wrap'}}>{inv.snippet}</pre>
            {inv.bypass_path&&<div style={{padding:'9px 12px',background:`${C.red}08`,border:`1px solid ${C.red}20`,borderRadius:4,fontSize:11,color:C.red,fontFamily:'monospace',lineHeight:1.6}}>
              ⚠ {inv.bypass_path}
            </div>}
          </div>}
        </div>;
      })}
    </div>
  </div>);
}

//   ATTACK SURFACE                               

function SurfaceTab({report}:{report:AnalysisReport}) {
  const [selInstr,setSelInstr]=useState<string|null>(null);
  const instrNodes=report.call_graph.nodes.filter(n=>n.node_type==='instruction');
  const active=selInstr||instrNodes[0]?.id||null;
  const trustForInstr=active?(report.data_flow.trust_map[active]||{}):{};
  const edges=report.call_graph.edges.filter(e=>e.from===active||e.to===active);
  const shared=report.data_flow.shared_accounts;

  return (<div>
    <Sec title="Attack Surface Map" sub="Per-instruction trust classification + call graph"/>

    {/* Entry point selector */}
    <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:18}}>
      {instrNodes.map(n=>{
        const scoreCol=n.attack_surface_score>30?C.red:n.attack_surface_score>15?C.amb:C.grn;
        return <button key={n.id}
          style={{fontSize:10,fontWeight:700,padding:'5px 12px',borderRadius:4,border:`1px solid ${n.id===active?C.cyan:C.bdr}`,background:n.id===active?`${C.cyan}15`:'transparent',cursor:'pointer',color:n.id===active?C.cyan:C.t2,fontFamily:'monospace',display:'flex',alignItems:'center',gap:6}}
          onClick={()=>setSelInstr(n.id)}>
          {n.id}
          <span style={{fontSize:9,color:scoreCol}}>⬆{n.attack_surface_score}</span>
        </button>;
      })}
    </div>

    {active&&<>
      {/* Trust map + call edges */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:20}}>
        <div>
          <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:8}}>Account Trust — `{active}`</div>
          {Object.keys(trustForInstr).length===0
            ? <div style={{fontSize:11,color:C.t3,fontFamily:'monospace',padding:14,background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5}}>No trust data</div>
            : <div style={{display:'flex',flexDirection:'column',gap:4}}>
              {Object.entries(trustForInstr).sort(([,a],[,b])=>TRUST_RISK[b]-TRUST_RISK[a]).map(([acct,trust])=>(
                <div key={acct} style={{display:'flex',alignItems:'center',gap:8,padding:'7px 11px',background:C.bg2,border:`1px solid ${C.bdr}`,borderLeft:`3px solid ${TRUST_COLOR[trust]}`,borderRadius:4}}>
                  <span style={{fontFamily:'monospace',fontSize:11,flex:1}}>{acct}</span>
                  <span style={{fontSize:8,padding:'1px 6px',borderRadius:3,background:`${TRUST_COLOR[trust]}12`,color:TRUST_COLOR[trust],fontFamily:'monospace',border:`1px solid ${TRUST_COLOR[trust]}25`,whiteSpace:'nowrap'}}>{TRUST_LABEL[trust]}</span>
                </div>
              ))}
            </div>
          }
        </div>
        <div>
          <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:8}}>CPI Calls from `{active}`</div>
          {edges.filter(e=>e.from===active).length===0
            ? <div style={{fontSize:11,color:C.t3,fontFamily:'monospace',padding:14,background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5}}>No CPI calls detected</div>
            : edges.filter(e=>e.from===active).map((e,i)=>(
              <div key={i} style={{padding:'8px 11px',background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:4,marginBottom:5}}>
                <div style={{display:'flex',alignItems:'center',gap:5,marginBottom:4}}>
                  <span style={{fontFamily:'monospace',fontSize:10,color:C.cyan}}>{e.to.split('::').pop()}</span>
                  <span style={{fontSize:9,padding:'1px 5px',borderRadius:2,background:`${C.cyan}10`,color:C.cyan,fontFamily:'monospace'}}>{e.cpi_type}</span>
                  {e.uses_pda_signer&&<span style={{fontSize:9,color:C.grn,fontFamily:'monospace'}}>PDA signer</span>}
                </div>
                <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                  {e.accounts_passed.slice(0,4).map(a=>(
                    <span key={a.account_name} style={{fontSize:8,padding:'1px 5px',borderRadius:2,background:`${TRUST_COLOR[a.trust]}10`,color:TRUST_COLOR[a.trust],fontFamily:'monospace'}}>{a.account_name}</span>
                  ))}
                </div>
              </div>
            ))
          }
        </div>
      </div>

      {/* Attacker footprint */}
      {instrNodes.find(n=>n.id===active)&&(() => {
        const node=instrNodes.find(n=>n.id===active)!;
        const fp=node.attacker_footprint;
        return <div style={{padding:'12px 14px',background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5,marginBottom:20}}>
          <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:8}}>Minimum attacker footprint for `{active}`</div>
          <div style={{display:'flex',gap:20,flexWrap:'wrap'}}>
            {[
              {l:'Keypairs required',v:fp.required_keypairs,col:C.red},
              {l:'Minimum SOL',v:`~${fp.required_sol.toFixed(3)}`,col:C.amb},
              {l:'Exploit complexity',v:COMPLEXITY_LABEL[fp.complexity],col:fp.complexity==='trivial'?C.red:fp.complexity==='low'?C.amb:fp.complexity==='medium'?C.blu:C.grn},
              {l:'On-chain setup',v:fp.on_chain_setup?'Required':'No',col:fp.on_chain_setup?C.red:C.grn},
            ].map(f=>(
              <div key={f.l}>
                <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:2}}>{f.l}</div>
                <div style={{fontSize:14,fontWeight:700,color:f.col}}>{f.v}</div>
              </div>
            ))}
          </div>
        </div>;
      })()}
    </>}

    {/* Shared accounts */}
    {shared.length>0&&<>
      <Sec title="Shared Accounts" sub="Used across multiple instructions — trust inconsistency = privilege escalation risk"/>
      {shared.map(sa=>(
        <div key={sa.account_name} style={{padding:'10px 14px',background:C.bg2,border:`1px solid ${sa.trust_inconsistent?C.amb:C.bdr}`,borderRadius:5,marginBottom:6}}>
          <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:5}}>
            <span style={{fontFamily:'monospace',fontSize:12,fontWeight:600}}>{sa.account_name}</span>
            {sa.trust_inconsistent&&<span style={{fontSize:8,padding:'1px 7px',borderRadius:3,background:`${C.amb}12`,color:C.amb,fontFamily:'monospace',border:`1px solid ${C.amb}25`}}>⚠ trust inconsistent</span>}
            <span style={{fontSize:8,padding:'1px 6px',borderRadius:3,background:`${TRUST_COLOR[sa.max_trust_risk]}10`,color:TRUST_COLOR[sa.max_trust_risk],fontFamily:'monospace'}}>max: {TRUST_LABEL[sa.max_trust_risk]}</span>
          </div>
          <div style={{display:'flex',gap:5,flexWrap:'wrap'}}>
            {sa.used_in.map(i=><span key={i} style={{fontSize:9,padding:'2px 8px',borderRadius:3,background:`${C.cyan}10`,color:C.cyan,fontFamily:'monospace',border:`1px solid ${C.cyan}20`}}>{i}</span>)}
          </div>
          {sa.trust_inconsistent&&<p style={{fontSize:10,color:C.amb,fontFamily:'monospace',marginTop:6,lineHeight:1.5}}>Attacker exploiting a weaker instruction may position for a stronger one.</p>}
        </div>
      ))}
    </>}
  </div>);
}

//   CHAINS                                   

function ChainsTab({report}:{report:AnalysisReport}) {
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
      return <div key={chain.id} style={{border:`1px solid ${SEV_COLOR[chain.severity]}35`,borderLeft:`3px solid ${SEV_COLOR[chain.severity]}`,borderRadius:6,overflow:'hidden',marginBottom:7}}>
        <div style={{display:'flex',alignItems:'center',gap:8,padding:'11px 14px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:chain.id)}>
          <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{chain.id}</span>
          <Pill sev={chain.severity}/>
          <span style={{fontSize:12,fontWeight:600,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{chain.title}</span>
          <span style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>{chain.finding_ids.join('+')} · {chain.instructions_involved.length} instrs</span>
          <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
        </div>
        {isOpen&&<div style={{padding:'14px 15px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
          <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.7,marginBottom:14}}>{chain.description}</p>
          <div style={{marginBottom:14}}>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.1em',marginBottom:8}}>Exploit Path</div>
            {chain.exploit_steps.map((step,i)=>(
              <div key={i} style={{display:'flex',gap:10,padding:'6px 0',borderBottom:i<chain.exploit_steps.length-1?`1px solid ${C.bdr}`:'none'}}>
                <span style={{fontSize:9,fontFamily:'monospace',color:SEV_COLOR[chain.severity],flexShrink:0,fontWeight:700}}>Step {i+1}</span>
                <span style={{fontSize:11,color:C.t2,fontFamily:'monospace'}}>{step}</span>
              </div>
            ))}
          </div>
          <div style={{display:'flex',gap:6,flexWrap:'wrap',marginBottom:12}}>
            {chain.finding_ids.map(id=>{
              const f=report.findings.find(f=>f.id===id);
              return <span key={id} style={{fontSize:10,padding:'3px 10px',borderRadius:3,background:f?SEV_BG[f.severity]:C.bg2,color:f?SEV_COLOR[f.severity]:C.t2,fontFamily:'monospace',border:`1px solid ${f?SEV_COLOR[f.severity]+'30':C.bdr}`}}>
                {id}{f?`: ${f.title.slice(0,35)}…`:''}
              </span>;
            })}
          </div>
          {chain.ai_explanation&&<div style={{padding:'8px 10px',background:`${C.pur}08`,border:`1px solid ${C.pur}20`,borderRadius:4,fontSize:11,color:C.pur,fontFamily:'monospace',lineHeight:1.6,marginBottom:10}}>
            <span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.pur}15`,marginRight:8}}>AI context</span>{chain.ai_explanation}
          </div>}
          <button style={{...Sb.btnSm,fontSize:10,padding:'7px 14px',width:'auto',background:`${SEV_COLOR[chain.severity]}12`,color:SEV_COLOR[chain.severity],border:`1px solid ${SEV_COLOR[chain.severity]}30`}}
            onClick={()=>setShowPoC(showPoC===chain.id?null:chain.id)}>
            {showPoC===chain.id?'Hide':'Generate'} Chain PoC Test
          </button>
          {poc&&<div style={{marginTop:12}}>
            <div style={{display:'flex',justifyContent:'space-between',padding:'5px 10px',background:C.bg2,borderRadius:'4px 4px 0 0',border:`1px solid ${C.bdr}`,borderBottom:'none'}}>
              <span style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>{poc.test_name}.rs</span>
              <button style={Sb.exBtn} onClick={()=>copy(poc.code,chain.id)}>{copied===chain.id?'✓ Copied':'Copy'}</button>
            </div>
            <pre style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderTop:'none',borderRadius:'0 0 4px 4px',padding:12,fontSize:10,fontFamily:'monospace',color:C.t2,overflow:'auto',maxHeight:340,whiteSpace:'pre-wrap',margin:0}}>{poc.code}</pre>
          </div>}
        </div>}
      </div>;
    })}
  </div>);
}

//   FINDINGS                                  

function FindingsTab({report}:{report:AnalysisReport}) {
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
    <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:14,flexWrap:'wrap'}}>
      <div style={{display:'flex',gap:4}}>
        {['all','critical','high','medium','low','info'].map(s=>{
          const cnt=s==='all'?report.summary.total:(report.summary as any)[s] as number;
          return <button key={s} style={{fontSize:9,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',padding:'4px 9px',borderRadius:3,border:`1px solid ${filter===s?'transparent':C.bdr}`,background:filter===s?C.cyan:'transparent',color:filter===s?C.bg:C.t3,cursor:'pointer',fontFamily:"'Outfit',sans-serif"}} onClick={()=>setFilter(s)}>{s} ({cnt})</button>;
        })}
      </div>
      <div style={{marginLeft:'auto',display:'flex',gap:5,alignItems:'center'}}>
        <span style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>Sort:</span>
        <button style={{fontSize:9,padding:'3px 8px',borderRadius:3,border:`1px solid ${C.bdr}`,background:sortBy==='severity'?C.surf:'transparent',color:sortBy==='severity'?C.txt:C.t3,cursor:'pointer',fontFamily:'monospace'}} onClick={()=>setSortBy('severity')}>Severity</button>
        <button style={{fontSize:9,padding:'3px 8px',borderRadius:3,border:`1px solid ${C.bdr}`,background:sortBy==='exploitability'?C.surf:'transparent',color:sortBy==='exploitability'?C.txt:C.t3,cursor:'pointer',fontFamily:'monospace'}} onClick={()=>setSortBy('exploitability')}>Exploitability</button>
      </div>
    </div>

    {visible.length===0?<div style={{textAlign:'center',padding:32,color:C.t3,fontFamily:'monospace',fontSize:11,border:`1px dashed ${C.bdr}`,borderRadius:5}}>No findings in this category</div>
    :<div style={{display:'flex',flexDirection:'column',gap:5}}>
      {visible.map(f=>{
        const isOpen=expanded===f.id;
        const poc=isOpen&&fView==='poc'?generatePoC(f):null;
        const diff=isOpen&&fView==='diff'?generateFixDiff(f):null;
        return <div key={f.id} style={{border:`1px solid ${C.bdr}`,borderLeft:`2px solid ${SEV_COLOR[f.severity]}`,borderRadius:5,overflow:'hidden'}}>
          <div style={{display:'flex',alignItems:'center',gap:7,padding:'9px 12px',background:C.bg2,cursor:'pointer'}} onClick={()=>{setExpanded(isOpen?null:f.id);setFView('details');}}>
            <span style={{fontFamily:'monospace',fontSize:9,color:C.t3,flexShrink:0}}>{f.id}</span>
            <Pill sev={f.severity}/>
            <span style={{fontSize:11,fontWeight:600,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.title}</span>
            {f.confirmed_by_taint.length>0&&<span style={{fontSize:8,padding:'1px 5px',borderRadius:3,background:`${C.red}12`,color:C.red,fontFamily:'monospace',border:`1px solid ${C.red}25`,whiteSpace:'nowrap'}}>taint ✓</span>}
            <span style={{fontSize:10,fontFamily:'monospace',color:C.amb,flexShrink:0}}>⬆{f.exploitability}</span>
            <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',whiteSpace:'nowrap'}}>{CATEGORY_LABELS[f.category]}</span>
            <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s',flexShrink:0}}>▼</span>
          </div>
          {isOpen&&<div style={{borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
            <div style={{display:'flex',borderBottom:`1px solid ${C.bdr}`,padding:'0 12px',background:C.bg2}}>
              {(['details','poc','diff'] as FindingView[]).map(v=>(
                <button key={v} style={{fontSize:10,fontWeight:600,padding:'8px 12px',border:'none',background:'none',cursor:'pointer',color:fView===v?C.txt:C.t3,fontFamily:"'Outfit',sans-serif",borderBottom:`2px solid ${fView===v?C.cyan:'transparent'}`,textTransform:'uppercase',letterSpacing:'.06em'}} onClick={()=>setFView(v)}>
                  {v==='poc'?'PoC Test':v==='diff'?'Fix Diff':'Details'}
                </button>
              ))}
            </div>
            <div style={{padding:'12px 13px'}}>
              {fView==='details'&&<>
                {f.line&&<div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:6}}>Line {f.line} · {f.file}</div>}
                <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.7,marginBottom:10}}>{f.description}</p>
                {f.ai_explanation&&<div style={{padding:'7px 10px',background:`${C.pur}08`,border:`1px solid ${C.pur}20`,borderRadius:4,fontSize:11,color:C.pur,fontFamily:'monospace',lineHeight:1.6,marginBottom:10}}><span style={{fontSize:9,padding:'1px 5px',borderRadius:3,background:`${C.pur}15`,marginRight:8}}>AI context</span>{f.ai_explanation}</div>}
                {f.snippet&&<pre style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:4,padding:'9px 11px',fontSize:10,fontFamily:'monospace',marginBottom:10,whiteSpace:'pre-wrap',wordBreak:'break-all',lineHeight:1.6}}>{f.snippet}</pre>}
                <div style={{background:`${C.grn}06`,border:`1px solid ${C.grn}20`,borderRadius:4,padding:'8px 11px',fontSize:10,fontFamily:'monospace',color:C.grn,lineHeight:1.6,whiteSpace:'pre-wrap',marginBottom:6}}>
                  ✓ Fix: {f.recommendation}{f.anchor_fix?`\n\nAnchor: ${f.anchor_fix}`:''}
                </div>
                <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
                  {f.function&&<span style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>fn: {f.function}</span>}
                  {f.cwe&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.cyan}10`,border:`1px solid ${C.cyan}20`,color:C.cyan,fontFamily:'monospace'}}>{f.cwe}</span>}
                  <span style={{fontSize:9,fontFamily:'monospace',color:C.amb}}>exploitability: {f.exploitability}/100</span>
                </div>
              </>}
              {fView==='poc'&&(poc
                ? <div>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:10}}>
                    <div>
                      <p style={{fontSize:11,fontWeight:600,marginBottom:3}}>Proves: {poc.proves}</p>
                      <p style={{fontSize:10,color:C.grn,fontFamily:'monospace'}}>After fix → {poc.fix_assertion}</p>
                    </div>
                    <button style={Sb.exBtn} onClick={()=>copy(poc.code,f.id)}>{copied===f.id?'✓ Copied':'Copy'}</button>
                  </div>
                  <pre style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:4,padding:12,fontSize:10,fontFamily:'monospace',color:C.t2,overflow:'auto',maxHeight:380,whiteSpace:'pre-wrap',margin:0}}>{poc.code}</pre>
                  <div style={{marginTop:8}}>
                    <p style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:3}}>Add to Cargo.toml [dev-dependencies]:</p>
                    {poc.deps.map(d=><code key={d} style={{display:'block',fontSize:9,fontFamily:'monospace',color:C.t2,background:C.bg2,padding:'2px 8px',borderRadius:2,marginBottom:2}}>{d}</code>)}
                  </div>
                </div>
                : <div style={{padding:20,textAlign:'center',color:C.t3,fontFamily:'monospace',fontSize:11}}>PoC not available for this finding category</div>
              )}
              {fView==='diff'&&diff&&<FixDiffView diff={diff} onCopy={copy} copied={copied}/>}
            </div>
          </div>}
        </div>;
      })}
    </div>}
  </div>);
}

//   ADVISORIES                                 

function AdvisoriesTab({report}:{report:AnalysisReport}) {
  if (!report.known_vulns.length) return (
    <div style={{textAlign:'center',padding:'60px 20px',color:C.t3,fontFamily:'monospace'}}>
      <div style={{fontSize:28,opacity:.15,marginBottom:10}}>✓</div>
      Anchor {report.profile.anchor_version} has no known advisories in the database
    </div>
  );
  return (<div>
    <Sec title={`${report.known_vulns.length} Known Advisor${report.known_vulns.length>1?'ies':'y'}`} sub={`Detected for anchor-lang ${report.profile.anchor_version}`}/>
    {report.known_vulns.map(v=>(
      <div key={v.advisory_id} style={{border:`1px solid ${SEV_COLOR[v.severity]}25`,borderLeft:`3px solid ${SEV_COLOR[v.severity]}`,borderRadius:5,padding:'13px 15px',background:C.bg2,marginBottom:8}}>
        <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:7,flexWrap:'wrap'}}>
          <Pill sev={v.severity}/>
          <span style={{fontSize:12,fontWeight:600}}>{v.title}</span>
          <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{v.advisory_id}</span>
          {v.cve_id&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.cyan}10`,color:C.cyan,fontFamily:'monospace'}}>{v.cve_id}</span>}
        </div>
        <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.65,marginBottom:10}}>{v.description}</p>
        <div style={{display:'flex',alignItems:'center',gap:14,flexWrap:'wrap',marginBottom:10}}>
          <span style={{fontSize:9,fontFamily:'monospace',color:C.t3}}>Affected: <span style={{color:C.red}}>{v.affected_versions}</span></span>
          {v.fixed_in&&<span style={{fontSize:9,fontFamily:'monospace',color:C.t3}}>Fixed: <span style={{color:C.grn}}>{v.fixed_in}</span></span>}
          <a href={v.url} target="_blank" rel="noopener noreferrer" style={{fontSize:9,color:C.cyan,fontFamily:'monospace',textDecoration:'none'}}>Advisory ↗</a>
        </div>
        <div style={{padding:'7px 10px',background:`${C.amb}08`,border:`1px solid ${C.amb}20`,borderRadius:4}}>
          <span style={{fontSize:10,color:C.amb,fontFamily:'monospace',fontWeight:600}}>⬆ Upgrade to anchor-lang = "{v.fixed_in||'latest'}" to resolve.</span>
        </div>
      </div>
    ))}
  </div>);
}

//   TOKEN FLOW                                 

function TokenFlowTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  const tf = report.token_flow;
  if (!tf) return <Empty icon="⟳" text="No token flow data — no token accounts detected"/>;

  const movColor: Record<string,string> = {
    deposit:C.grn, withdrawal:C.red, swap:C.blu, internal_transfer:C.t2,
    fee_collection:C.amb, account_close:'#FF7A5A', mint:C.red, burn:C.pur,
  };
  const movLabel: Record<string,string> = {
    deposit:'Deposit', withdrawal:'Withdrawal', swap:'Swap', internal_transfer:'Internal',
    fee_collection:'Fee', account_close:'Close', mint:'Mint', burn:'Burn',
  };

  return (<div>
    {/* Anomalies — shown first, always visible */}
    {tf.anomalies.length>0&&<>
      <Sec title={`${tf.anomalies.length} Flow Anomal${tf.anomalies.length>1?'ies':'y'}`} sub="Patterns in the token lifecycle that indicate potential vulnerabilities"/>
      {tf.anomalies.map(a=>{
        const col = a.severity==='CRITICAL'?C.red:a.severity==='HIGH'?C.amb:C.blu;
        return <div key={a.id} style={{padding:'12px 14px',background:C.bg2,border:`1px solid ${col}30`,borderLeft:`3px solid ${col}`,borderRadius:5,marginBottom:8}}>
          <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:7}}>
            <span style={{fontSize:8,fontWeight:700,padding:'2px 6px',borderRadius:3,background:`${col}15`,color:col,fontFamily:'monospace'}}>{a.severity}</span>
            <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{a.anomaly_type.replace(/_/g,' ')}</span>
            <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginLeft:'auto'}}>{a.edge_ids.join(', ')}</span>
          </div>
          <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.65,marginBottom:8}}>{a.description}</p>
          <div style={{padding:'7px 10px',background:`${C.grn}06`,border:`1px solid ${C.grn}20`,borderRadius:4,fontSize:10,color:C.grn,fontFamily:'monospace',lineHeight:1.5}}>
            ✓ {a.recommendation}
          </div>
        </div>;
      })}
    </>}

    {/* Token account nodes */}
    <Sec title={`${tf.nodes.length} Token Account${tf.nodes.length!==1?'s':''}`} sub="Every token account detected — role, trust level, which instructions use it"/>
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:6,marginBottom:22}}>
      {tf.nodes.map(n=>(
        <div key={n.id} style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderLeft:`3px solid ${TRUST_COLOR[n.trust as keyof typeof TRUST_COLOR]||C.t3}`,borderRadius:4,padding:'10px 12px'}}>
          <div style={{fontFamily:'monospace',fontSize:11,fontWeight:600,marginBottom:4}}>{n.account_name}</div>
          <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:5}}>
            {n.role} {n.is_pda?'· PDA':''}
          </div>
          {n.mint&&<div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:5}}>mint: {n.mint}</div>}
          <div style={{display:'flex',gap:3,flexWrap:'wrap'}}>
            {n.instructions_used_in.map(i=>(
              <span key={i} style={{fontSize:8,padding:'1px 5px',borderRadius:2,background:`${C.cyan}10`,color:C.cyan,fontFamily:'monospace'}}>{i}</span>
            ))}
          </div>
        </div>
      ))}
    </div>

    {/* Flow edges */}
    <Sec title={`${tf.edges.length} Token Movement${tf.edges.length!==1?'s':''}`} sub="Every transfer, mint, burn, and close — with full authorization context"/>
    <div style={{display:'flex',flexDirection:'column',gap:5}}>
      {tf.edges.map(e=>{
        const isOpen=expanded===e.id;
        const mCol=movColor[e.movement_type]||C.t2;
        const mLbl=movLabel[e.movement_type]||e.movement_type;
        return <div key={e.id} style={{border:`1px solid ${C.bdr}`,borderLeft:`2px solid ${mCol}`,borderRadius:5,overflow:'hidden'}}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'9px 13px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:e.id)}>
            <span style={{fontFamily:'monospace',fontSize:9,color:C.t3,flexShrink:0}}>{e.id}</span>
            <span style={{fontSize:9,fontWeight:700,padding:'2px 6px',borderRadius:3,background:`${mCol}15`,color:mCol,fontFamily:'monospace',whiteSpace:'nowrap'}}>{mLbl}</span>
            {/* Flow arrow */}
            <div style={{display:'flex',alignItems:'center',gap:5,flex:1,overflow:'hidden',minWidth:0}}>
              <span style={{fontFamily:'monospace',fontSize:10,color:C.t2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.from_account}</span>
              <span style={{color:C.t3,flexShrink:0}}>→</span>
              <span style={{fontFamily:'monospace',fontSize:10,color:C.t2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.to_account}</span>
            </div>
            <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',whiteSpace:'nowrap',flexShrink:0}}>{e.instruction}</span>
            {!e.is_guarded&&!e.uses_pda_signer&&matches(e.movement_type,['withdrawal','account_close'])&&(
              <span style={{fontSize:8,padding:'1px 5px',borderRadius:3,background:`${C.red}12`,color:C.red,fontFamily:'monospace',border:`1px solid ${C.red}25`,flexShrink:0}}>⚠ unguarded</span>
            )}
            <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s',flexShrink:0}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'12px 14px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:10}}>
              <div>
                <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Authorization</div>
                <div style={{fontSize:11,fontFamily:'monospace',color:C.t2,lineHeight:1.6}}>
                  {e.authorization.constraint_text}
                </div>
                <div style={{marginTop:6,display:'flex',gap:5,flexWrap:'wrap'}}>
                  {e.uses_pda_signer&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.grn}12`,color:C.grn,fontFamily:'monospace'}}>PDA signer</span>}
                  {e.authorization.requires_signer&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.blu}12`,color:C.blu,fontFamily:'monospace'}}>signature required</span>}
                  {e.is_guarded&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.grn}12`,color:C.grn,fontFamily:'monospace'}}>require! guarded</span>}
                  {!e.is_guarded&&!e.uses_pda_signer&&<span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${C.red}12`,color:C.red,fontFamily:'monospace'}}>no guard</span>}
                </div>
              </div>
              <div>
                <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Amount Source</div>
                <div style={{fontSize:11,fontFamily:'monospace',color:C.t2}}>{e.amount_source}</div>
                {e.preconditions.length>0&&<div style={{marginTop:8}}>
                  <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',marginBottom:4}}>Guards:</div>
                  {e.preconditions.map((p,i)=><code key={i} style={{display:'block',fontSize:9,fontFamily:'monospace',color:C.grn,marginBottom:2}}>{p}</code>)}
                </div>}
              </div>
            </div>
            {e.snippet&&<pre style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:4,padding:'8px 10px',fontSize:9,fontFamily:'monospace',overflow:'auto',maxHeight:140,whiteSpace:'pre-wrap',lineHeight:1.6}}>{e.snippet}</pre>}
          </div>}
        </div>;
      })}
    </div>
  </div>);
}

//   PERMISSIONS                                ─

function PermissionsTab({report}:{report:AnalysisReport}) {
  const [expanded,setExpanded]=useState<string|null>(null);
  const pm = report.permission_matrix;
  if (!pm) return <Empty icon="🔑" text="No permission data available"/>;

  const statusColor: Record<string,string> = {
    allowed:C.grn, intended_but_broken:C.red, missing:C.red, read_only:C.t3,
  };
  const statusLabel: Record<string,string> = {
    allowed:'✓ Correctly enforced',
    intended_but_broken:'⚠ Intended but broken',
    missing:'✗ No access control',
    read_only:'Read-only',
  };
  const opLabel: Record<string,string> = {
    modify_config:'Modify Config', drain_vault:'Drain Vault',
    transfer_tokens:'Transfer Tokens', close_account:'Close Account',
    mint_tokens:'Mint Tokens', initialize:'Initialize', program_upgrade:'Program Upgrade',
    read_only:'Read Only',
  };
  const principalLabel: Record<string,string> = {
    admin:'Admin (signed + bound)', any_signer:'Any signer (not bound)',
    program_pda:'Program PDA', stored_key:'Stored key (no sig ⚠)',
    anyone:'Anyone (open)', unknown:'Unknown',
  };
  const principalColor: Record<string,string> = {
    admin:C.grn, any_signer:C.amb, program_pda:C.blu,
    stored_key:C.red, anyone:C.red, unknown:C.t3,
  };

  const broken = pm.entries.filter(e=>e.status==='intended_but_broken'||e.status==='missing');
  const fine = pm.entries.filter(e=>e.status==='allowed'||e.status==='read_only');

  return (<div>
    {/* Summary bar */}
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10,marginBottom:22}}>
      {[
        {l:'Total Operations',v:pm.entries.length,col:C.t2},
        {l:'Broken / Missing',v:pm.broken_permission_count,col:pm.broken_permission_count>0?C.red:C.grn},
        {l:'Correctly Enforced',v:fine.length,col:C.grn},
      ].map(s=>(
        <div key={s.l} style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:5,padding:'12px 14px'}}>
          <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:4}}>{s.l}</div>
          <div style={{fontSize:22,fontWeight:700,color:s.col}}>{s.v}</div>
        </div>
      ))}
    </div>

    {/* Broken permissions first */}
    {broken.length>0&&<>
      <Sec title={`${broken.length} Broken Permission${broken.length>1?'s':''}`} sub="Access control exists in code but doesn't actually restrict who can call these operations"/>
      {broken.map(entry=>{
        const isOpen=expanded===entry.id;
        const col=statusColor[entry.status]||C.t3;
        return <div key={entry.id} style={{border:`1px solid ${col}30`,borderLeft:`3px solid ${col}`,borderRadius:5,overflow:'hidden',marginBottom:6}}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'10px 14px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:entry.id)}>
            <span style={{fontFamily:'monospace',fontSize:9,color:C.t3}}>{entry.id}</span>
            <span style={{fontSize:8,fontWeight:700,padding:'2px 7px',borderRadius:3,background:`${col}15`,color:col,fontFamily:'monospace',whiteSpace:'nowrap'}}>{statusLabel[entry.status]||entry.status}</span>
            <span style={{fontFamily:'monospace',fontSize:10,fontWeight:600}}>{entry.instruction}</span>
            <span style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>→</span>
            <span style={{fontSize:10,color:C.t2,fontFamily:'monospace'}}>{opLabel[entry.operation as string]||entry.operation}</span>
            <span style={{marginLeft:'auto',fontSize:9,padding:'1px 7px',borderRadius:3,background:`${principalColor[entry.principal as string]||C.t3}12`,color:principalColor[entry.principal as string]||C.t3,fontFamily:'monospace',whiteSpace:'nowrap'}}>
              {principalLabel[entry.principal as string]||entry.principal}
            </span>
            <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'12px 14px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
            <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',lineHeight:1.65,marginBottom:10}}>{entry.evidence}</p>
            {entry.gap&&<div style={{padding:'9px 12px',background:`${C.amb}06`,border:`1px solid ${C.amb}20`,borderRadius:4,fontSize:11,color:C.amb,fontFamily:'monospace',lineHeight:1.6}}>
              ↳ Gap: {entry.gap}
            </div>}
          </div>}
        </div>;
      })}
    </>}

    {/* Access control matrix — full table */}
    <Sec title="Full Access Control Matrix" sub="Every instruction × every privileged operation"/>
    <div style={{overflowX:'auto'}}>
      <table style={{width:'100%',borderCollapse:'collapse',fontSize:10,fontFamily:'monospace'}}>
        <thead>
          <tr style={{borderBottom:`1px solid ${C.bdr}`}}>
            <th style={{textAlign:'left',padding:'7px 10px',color:C.t3,fontWeight:500}}>Instruction</th>
            <th style={{textAlign:'left',padding:'7px 10px',color:C.t3,fontWeight:500}}>Operation</th>
            <th style={{textAlign:'left',padding:'7px 10px',color:C.t3,fontWeight:500}}>Principal</th>
            <th style={{textAlign:'left',padding:'7px 10px',color:C.t3,fontWeight:500}}>Status</th>
          </tr>
        </thead>
        <tbody>
          {pm.entries.map((e,i)=>{
            const sc=statusColor[e.status]||C.t3;
            const pc=principalColor[e.principal as string]||C.t3;
            return <tr key={e.id} style={{borderBottom:`1px solid ${C.bdr}`,background:i%2===0?'transparent':C.bg2}}>
              <td style={{padding:'7px 10px',color:C.txt,fontWeight:600}}>{e.instruction}</td>
              <td style={{padding:'7px 10px',color:C.t2}}>{opLabel[e.operation as string]||e.operation}</td>
              <td style={{padding:'7px 10px'}}>
                <span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${pc}12`,color:pc}}>{principalLabel[e.principal as string]||e.principal}</span>
              </td>
              <td style={{padding:'7px 10px'}}>
                <span style={{fontSize:9,padding:'1px 6px',borderRadius:3,background:`${sc}12`,color:sc,fontWeight:700}}>{statusLabel[e.status]||e.status}</span>
              </td>
            </tr>;
          })}
        </tbody>
      </table>
    </div>
  </div>);
}

//   Fix Diff View                               ─

function FixDiffView({diff,onCopy,copied}:{diff:FixDiff;onCopy:(c:string,k:string)=>void;copied:string|null}) {
  const lineStyle=(type:string):React.CSSProperties=>({
    background:type==='removed'?`${C.red}10`:type==='added'?`${C.grn}10`:type==='annotation'?`${C.cyan}07`:'transparent',
    borderLeft:`2px solid ${type==='removed'?C.red:type==='added'?C.grn:type==='annotation'?C.cyan:'transparent'}`,
    color:type==='removed'?C.red:type==='added'?C.grn:type==='annotation'?C.cyan:C.t2,
    padding:'1px 8px 1px 10px',fontFamily:'monospace',fontSize:10,lineHeight:1.6,
    display:'flex',gap:8,alignItems:'flex-start',whiteSpace:'pre-wrap',wordBreak:'break-all',
  });
  const pfx=(t:string)=>t==='removed'?'-':t==='added'?'+':t==='annotation'?'#':' ';
  const afterCode=diff.after_lines.map(l=>`${pfx(l.type)} ${l.content}`).join('\n');
  return (<div>
    <p style={{fontSize:11,color:C.t2,fontFamily:'monospace',marginBottom:14,lineHeight:1.6}}>{diff.change_summary}</p>
    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:10}}>
      {[{lines:diff.before_lines,label:diff.before_label,col:C.red},{lines:diff.after_lines,label:diff.after_label,col:C.grn}].map((side,si)=>(
        <div key={si}>
          <div style={{display:'flex',justifyContent:'space-between',padding:'5px 10px',background:`${side.col}12`,borderRadius:'4px 4px 0 0',border:`1px solid ${side.col}25`,borderBottom:'none'}}>
            <span style={{fontSize:9,color:side.col,fontFamily:'monospace',fontWeight:700}}>{side.label}</span>
            {si===1&&<button style={Sb.exBtn} onClick={()=>onCopy(afterCode,'diff-'+diff.finding_id)}>{copied==='diff-'+diff.finding_id?'✓ Copied':'Copy fixed'}</button>}
          </div>
          <div style={{background:C.bg2,border:`1px solid ${side.col}25`,borderTop:'none',borderRadius:'0 0 4px 4px',overflow:'auto',maxHeight:280}}>
            {side.lines.map((line,i)=>(
              <div key={i} style={lineStyle(line.type)}>
                <span style={{opacity:.4,flexShrink:0,minWidth:12}}>{pfx(line.type)}</span>
                <span style={{flex:1}}>{line.content}</span>
                {line.annotation&&<span style={{fontSize:8,fontStyle:'italic',whiteSpace:'nowrap',marginLeft:8,opacity:.8}}>← {line.annotation}</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
    {diff.cargo_change&&<div style={{padding:'9px 11px',background:`${C.cyan}08`,border:`1px solid ${C.cyan}20`,borderRadius:4,fontFamily:'monospace',fontSize:10,color:C.cyan,whiteSpace:'pre-wrap'}}>📦 Also update Cargo.toml:\n{diff.cargo_change}</div>}
  </div>);
}

//   LANDING                                  ─

function Landing({onStart,onDiff}:{onStart:()=>void;onDiff:()=>void}) {
  return (<Shell>
    <TopBar/>
    <div style={{paddingTop:60}}>
      <section style={{padding:'100px 44px 60px',position:'relative',overflow:'hidden'}}>
        <div style={{position:'absolute',inset:0,backgroundImage:`linear-gradient(${C.bdr} 1px,transparent 1px),linear-gradient(90deg,${C.bdr} 1px,transparent 1px)`,backgroundSize:'52px 52px',opacity:.4}}/>
        <div style={{maxWidth:1060,margin:'0 auto',position:'relative'}}>
          <div style={{display:'inline-flex',alignItems:'center',gap:8,fontFamily:'monospace',fontSize:10,color:C.cyan,letterSpacing:'.14em',textTransform:'uppercase',padding:'5px 14px',border:`1px solid ${C.cyan}30`,borderRadius:100,background:`${C.cyan}08`,marginBottom:28}}>
            <span style={{width:5,height:5,borderRadius:'50%',background:C.cyan,display:'inline-block'}}/>
            Not a linter. Not an AI wrapper. Static analysis that understands Anchor.
          </div>
          <h1 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:'clamp(56px,9vw,108px)',lineHeight:.95,letterSpacing:'.04em',marginBottom:22}}>
            FIND BUGS.<br/><span style={{color:C.cyan}}>PROVE THEM.</span><br/>FIX THEM.
          </h1>
          <p style={{fontSize:15,color:C.t2,lineHeight:1.75,maxWidth:540,marginBottom:36,fontFamily:'monospace',fontWeight:300}}>
            8-stage static analysis: trust classification, taint propagation, invariant mining, call graph, vulnerability chains, exploitability scoring. Every finding ships with a runnable Rust PoC test and side-by-side fix diff.
          </p>
          <div style={{display:'flex',gap:12}}>
            <button style={Sb.btnP} onClick={onStart}>Start Audit →</button>
            <button style={{...Sb.btnP,background:'transparent',color:C.pur,border:`1px solid ${C.pur}40`}} onClick={onDiff}>⇄ Compare Reports</button>
          </div>
        </div>
      </section>

      <div style={{borderTop:`1px solid ${C.bdr}`,borderBottom:`1px solid ${C.bdr}`,padding:'18px 44px',display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:16}}>
        {[['Taint Analysis','new'],['Invariant Mining','new'],['Token Flow','new'],['Permission Matrix','new'],['Exploit Chains','v3'],['Regression Diff','new']].map(([l,b])=>(
          <div key={l} style={{textAlign:'center'}}>
            <div style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:13,letterSpacing:'.04em',color:C.cyan}}>{l}</div>
            <div style={{fontFamily:'monospace',fontSize:9,color:C.t3,marginTop:2}}>{b}</div>
          </div>
        ))}
      </div>

      <section style={{padding:'72px 44px',maxWidth:1060,margin:'0 auto'}}>
        <div style={{fontFamily:'monospace',fontSize:10,color:C.cyan,letterSpacing:'.14em',textTransform:'uppercase',marginBottom:14}}>What makes this different</div>
        <h2 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:'clamp(32px,5vw,52px)',letterSpacing:'.04em',lineHeight:1,marginBottom:40}}>PATTERN MATCHING<br/>IS NOT ANALYSIS.</h2>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:18}}>
          {[
            ['~','Taint Analysis','Tracks attacker-controlled values from instruction parameters through arithmetic, assignments, and state writes — to security sinks like transfer amounts and authority checks. Pattern matching cannot do this.'],
            ['∀','Invariant Mining','Every require!() is a security invariant. ChainProbe extracts them all, then checks whether taint analysis can make any condition evaluate incorrectly. Finds bypasses no linter sees.'],
            ['⛓','Exploit Chains','Two Medium findings that are individually acceptable can combine into a Critical exploit. ChainProbe builds the call graph, verifies reachability, and shows the step-by-step attack path with a generated PoC.'],
          ].map(([ico,h,p])=>(
            <div key={h} style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:8,padding:26}}>
              <div style={{fontSize:22,color:C.cyan,marginBottom:14}}>{ico}</div>
              <h3 style={{fontSize:14,fontWeight:700,marginBottom:8}}>{h}</h3>
              <p style={{fontSize:11,color:C.t2,lineHeight:1.7,fontFamily:'monospace',fontWeight:300}}>{p}</p>
            </div>
          ))}
        </div>
      </section>

      <div style={{borderTop:`1px solid ${C.bdr}`,padding:'72px 44px',textAlign:'center'}}>
        <h2 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:'clamp(36px,5vw,60px)',letterSpacing:'.04em',marginBottom:12}}>READY TO PROBE?</h2>
        <p style={{fontSize:14,color:C.t2,fontFamily:'monospace',marginBottom:28}}>No signup. No API key required. Drop your project.</p>
        <button style={Sb.btnP} onClick={onStart}>Start Free Audit →</button>
      </div>
      <footer style={{borderTop:`1px solid ${C.bdr}`,padding:'22px 44px',display:'flex',justifyContent:'space-between'}}>
        <span style={{fontSize:10,color:C.t3,fontFamily:'monospace'}}>ChainProbe v4</span>
        <span style={{fontSize:10,color:C.t3,fontFamily:'monospace'}}>React + Rust Axum · Deterministic static analysis</span>
      </footer>
    </div>
  </Shell>);
}

//   DIFF PAGE                                 ─
// Load two AnalysisReport JSON files, POST to /api/diff, show regression report.

function DiffPage({report,initialDiff,onSetDiff,onBack,onHome}:{
  report:AnalysisReport|null;
  initialDiff:DiffReport|null;
  onSetDiff:(d:DiffReport)=>void;
  onBack:()=>void;
  onHome:()=>void;
}) {
  const [baseline,setBaseline]=useState<AnalysisReport|null>(null);
  const [current,setCurrent]=useState<AnalysisReport|null>(report);
  const [diff,setDiff]=useState<DiffReport|null>(initialDiff);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState<string|null>(null);
  const [expanded,setExpanded]=useState<string|null>(null);

  const loadJSON=(setter:(r:AnalysisReport)=>void)=>{
    const inp=document.createElement('input');
    inp.type='file'; inp.accept='.json';
    inp.onchange=e=>{
      const f=(e.target as HTMLInputElement).files?.[0];
      if(!f) return;
      const rd=new FileReader();
      rd.onload=ev=>{
        try{ setter(JSON.parse(ev.target!.result as string)); }
        catch{ setErr('Invalid JSON file'); }
      };
      rd.readAsText(f);
    };
    inp.click();
  };

  const runDiff=async()=>{
    if(!baseline||!current){setErr('Load both reports first');return;}
    setLoading(true);setErr(null);
    try{
      const res=await fetch(`${API}/diff`,{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({baseline,current}),
      });
      if(!res.ok)throw new Error(`Server error ${res.status}`);
      const d:DiffReport=await res.json();
      setDiff(d);onSetDiff(d);
    }catch(e){setErr(`Diff failed: ${(e as Error).message}`);}
    finally{setLoading(false);}
  };

  const verdictCol=(v:string)=>DIFF_VERDICT_COLOR[v as keyof typeof DIFF_VERDICT_COLOR]||C.t2;
  const changeCol=(c:string)=>DIFF_CHANGE_COLOR[c as keyof typeof DIFF_CHANGE_COLOR]||C.t2;
  const changeLbl:Record<string,string>={fixed:'Fixed',new:'New',regressed:'Regressed',improved:'Improved',unchanged:'Unchanged'};

  return (<Shell>
    <TopBar onHome={onHome}/>
    <div style={{paddingTop:60}}>
      <div style={{padding:'22px 44px 18px',borderBottom:`1px solid ${C.bdr}`,display:'flex',alignItems:'center',justifyContent:'space-between',flexWrap:'wrap',gap:12}}>
        <div>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:4}}>
            <button style={{...Sb.rbBtn,color:C.t2,border:`1px solid ${C.bdr}`,background:'transparent'}} onClick={onBack}>← Back</button>
            <h2 style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:22,letterSpacing:'.04em'}}>REGRESSION COMPARISON</h2>
          </div>
          <p style={{fontSize:11,color:C.t2,fontFamily:'monospace'}}>Compare two audit runs — find what was fixed, what regressed, what is new.</p>
        </div>
      </div>

      <div style={{maxWidth:1060,margin:'0 auto',padding:'28px 44px'}}>
        {/* Load panel */}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr auto',gap:12,marginBottom:24,alignItems:'end'}}>
          {/* Baseline */}
          <div style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:6,padding:16}}>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.1em',marginBottom:8}}>Baseline report (before)</div>
            {baseline
              ? <div style={{fontSize:11,fontFamily:'monospace',color:C.grn,marginBottom:8}}>
                  ✓ {baseline.profile.program_name} · score {baseline.summary.security_score}
                </div>
              : <div style={{fontSize:11,color:C.t3,fontFamily:'monospace',marginBottom:8}}>No report loaded</div>
            }
            <button style={{...Sb.btnSm,fontSize:10}} onClick={()=>loadJSON(setBaseline)}>
              {baseline?'Replace':'Load'} Baseline JSON
            </button>
          </div>

          {/* Current */}
          <div style={{background:C.bg2,border:`1px solid ${C.bdr}`,borderRadius:6,padding:16}}>
            <div style={{fontSize:9,color:C.t3,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.1em',marginBottom:8}}>Current report (after)</div>
            {current
              ? <div style={{fontSize:11,fontFamily:'monospace',color:C.cyan,marginBottom:8}}>
                  ✓ {current.profile.program_name} · score {current.summary.security_score}
                </div>
              : <div style={{fontSize:11,color:C.t3,fontFamily:'monospace',marginBottom:8}}>No report loaded{report?' (run an audit first)':''}</div>
            }
            <button style={{...Sb.btnSm,fontSize:10}} onClick={()=>loadJSON(setCurrent)}>
              {current?'Replace':'Load'} Current JSON
            </button>
          </div>

          {/* Run */}
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {err&&<div style={{fontSize:10,color:C.red,fontFamily:'monospace'}}>{err}</div>}
            <button
              style={{...Sb.runBtn,padding:'12px 24px',width:'auto',opacity:(!baseline||!current||loading)?0.4:1}}
              disabled={!baseline||!current||loading}
              onClick={runDiff}>
              {loading?'Comparing…':'Run Diff →'}
            </button>
          </div>
        </div>

        {/* Results */}
        {diff&&<>
          {/* Verdict banner */}
          <div style={{padding:'18px 22px',background:C.bg2,border:`2px solid ${verdictCol(diff.summary.verdict)}30`,borderRadius:8,marginBottom:22,display:'grid',gridTemplateColumns:'1fr auto',alignItems:'center',gap:20}}>
            <div>
              <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6}}>
                <span style={{fontSize:14,fontWeight:700,color:verdictCol(diff.summary.verdict)}}>
                  {diff.summary.verdict==='critical_regression'?'⚠ CRITICAL REGRESSION':
                   diff.summary.verdict==='regressed'?'↓ Regressed':
                   diff.summary.verdict==='improved'?'↑ Improved':'→ Neutral'}
                </span>
                <span style={{fontSize:11,color:C.t2,fontFamily:'monospace'}}>{diff.summary.verdict_reason}</span>
              </div>
              <div style={{display:'flex',gap:16,flexWrap:'wrap'}}>
                {[
                  {l:'Fixed',v:diff.summary.total_fixed,c:C.grn},
                  {l:'New',v:diff.summary.total_new,c:C.red},
                  {l:'Regressed',v:diff.summary.total_regressed,c:C.red},
                  {l:'Improved',v:diff.summary.total_improved,c:C.blu},
                  {l:'Unchanged',v:diff.findings_unchanged,c:C.t3},
                ].map(s=>(
                  <div key={s.l} style={{textAlign:'center'}}>
                    <div style={{fontSize:20,fontWeight:700,color:s.c}}>{s.v}</div>
                    <div style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>{s.l}</div>
                  </div>
                ))}
              </div>
            </div>
            {/* Score delta */}
            <div style={{textAlign:'center',flexShrink:0}}>
              <div style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:42,letterSpacing:'.04em',color:diff.score_delta>=0?C.grn:C.red,lineHeight:1}}>
                {diff.score_delta>0?'+':''}{diff.score_delta}
              </div>
              <div style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>score delta</div>
              <div style={{fontSize:10,color:C.t2,fontFamily:'monospace',marginTop:4}}>
                {diff.score_before} → {diff.score_after}
              </div>
            </div>
          </div>

          {/* Finding changes */}
          {(diff.findings_new.length+diff.findings_regressed.length+diff.findings_fixed.length+diff.findings_improved.length)>0&&<>
            <Sec title="Finding Changes" sub="Matched by category + function + file — not by generated ID"/>
            <div style={{display:'flex',flexDirection:'column',gap:4,marginBottom:22}}>
              {[...diff.findings_regressed,...diff.findings_new,...diff.findings_fixed,...diff.findings_improved].map(f=>{
                const isOpen=expanded===f.id+'_diff';
                const col=changeCol(f.change);
                return <div key={f.id+'_diff'} style={{border:`1px solid ${col}25`,borderLeft:`3px solid ${col}`,borderRadius:4,overflow:'hidden'}}>
                  <div style={{display:'flex',alignItems:'center',gap:8,padding:'8px 12px',background:C.bg2,cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:f.id+'_diff')}>
                    <span style={{fontSize:8,fontWeight:700,padding:'1px 6px',borderRadius:3,background:`${col}15`,color:col,fontFamily:'monospace',whiteSpace:'nowrap'}}>{changeLbl[f.change]||f.change}</span>
                    <span style={{fontSize:11,fontWeight:600,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.title}</span>
                    {f.severity_before&&f.severity_after&&f.severity_before!==f.severity_after&&(
                      <span style={{fontSize:9,fontFamily:'monospace',color:col,whiteSpace:'nowrap'}}>
                        {f.severity_before} → {f.severity_after}
                      </span>
                    )}
                    {(!f.severity_before||!f.severity_after)&&(
                      <span style={{fontSize:9,fontFamily:'monospace',color:col,whiteSpace:'nowrap'}}>
                        {f.severity_after||f.severity_before}
                      </span>
                    )}
                    <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',whiteSpace:'nowrap'}}>{f.function}</span>
                    <span style={{fontSize:9,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
                  </div>
                  {isOpen&&<div style={{padding:'10px 13px',borderTop:`1px solid ${C.bdr}`,background:C.bg}}>
                    <div style={{fontSize:9,color:C.t3,fontFamily:'monospace'}}>
                      {f.file.split('/').pop()} · fn {f.function} · {CATEGORY_LABELS[f.category as Category]||f.category}
                    </div>
                  </div>}
                </div>;
              })}
            </div>
          </>}

          {/* Chain changes */}
          {(diff.chains_new.length+diff.chains_resolved.length)>0&&<Sec title="Chain Changes">
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:22}}>
              {diff.chains_resolved.length>0&&<div>
                <div style={{fontSize:9,color:C.grn,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Resolved ({diff.chains_resolved.length})</div>
                {diff.chains_resolved.map((t,i)=><div key={i} style={{fontSize:10,fontFamily:'monospace',color:C.grn,padding:'4px 0',borderBottom:`1px solid ${C.bdr}`}}>✓ {t}</div>)}
              </div>}
              {diff.chains_new.length>0&&<div>
                <div style={{fontSize:9,color:C.red,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>New ({diff.chains_new.length})</div>
                {diff.chains_new.map(c=><div key={c.id} style={{fontSize:10,fontFamily:'monospace',color:C.red,padding:'4px 0',borderBottom:`1px solid ${C.bdr}`}}>⚠ {c.title} [{c.severity}]</div>)}
              </div>}
            </div>
          </Sec>}

          {/* Permission changes */}
          {(diff.permissions_newly_broken.length+diff.permissions_fixed.length)>0&&<Sec title="Permission Changes">
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:22}}>
              {diff.permissions_fixed.length>0&&<div>
                <div style={{fontSize:9,color:C.grn,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Fixed ({diff.permissions_fixed.length})</div>
                {diff.permissions_fixed.map((p,i)=><div key={i} style={{fontSize:10,fontFamily:'monospace',color:C.grn,padding:'4px 0',borderBottom:`1px solid ${C.bdr}`}}>✓ {p}</div>)}
              </div>}
              {diff.permissions_newly_broken.length>0&&<div>
                <div style={{fontSize:9,color:C.red,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Newly broken ({diff.permissions_newly_broken.length})</div>
                {diff.permissions_newly_broken.map(p=>(
                  <div key={p.id} style={{fontSize:10,fontFamily:'monospace',padding:'6px 0',borderBottom:`1px solid ${C.bdr}`}}>
                    <div style={{color:C.red,marginBottom:2}}>⚠ {p.instruction} → {p.operation}</div>
                    <div style={{fontSize:9,color:C.t3}}>{p.evidence.slice(0,100)}</div>
                  </div>
                ))}
              </div>}
            </div>
          </Sec>}

          {/* Invariant changes */}
          {(diff.invariants_newly_bypassable.length+diff.invariants_fixed.length)>0&&<Sec title="Invariant Changes">
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:22}}>
              {diff.invariants_fixed.length>0&&<div>
                <div style={{fontSize:9,color:C.grn,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Fixed ({diff.invariants_fixed.length})</div>
                {diff.invariants_fixed.map((c,i)=><div key={i} style={{fontSize:9,fontFamily:'monospace',color:C.grn,padding:'3px 0',borderBottom:`1px solid ${C.bdr}`}}>✓ {c}</div>)}
              </div>}
              {diff.invariants_newly_bypassable.length>0&&<div>
                <div style={{fontSize:9,color:C.red,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Newly bypassable ({diff.invariants_newly_bypassable.length})</div>
                {diff.invariants_newly_bypassable.map(i=>(
                  <div key={i.id} style={{fontSize:9,fontFamily:'monospace',padding:'3px 0',borderBottom:`1px solid ${C.bdr}`}}>
                    <div style={{color:C.red}}>⚠ {i.condition.slice(0,60)}</div>
                    <div style={{color:C.t3}}>in {i.instruction} · {i.status}</div>
                  </div>
                ))}
              </div>}
            </div>
          </Sec>}

          {/* Token flow anomaly changes */}
          {(diff.anomalies_new.length+diff.anomalies_resolved.length)>0&&<Sec title="Token Flow Changes">
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              {diff.anomalies_resolved.length>0&&<div>
                <div style={{fontSize:9,color:C.grn,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>Resolved ({diff.anomalies_resolved.length})</div>
                {diff.anomalies_resolved.map((a,i)=><div key={i} style={{fontSize:10,fontFamily:'monospace',color:C.grn,padding:'3px 0',borderBottom:`1px solid ${C.bdr}`}}>✓ {a.replace(/_/g,' ')}</div>)}
              </div>}
              {diff.anomalies_new.length>0&&<div>
                <div style={{fontSize:9,color:C.amb,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.08em',marginBottom:6}}>New ({diff.anomalies_new.length})</div>
                {diff.anomalies_new.map(a=><div key={a.id} style={{fontSize:10,fontFamily:'monospace',color:C.amb,padding:'3px 0',borderBottom:`1px solid ${C.bdr}`}}>⚠ {a.anomaly_type.replace(/_/g,' ')}</div>)}
              </div>}
            </div>
          </Sec>}

          {/* CI/CD hint */}
          <div style={{marginTop:24,padding:'14px 16px',background:`${C.cyan}06`,border:`1px solid ${C.cyan}20`,borderRadius:5}}>
            <div style={{fontSize:9,color:C.cyan,fontFamily:'monospace',textTransform:'uppercase',letterSpacing:'.1em',marginBottom:6}}>Use in CI/CD</div>
            <code style={{fontSize:10,fontFamily:'monospace',color:C.t2,display:'block',lineHeight:1.7}}>
              # Run audit and save baseline<br/>
              chainprobe-cli --project-path . --output-json baseline.json<br/>
              <br/>
              # On next PR, compare against baseline<br/>
              chainprobe-cli --project-path . --compare-to baseline.json --fail-on-chains<br/>
              <br/>
              # Will exit 1 if score drops &gt;5 pts or new CRITICAL findings appear
            </code>
          </div>
        </>}
      </div>
    </div>
  </Shell>);
}

//   Shared components                             ─

function Shell({children}:{children:React.ReactNode}) {
  return <div style={{background:C.bg,color:C.txt,fontFamily:"'Outfit',sans-serif",minHeight:'100vh',overflowX:'hidden'}}>{children}</div>;
}
function TopBar({onHome,onDiff}:{onHome?:()=>void;onDiff?:()=>void}={}) {
  return <nav style={{position:'fixed',top:0,left:0,right:0,zIndex:200,padding:'13px 44px',display:'flex',alignItems:'center',justifyContent:'space-between',backdropFilter:'blur(24px)',background:'rgba(5,7,10,.92)',borderBottom:`1px solid ${C.bdr}`}}>
    <div style={{display:'flex',alignItems:'center',gap:12,cursor:'pointer'}} onClick={onHome}>
      <div style={{width:27,height:27,border:`1.5px solid ${C.cyan}`,borderRadius:5,display:'flex',alignItems:'center',justifyContent:'center'}}><span style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:12,color:C.cyan}}>CP</span></div>
      <span style={{fontFamily:"'Bebas Neue',sans-serif",fontSize:18,letterSpacing:'.08em'}}>Chain<span style={{color:C.cyan}}>Probe</span></span>
    </div>
    <div style={{display:'flex',alignItems:'center',gap:10}}>
      {onDiff&&<button style={{fontSize:9,fontWeight:700,padding:'4px 12px',borderRadius:4,border:`1px solid ${C.pur}40`,background:'transparent',cursor:'pointer',color:C.pur,fontFamily:"'Outfit',sans-serif"}} onClick={onDiff}>⇄ Compare</button>}
      <span style={{fontSize:9,color:C.t3,fontFamily:'monospace',padding:'3px 10px',border:`1px solid ${C.bdr}`,borderRadius:100}}>v4 · no AI detection</span>
    </div>
  </nav>;
}
function SLabel({children,extra}:{children:React.ReactNode,extra?:React.ReactNode}) {
  return <div style={{fontFamily:'monospace',fontSize:9,color:C.t3,letterSpacing:'.12em',textTransform:'uppercase',marginBottom:8,display:'flex',alignItems:'center'}}>{children}{extra}</div>;
}
function Sec({title,sub,children}:{title:string,sub?:string,children?:React.ReactNode}) {
  return <div style={{marginBottom:22}}>
    <div style={{fontFamily:'monospace',fontSize:9,fontWeight:500,color:C.t3,letterSpacing:'.12em',textTransform:'uppercase',marginBottom:sub?2:10,paddingBottom:8,borderBottom:`1px solid ${C.bdr}`}}>{title}</div>
    {sub&&<div style={{fontSize:10,color:C.t3,fontFamily:'monospace',marginBottom:10}}>{sub}</div>}
    {children}
  </div>;
}
function Empty({icon,text}:{icon:string,text:string}) {
  return <div style={{textAlign:'center',padding:'60px 20px',color:C.t3,fontFamily:'monospace'}}>
    <div style={{fontSize:28,opacity:.12,marginBottom:10}}>{icon}</div>{text}
  </div>;
}
function Pill({sev}:{sev:Severity}) {
  return <span style={{fontSize:8,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',padding:'2px 6px',borderRadius:3,whiteSpace:'nowrap',fontFamily:'monospace',background:SEV_BG[sev],color:SEV_COLOR[sev]}}>{sev}</span>;
}

// Check if a snake_case value is in a list
function matches(val: string, list: string[]): boolean {
  return list.includes(val);
}

//   Styles                                   

const Sb: Record<string,React.CSSProperties> = {
  field: {width:'100%',background:C.bg,border:`1px solid ${C.bdr}`,borderRadius:4,padding:'8px 10px',fontFamily:'monospace',fontSize:11,color:C.txt,outline:'none',marginBottom:6},
  btnSm: {width:'100%',fontSize:10,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',color:C.bg,background:C.cyan,padding:8,borderRadius:4,border:'none',cursor:'pointer',fontFamily:"'Outfit',sans-serif"},
  btnP: {display:'inline-flex',alignItems:'center',fontSize:12,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',color:C.bg,background:C.cyan,padding:'13px 26px',borderRadius:4,border:'none',cursor:'pointer',fontFamily:"'Outfit',sans-serif"},
  exBtn: {fontSize:9,padding:'3px 9px',borderRadius:3,border:`1px solid ${C.bdr}`,background:'transparent',cursor:'pointer',color:C.t3,fontFamily:'monospace'},
  runBtn: {width:'100%',fontSize:11,fontWeight:800,letterSpacing:'.1em',textTransform:'uppercase',color:C.bg,background:C.cyan,padding:11,borderRadius:4,border:'none',cursor:'pointer',fontFamily:"'Outfit',sans-serif"},
  rbBtn: {fontSize:10,fontWeight:700,letterSpacing:'.08em',textTransform:'uppercase',padding:'8px 13px',borderRadius:4,cursor:'pointer',fontFamily:"'Outfit',sans-serif"},
};

//   Demo data (same as v3)                           

const DEMO_ESCROW=`// ===== FILE: anchor-escrow/programs/anchor-escrow/Cargo.toml =====
[package]
name = "anchor-escrow"
version = "0.1.0"
[dependencies]
anchor-lang = { version = "0.29.0", features = ["init-if-needed"] }
anchor-spl = "0.29.0"

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/lib.rs =====
use anchor_lang::prelude::*;
pub mod instructions; pub mod state; use instructions::*;
declare_id!("5UFZzEt5vU9fxtUAgsD11z63ApZEHJ5bH7Z4QpFwZ2CQ");
#[program]
pub mod anchor_escrow {
    use super::*;
    pub fn make(ctx: Context<Make>, seed: u64, deposit: u64, receive: u64) -> Result<()> { ctx.accounts.deposit(deposit)?; ctx.accounts.init_escrow(seed, receive, &ctx.bumps) }
    pub fn refund(ctx: Context<Refund>) -> Result<()> { ctx.accounts.refund_and_close_vault() }
    pub fn take(ctx: Context<Take>) -> Result<()> { ctx.accounts.deposit()?; ctx.accounts.withdraw_and_close_vault() }
}

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/state/mod.rs =====
use anchor_lang::prelude::*;
#[account] #[derive(InitSpace)]
pub struct Escrow { pub seed: u64, pub maker: Pubkey, pub mint_a: Pubkey, pub mint_b: Pubkey, pub receive: u64, pub bump: u8 }

// ===== FILE: anchor-escrow/programs/anchor-escrow/src/instructions/take.rs =====
use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken,token_interface::{close_account,transfer_checked,CloseAccount,Mint,TokenAccount,TokenInterface,TransferChecked}};
use crate::Escrow;
#[derive(Accounts)]
pub struct Take<'info> {
    #[account(mut)] pub taker: Signer<'info>,
    #[account(mut)] pub maker: SystemAccount<'info>,
    pub mint_a: InterfaceAccount<'info, Mint>,
    pub mint_b: InterfaceAccount<'info, Mint>,
    #[account(init_if_needed,payer=taker,associated_token::mint=mint_a,associated_token::authority=taker,associated_token::token_program=token_program)] pub taker_ata_a: InterfaceAccount<'info, TokenAccount>,
    #[account(mut,associated_token::mint=mint_b,associated_token::authority=taker,associated_token::token_program=token_program)] pub taker_ata_b: InterfaceAccount<'info, TokenAccount>,
    #[account(init_if_needed,payer=taker,associated_token::mint=mint_b,associated_token::authority=maker,associated_token::token_program=token_program)] pub maker_ata_b: InterfaceAccount<'info, TokenAccount>,
    #[account(mut,close=maker,has_one=mint_a,has_one=mint_b,has_one=maker,seeds=[b"escrow",maker.key().as_ref(),&escrow.seed.to_le_bytes()],bump=escrow.bump)] pub escrow: Account<'info, Escrow>,
    #[account(mut,associated_token::mint=mint_a,associated_token::authority=escrow,associated_token::token_program=token_program)] pub vault: InterfaceAccount<'info, TokenAccount>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
impl<'info> Take<'info> {
    pub fn deposit(&mut self) -> Result<()> {
        let cpi = CpiContext::new(self.token_program.to_account_info(), TransferChecked { from: self.taker_ata_b.to_account_info(), mint: self.mint_b.to_account_info(), to: self.maker_ata_b.to_account_info(), authority: self.taker.to_account_info() });
        transfer_checked(cpi, self.escrow.receive, self.mint_b.decimals)
    }
    pub fn withdraw_and_close_vault(&mut self) -> Result<()> {
        let ss: &[&[&[u8]]] = &[&[b"escrow", self.maker.to_account_info().key.as_ref(), &self.escrow.seed.to_le_bytes(), &[self.escrow.bump]]];
        let cpi = CpiContext::new_with_signer(self.token_program.to_account_info(), TransferChecked { from: self.vault.to_account_info(), mint: self.mint_a.to_account_info(), to: self.taker_ata_a.to_account_info(), authority: self.escrow.to_account_info() }, ss);
        transfer_checked(cpi, self.vault.amount, self.mint_a.decimals)?;
        close_account(CpiContext::new_with_signer(self.token_program.to_account_info(), CloseAccount { account: self.vault.to_account_info(), destination: self.maker.to_account_info(), authority: self.escrow.to_account_info() }, ss))
    }
}`;

const DEMO_SWAP=`// ===== FILE: anchor-swap/programs/anchor-swap/Cargo.toml =====
[package]
name = "anchor-swap"
version = "0.1.0"
[dependencies]
anchor-lang = "0.28.0"
anchor-spl = "0.28.0"

// ===== FILE: anchor-swap/programs/anchor-swap/src/lib.rs =====
use anchor_lang::prelude::*;
pub mod instructions; pub mod state; use instructions::*;
declare_id!("SwapXXXXXX");
#[program]
pub mod anchor_swap {
    use super::*;
    pub fn swap(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> { instructions::swap::execute(ctx, amount_in, min_out) }
    pub fn update_fee(ctx: Context<UpdateFee>, new_fee: u64) -> Result<()> { instructions::admin::update_fee(ctx, new_fee) }
}

// ===== FILE: anchor-swap/programs/anchor-swap/src/state/mod.rs =====
use anchor_lang::prelude::*;
#[account]
pub struct Pool { pub authority: Pubkey, pub token_a_reserve: u64, pub token_b_reserve: u64, pub fee_bps: u64 }

// ===== FILE: anchor-swap/programs/anchor-swap/src/instructions/swap.rs =====
use anchor_lang::prelude::*;
use anchor_spl::token::{self,Token,TokenAccount,Transfer};
use crate::state::Pool;
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)] pub pool: Account<'info, Pool>,
    #[account(mut)] pub user_in: Account<'info, TokenAccount>,
    #[account(mut)] pub pool_in: Account<'info, TokenAccount>,
    #[account(mut)] pub pool_out: Account<'info, TokenAccount>,
    #[account(mut)] pub user_out: Account<'info, TokenAccount>,
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}
pub fn execute(ctx: Context<Swap>, amount_in: u64, min_out: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let amount_out = pool.token_b_reserve * amount_in / pool.token_a_reserve;
    require!(amount_out > 0, SwapError::ZeroOutput);
    pool.token_a_reserve += amount_in;
    pool.token_b_reserve -= amount_out;
    token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer { from: ctx.accounts.user_in.to_account_info(), to: ctx.accounts.pool_in.to_account_info(), authority: ctx.accounts.authority.to_account_info() }), amount_in)?;
    token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer { from: ctx.accounts.pool_out.to_account_info(), to: ctx.accounts.user_out.to_account_info(), authority: pool.to_account_info() }), amount_out)?;
    Ok(())
}

// ===== FILE: anchor-swap/programs/anchor-swap/src/instructions/admin.rs =====
use anchor_lang::prelude::*;
use crate::state::Pool;
#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(mut)] pub pool: Account<'info, Pool>,
    pub authority: AccountInfo<'info>,
}
pub fn update_fee(ctx: Context<UpdateFee>, new_fee: u64) -> Result<()> { ctx.accounts.pool.fee_bps = new_fee; Ok(()) }`;
