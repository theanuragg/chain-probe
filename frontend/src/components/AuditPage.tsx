"use client";
import React, { useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { C } from '@/lib/constants';
import { Shell, TopBar, SLabel } from '@/components/ui';
import { Sb, DEMO_ESCROW, DEMO_SWAP } from '@/lib/styles';
import { AnalysisReport, shouldKeep, filePriority } from '@/types';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api';

type InputMode = 'folder' | 'github' | 'paste';
type Stage = 'idle' | 'loading' | 'analyzing' | 'done' | 'error';

export default function AuditPage() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>('idle');
  const [stageMsg, setStageMsg] = useState('');
  const [progress, setProgress] = useState(0);
  const [files, setFiles] = useState<Record<string,string>>({});
  const [skipped, setSkipped] = useState(0);
  const [error, setError] = useState<string|null>(null);
  const [mode, setMode] = useState<InputMode>('folder');
  const [ghUrl, setGhUrl] = useState('');
  const [paste, setPaste] = useState('');
  const [drag, setDrag] = useState(false);
  const [selectedFile, setSelectedFile] = useState<string|null>(null);
  const folderRef = useRef<HTMLInputElement>(null);

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
      const data: AnalysisReport = await res.json();
      setStage('done'); setProgress(100);
      sessionStorage.setItem('chainprobe-report', JSON.stringify(data));
      router.push('/?page=report');
    } catch(e){
      timers.forEach(clearTimeout);
      setError(`Analysis failed: ${(e as Error).message}`);
      setStage('error'); setProgress(0);
    }
  };

  const rsCount = paths.filter(p=>p.endsWith('.rs')).length;
  const totalLines = Object.values(files).join('').split('\n').length;

  return (
    <Shell>
      <TopBar onHome={()=>router.push('/')}/>

      {/* Hero Section */}
      <div style={{paddingTop:80,paddingBottom:40,background:'linear-gradient(180deg,#fff 0%,#F8F9FB 100%)'}}>
        <div style={{maxWidth:1440,margin:'0 auto',padding:'0 24px',textAlign:'center'}}>
          <div style={{
            display:'inline-flex',alignItems:'center',gap:8,
            background:'#fff',borderRadius:9999,padding:'8px 16px',
            border:`1px solid ${C.cyan}20`,marginBottom:20,
            boxShadow:`0 0 60px ${C.cyan}12`
          }}>
            <span style={{fontSize:12,fontWeight:600,color:C.cyan}}>Solana&apos;s static analysis engine</span>
          </div>
          <h1 style={{fontFamily:"'Playfair Display',serif",fontSize:48,color:C.txt,fontWeight:700,marginBottom:12,letterSpacing:'-0.02em'}}>
            Run your first audit
          </h1>
          <p style={{fontSize:18,color:C.t2,maxWidth:600,margin:'0 auto 24px',lineHeight:1.6}}>
            8-stage static analysis: AST → trust → taint → invariants → call graph → patterns → chains → scoring
          </p>
        </div>
      </div>

      {/* Main Content */}
      <div style={{maxWidth:1440,margin:'0 auto',padding:'0 24px 60px'}}>
        <div className="audit-grid" style={{display:'grid',gridTemplateColumns:'320px 1fr',gap:32,alignItems:'start'}}>

          {/* Left Panel - Input */}
          <div style={{
            background:'#fff',borderRadius:24,border:`1px solid ${C.bdr}`,
            padding:24,display:'flex',flexDirection:'column',gap:20,
            boxShadow:'0 0 60px rgba(85,106,220,0.05)'
          }}>
            <div>
              <SLabel>Input Mode</SLabel>
              <div style={{display:'flex',gap:2,background:'#F8F9FB',borderRadius:12,padding:3}}>
                {(['folder','github','paste'] as InputMode[]).map((m,i)=>(
                  <button key={m} style={{
                    flex:1,fontSize:12,fontWeight:600,padding:'8px 8px',borderRadius:10,
                    border:'none',
                    background:m===mode?'#fff':'transparent',
                    cursor:'pointer',
                    color:m===mode?C.txt:C.t3,
                    fontFamily:"'Inter',sans-serif",
                    boxShadow:m===mode?'0 1px 4px rgba(0,0,0,0.08)':'none',
                    transition:'all .2s'
                  }} onClick={()=>setMode(m)}>
                    {['Folder','GitHub','Paste'][i]}
                  </button>
                ))}
              </div>
            </div>

            {mode==='folder'&&<>
              <div
                style={{
                  border:`2px dashed ${drag?C.cyan:C.bdr}`,borderRadius:16,padding:'24px 16px',
                  textAlign:'center',cursor:'pointer',
                  background:drag?'rgba(85,106,220,0.04)':'transparent',
                  transition:'all .2s'
                }}
                onDragOver={e=>{e.preventDefault();setDrag(true)}}
                onDragLeave={()=>setDrag(false)}
                onDrop={e=>{e.preventDefault();setDrag(false);e.dataTransfer.files.length&&loadFolder(e.dataTransfer.files)}}
                onClick={()=>folderRef.current?.click()}
              >
                <div style={{fontSize:32,marginBottom:8}}>📁</div>
                <p style={{fontSize:14,color:C.t2,fontFamily:"'Inter',sans-serif",lineHeight:1.5,marginBottom:4}}>
                  Drop Anchor project folder
                </p>
                <small style={{fontSize:12,color:C.t3,fontFamily:"'Inter',sans-serif"}}>
                  Keeps .rs .toml · drops target/ .git/ locks
                </small>
              </div>
              <input ref={folderRef} type="file" multiple {...{webkitdirectory:''}} style={{display:'none'}} onChange={e=>e.target.files&&loadFolder(e.target.files)}/>
              <div style={{display:'flex',gap:6,flexWrap:'wrap',alignItems:'center'}}>
                <span style={{fontSize:12,color:C.t3,fontFamily:"'Inter',sans-serif"}}>Demos:</span>
                <button style={Sb.exBtn} onClick={()=>{setPaste(DEMO_ESCROW);setMode('paste');}}>Escrow</button>
                <button style={Sb.exBtn} onClick={()=>{setPaste(DEMO_SWAP);setMode('paste');}}>DeFi swap</button>
              </div>
            </>}

            {mode==='github'&&<>
              <input style={Sb.field} value={ghUrl} onChange={e=>setGhUrl(e.target.value)} placeholder="https://github.com/.../blob/main/src/lib.rs"/>
              <button style={Sb.btnSm} onClick={fetchGH}>Fetch</button>
            </>}

            {mode==='paste'&&<>
              <textarea style={{...Sb.field,height:120,resize:'vertical',borderRadius:12,fontFamily:"'JetBrains Mono',monospace",fontSize:13}} value={paste} onChange={e=>setPaste(e.target.value)} placeholder={'// Paste .rs code\n// Separate files:\n// ===== FILE: path/to/file.rs ====='}/>
              <button style={Sb.btnSm} onClick={loadPasted}>Use this code</button>
            </>}

            {paths.length>0&&<div>
              <SLabel extra={<span style={{marginLeft:'auto',fontSize:12,color:C.cyan,fontWeight:600}}>{rsCount} .rs files</span>}>Loaded Files</SLabel>
              <div style={{
                background:'#F8F9FB',border:`1px solid ${C.bdr}`,borderRadius:12,
                maxHeight:200,overflowY:'auto',padding:4
              }}>
                {paths.map(p=>(
                  <div key={p} style={{
                    display:'flex',alignItems:'center',gap:6,padding:'6px 10px',cursor:'pointer',
                    fontFamily:"'Inter',sans-serif",fontSize:12,
                    whiteSpace:'nowrap',overflow:'hidden',
                    color:selectedFile===p?C.cyan:C.t2,
                    background:selectedFile===p?'#fff':'transparent',
                    borderRadius:8,
                  }} onClick={()=>setSelectedFile(p)} title={p}>
                    <span style={{opacity:.5,fontSize:10}}>{p.endsWith('.rs')?'◈':'≡'}</span>
                    <span style={{overflow:'hidden',textOverflow:'ellipsis'}}>{p.split('/').pop()}</span>
                  </div>
                ))}
              </div>
              {skipped>0&&<div style={{marginTop:6,fontSize:12,padding:'4px 10px',background:`${C.amb}10`,border:`1px solid ${C.amb}20`,borderRadius:100,color:C.amb,textAlign:'center'}}>{skipped} files filtered</div>}
            </div>}

            <div>
              {(stage==='analyzing'||stage==='loading')&&<div style={{marginBottom:12}}>
                <div style={{height:4,background:'#F0F2FF',borderRadius:2,overflow:'hidden'}}>
                  <div style={{height:'100%',width:`${progress}%`,background:C.cyan,borderRadius:2,transition:'width .3s'}}/>
                </div>
                <div style={{fontSize:13,color:C.t2,marginTop:6}}>{stageMsg}</div>
              </div>}
              {error&&<div style={{fontSize:13,color:C.red,marginBottom:10,lineHeight:1.5,padding:'8px 12px',background:`${C.red}08`,borderRadius:12,border:`1px solid ${C.red}20`}}>{error}</div>}
              <button style={{
                ...Sb.runBtn,
                opacity:(!paths.length||stage==='analyzing')?0.4:1,
                cursor:(!paths.length||stage==='analyzing'||stage==='loading')?'not-allowed':'pointer',
              }}
                disabled={!paths.length||stage==='analyzing'||stage==='loading'}
                onClick={runAnalysis}
              >
                {stage==='analyzing'?'Running 8-stage pipeline…':'Run Full Audit →'}
              </button>
            </div>
          </div>

          {/* Right Panel - Preview */}
          <div style={{
            background:'#fff',borderRadius:24,border:`1px solid ${C.bdr}`,
            padding:40,display:'flex',flexDirection:'column',alignItems:'center',
            justifyContent:'center',gap:24,minHeight:400,
            boxShadow:'0 0 60px rgba(85,106,220,0.05)'
          }}>
            {paths.length===0?<>
              <div style={{
                width:80,height:80,borderRadius:'50%',background:'#F0F2FF',
                display:'flex',alignItems:'center',justifyContent:'center',marginBottom:8
              }}>
                <span style={{fontSize:32,opacity:.3}}>◈</span>
              </div>
              <p style={{fontSize:14,color:C.t3,textAlign:'center'}}>Load a project to begin analysis</p>
            </>:<>
              <div style={{textAlign:'center',marginBottom:8}}>
                <div style={{fontFamily:"'Playfair Display',serif",fontSize:36,fontWeight:700,color:C.txt,letterSpacing:'-0.02em'}}>{rsCount}</div>
                <div style={{fontSize:13,color:C.t3}}>Rust files ready</div>
              </div>
              <p style={{fontSize:14,color:C.t2}}>{totalLines.toLocaleString()} total lines of code</p>

              <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16,marginTop:12,width:'100%',maxWidth:480}}>
                {[['◈','Trust map','rgba(85,106,220,0.08)'],['~','Taint flows','rgba(255,61,92,0.08)'],['∀','Invariants','rgba(255,135,23,0.08)'],['⛓','Chains','rgba(157,122,255,0.08)']].map(([i,l,bg])=>(
                  <div key={l} style={{
                    textAlign:'center',padding:16,borderRadius:16,background:bg,
                    border:'1px solid rgba(0,0,0,0.04)'
                  }}>
                    <div style={{fontSize:20,marginBottom:6,color:C.cyan}}>{i}</div>
                    <div style={{fontSize:11,color:C.t2}}>{l}</div>
                  </div>
                ))}
              </div>
            </>}
          </div>
        </div>
      </div>
    </Shell>
  );
}
