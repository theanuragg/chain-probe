import React from 'react';
import { C } from '@/lib/constants';

export function Shell({children}:{children:React.ReactNode}) {
  return <div style={{background:C.bg,color:C.txt,fontFamily:"'Inter',sans-serif",minHeight:'100vh',overflowX:'hidden'}}>{children}</div>;
}

export function TopBar({onHome,onDiff}:{onHome?:()=>void;onDiff?:()=>void}={}) {
  return (
    <nav style={{
      position:'fixed',top:0,left:0,right:0,zIndex:200,
      padding:'12px 24px',
      display:'flex',alignItems:'center',justifyContent:'space-between',
      backdropFilter:'blur(24px)',
      background:'rgba(248,249,251,0.85)',
      borderBottom:`1px solid ${C.bdr}`,
    }}>
      <div style={{display:'flex',alignItems:'center',gap:12,cursor:'pointer'}} onClick={onHome}>
        <div style={{
          width:32,height:32,
          background:'linear-gradient(135deg,#556ADC,#BED2FF)',
          borderRadius:'50%',
          display:'flex',alignItems:'center',justifyContent:'center'
        }}>
          <span style={{fontFamily:"'Outfit',sans-serif",fontSize:12,color:'#fff',fontWeight:700}}>CP</span>
        </div>
        <span style={{fontFamily:"'Playfair Display',serif",fontSize:20,fontWeight:700,color:C.txt}}>
          Chain<span style={{color:C.cyan}}>Probe</span>
        </span>
      </div>
      <div style={{display:'flex',alignItems:'center',gap:10}}>
        {onDiff&&<button style={{
          fontSize:12,fontWeight:600,padding:'6px 14px',borderRadius:'9999px',
          border:`1px solid ${C.pur}40`,background:'transparent',
          cursor:'pointer',color:C.pur,fontFamily:"'Inter',sans-serif",
          transition:'all .2s'
        }} onClick={onDiff}>⇄ Compare</button>}
        <span style={{
          fontSize:11,color:C.t3,fontFamily:"'Inter',sans-serif",
          padding:'4px 12px',border:`1px solid ${C.bdr}`,borderRadius:'9999px',
          background:'#fff'
        }}>v4 · no AI detection</span>
      </div>
    </nav>
  );
}

export function SLabel({children,extra}:{children:React.ReactNode,extra?:React.ReactNode}) {
  return (
    <div style={{
      fontFamily:"'Inter',sans-serif",fontSize:11,color:C.t3,
      letterSpacing:'.08em',textTransform:'uppercase',
      marginBottom:10,fontWeight:600,display:'flex',alignItems:'center'
    }}>
      {children}{extra}
    </div>
  );
}

export function Sec({title,sub,children}:{title:string,sub?:string,children?:React.ReactNode}) {
  return (
    <div style={{marginBottom:28}}>
      <div style={{
        fontFamily:"'Inter',sans-serif",fontSize:11,fontWeight:700,
        color:C.t3,letterSpacing:'.08em',textTransform:'uppercase',
        marginBottom:sub?2:12,paddingBottom:10,borderBottom:`1px solid ${C.bdr}`
      }}>
        {title}
      </div>
      {sub&&<div style={{fontSize:13,color:C.t2,fontFamily:"'Inter',sans-serif",marginBottom:14,lineHeight:1.5}}>{sub}</div>}
      {children}
    </div>
  );
}

export function Empty({icon,text}:{icon:string,text:string}) {
  return (
    <div style={{
      textAlign:'center',padding:60,
      color:C.t3,fontFamily:"'Inter',sans-serif",
      background:C.bg2,borderRadius:24,
      border:`1px solid ${C.bdr}`
    }}>
      <div style={{fontSize:40,opacity:.15,marginBottom:12}}>{icon}</div>
      <p style={{fontSize:14,maxWidth:400,margin:'0 auto',lineHeight:1.6}}>{text}</p>
    </div>
  );
}

const SEV_COLORS: Record<string,string> = {
  CRITICAL:'#FF3D5C',HIGH:'#FF3D5C',MEDIUM:'#FFAA33',LOW:'#556ADC',INFO:'#999999',
};

export function Pill({sev}:{sev:string}) {
  const bg: Record<string,string> = {
    CRITICAL:'#FF3D5C15',HIGH:'#FF3D5C10',MEDIUM:'#FFAA3315',LOW:'#556ADC12',INFO:'#99999910',
  };
  return (
    <span style={{
      fontSize:9,fontWeight:700,letterSpacing:'.06em',textTransform:'uppercase',
      padding:'3px 8px',borderRadius:'9999px',whiteSpace:'nowrap',
      fontFamily:"'Inter',sans-serif",
      background:bg[sev]||bg.INFO,
      color:SEV_COLORS[sev]||SEV_COLORS.INFO,
      border:`1px solid ${SEV_COLORS[sev]}20`
    }}>
      {sev}
    </span>
  );
}
