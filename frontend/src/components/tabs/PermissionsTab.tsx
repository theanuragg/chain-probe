import React, { useState } from 'react';
import { C } from '@/lib/constants';
import { Sec, Empty } from '@/components/ui';
import { AnalysisReport } from '@/types';

export function PermissionsTab({report}:{report:AnalysisReport}) {
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
    admin:C.grn, any_signer:C.amb, program_pda:C.cyan,
    stored_key:C.red, anyone:C.red, unknown:C.t3,
  };

  const broken = pm.entries.filter(e=>e.status==='intended_but_broken'||e.status==='missing');
  const fine = pm.entries.filter(e=>e.status==='allowed'||e.status==='read_only');

  return (<div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12,marginBottom:28}}>
      {[
        {l:'Total Operations',v:pm.entries.length,col:C.t2},
        {l:'Broken / Missing',v:pm.broken_permission_count,col:pm.broken_permission_count>0?C.red:C.grn},
        {l:'Correctly Enforced',v:fine.length,col:C.grn},
      ].map(s=>(
        <div key={s.l} style={{
          background:'#fff',border:`1px solid ${C.bdr}`,borderRadius:16,padding:'16px 18px'
        }}>
          <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.06em',marginBottom:6,fontWeight:600}}>{s.l}</div>
          <div style={{fontSize:28,fontWeight:700,color:s.col,fontFamily:"'Playfair Display',serif"}}>{s.v}</div>
        </div>
      ))}
    </div>

    {broken.length>0&&<>
      <Sec title={`${broken.length} Broken Permission${broken.length>1?'s':''}`} sub="Access control exists in code but doesn't actually restrict who can call these operations"/>
      {broken.map(entry=>{
        const isOpen=expanded===entry.id;
        const col=statusColor[entry.status]||C.t3;
        return <div key={entry.id} style={{
          border:`1px solid ${col}25`,borderLeft:`3px solid ${col}`,
          borderRadius:16,overflow:'hidden',marginBottom:8,background:'#fff'
        }}>
          <div style={{display:'flex',alignItems:'center',gap:10,padding:'12px 16px',cursor:'pointer'}} onClick={()=>setExpanded(isOpen?null:entry.id)}>
            <span style={{fontSize:10,color:C.t3,fontWeight:500}}>{entry.id}</span>
            <span style={{fontSize:10,fontWeight:700,padding:'3px 9px',borderRadius:100,background:`${col}12`,color:col,whiteSpace:'nowrap'}}>{statusLabel[entry.status]||entry.status}</span>
            <span style={{fontSize:13,fontWeight:600,color:C.txt}}>{entry.instruction}</span>
            <span style={{fontSize:11,color:C.t3}}>→</span>
            <span style={{fontSize:13,color:C.t2}}>{opLabel[entry.operation as string]||entry.operation}</span>
            <span style={{marginLeft:'auto',fontSize:10,padding:'2px 9px',borderRadius:100,background:`${principalColor[entry.principal as string]||C.t3}10`,color:principalColor[entry.principal as string]||C.t3,whiteSpace:'nowrap',fontWeight:500}}>
              {principalLabel[entry.principal as string]||entry.principal}
            </span>
            <span style={{fontSize:10,color:C.t3,transform:isOpen?'rotate(180deg)':'none',transition:'transform .2s'}}>▼</span>
          </div>
          {isOpen&&<div style={{padding:'16px',borderTop:`1px solid ${C.bdr}`}}>
            <p style={{fontSize:14,color:C.t2,lineHeight:1.7,marginBottom:12}}>{entry.evidence}</p>
            {entry.gap&&<div style={{
              padding:'10px 12px',background:`${C.amb}08`,border:`1px solid ${C.amb}20`,
              borderRadius:12,fontSize:14,color:C.amb,lineHeight:1.6
            }}>
              ↳ Gap: {entry.gap}
            </div>}
          </div>}
        </div>;
      })}
    </>}

    <Sec title="Full Access Control Matrix" sub="Every instruction × every privileged operation"/>
    <div style={{overflowX:'auto',background:'#fff',borderRadius:20,border:`1px solid ${C.bdr}`}}>
      <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
        <thead>
          <tr style={{borderBottom:`1px solid ${C.bdr}`}}>
            <th style={{textAlign:'left',padding:'12px 16px',color:C.t3,fontWeight:600,fontSize:11,textTransform:'uppercase',letterSpacing:'.06em'}}>Instruction</th>
            <th style={{textAlign:'left',padding:'12px 16px',color:C.t3,fontWeight:600,fontSize:11,textTransform:'uppercase',letterSpacing:'.06em'}}>Operation</th>
            <th style={{textAlign:'left',padding:'12px 16px',color:C.t3,fontWeight:600,fontSize:11,textTransform:'uppercase',letterSpacing:'.06em'}}>Principal</th>
            <th style={{textAlign:'left',padding:'12px 16px',color:C.t3,fontWeight:600,fontSize:11,textTransform:'uppercase',letterSpacing:'.06em'}}>Status</th>
          </tr>
        </thead>
        <tbody>
          {pm.entries.map((e,i)=>{
            const sc=statusColor[e.status]||C.t3;
            const pc=principalColor[e.principal as string]||C.t3;
            return <tr key={e.id} style={{borderBottom:`1px solid ${C.bdr}`,background:i%2===0?'transparent':'#F8F9FB'}}>
              <td style={{padding:'10px 16px',color:C.txt,fontWeight:600}}>{e.instruction}</td>
              <td style={{padding:'10px 16px',color:C.t2}}>{opLabel[e.operation as string]||e.operation}</td>
              <td style={{padding:'10px 16px'}}>
                <span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${pc}10`,color:pc,fontWeight:500}}>{principalLabel[e.principal as string]||e.principal}</span>
              </td>
              <td style={{padding:'10px 16px'}}>
                <span style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:`${sc}10`,color:sc,fontWeight:700}}>{statusLabel[e.status]||e.status}</span>
              </td>
            </tr>;
          })}
        </tbody>
      </table>
    </div>
  </div>);
}
