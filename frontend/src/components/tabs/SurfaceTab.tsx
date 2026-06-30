import React, { useState, useMemo, useRef, useEffect } from 'react';
import { C } from '@/lib/constants';
import { Sec } from '@/components/ui';
import { AnalysisReport, COMPLEXITY_LABEL, TRUST_COLOR, TRUST_LABEL, TRUST_RISK, AccountTrust } from '@/types';

interface GraphNode {
  id: string; label: string; type: 'instruction' | 'cpi' | 'account';
  x: number; y: number; vx: number; vy: number;
  attack_surface_score?: number; trust?: AccountTrust;
}

interface GraphEdge {
  from: string; to: string; label?: string; cpi_type?: string;
}

function useForceGraph(nodes: GraphNode[], edges: GraphEdge[]) {
  const frameRef = useRef(0);

  useEffect(() => {
    const centerX = 400, centerY = 250;
    const repel = 8000, attract = 0.005, damping = 0.85;

    const step = () => {
      for (const n of nodes) {
        let fx = 0, fy = 0;

        // Repel from other nodes
        for (const other of nodes) {
          if (other.id === n.id) continue;
          const dx = n.x - other.x, dy = n.y - other.y;
          const dist = Math.max(Math.hypot(dx, dy), 1);
          fx += (dx / dist) * repel / (dist * dist);
          fy += (dy / dist) * repel / (dist * dist);
        }

        // Attract along edges
        for (const e of edges) {
          const target = e.from === n.id ? nodes.find(nd => nd.id === e.to)
            : e.to === n.id ? nodes.find(nd => nd.id === e.from)
            : undefined;
          if (!target) continue;
          const dx = target.x - n.x, dy = target.y - n.y;
          fx += dx * attract;
          fy += dy * attract;
        }

        // Center gravity
        fx += (centerX - n.x) * 0.001;
        fy += (centerY - n.y) * 0.001;

        n.vx = (n.vx + fx) * damping;
        n.vy = (n.vy + fy) * damping;
        n.x += n.vx;
        n.y += n.vy;

        // Clamp
        n.x = Math.max(50, Math.min(750, n.x));
        n.y = Math.max(50, Math.min(450, n.y));
      }
      frameRef.current = requestAnimationFrame(step);
    };

    frameRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameRef.current);
  }, [nodes, edges]);
}

function attackSurfaceLabel(score: number): string {
  return score > 30 ? 'High' : score > 15 ? 'Medium' : 'Low';
}

function attackSurfaceColor(score: number): string {
  return score > 30 ? C.red : score > 15 ? C.amb : C.grn;
}

export function SurfaceTab({report}:{report:AnalysisReport}) {
  const [active, setActive] = useState<string|null>(null);
  const [hover, setHover] = useState<string|null>(null);

  const instrNodes = report.call_graph.nodes.filter(n => n.node_type === 'instruction');

  // Build force graph data
  const { graphNodes, graphEdges } = useMemo(() => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const added = new Set<string>();

    // Add instruction nodes
    for (const n of instrNodes) {
      const id = n.id;
      nodes.push({
        id, label: id,
        type: 'instruction',
        x: 100 + Math.random() * 600,
        y: 100 + Math.random() * 300,
        vx: 0, vy: 0,
        attack_surface_score: n.attack_surface_score,
      });
      added.add(id);
    }

    // Add CPI target nodes + edges
    for (const e of report.call_graph.edges) {
      if (!added.has(e.to)) {
        nodes.push({
          id: e.to, label: e.to.split('::').pop() || e.to,
          type: 'cpi', x: 100 + Math.random() * 600,
          y: 100 + Math.random() * 300, vx: 0, vy: 0,
        });
        added.add(e.to);
      }
      edges.push({ from: e.from, to: e.to, label: e.cpi_type, cpi_type: e.cpi_type });
    }

    // Add shared accounts as nodes
    const acctAdded = new Set<string>();
    for (const sa of report.data_flow.shared_accounts) {
      if (acctAdded.has(sa.account_name)) continue;
      acctAdded.add(sa.account_name);
      const trust = sa.max_trust_risk;
      const id = `acct:${sa.account_name}`;
      nodes.push({
        id, label: sa.account_name,
        type: 'account',
        x: 100 + Math.random() * 600,
        y: 100 + Math.random() * 300,
        vx: 0, vy: 0,
        trust,
      });
      for (const instr of sa.used_in) {
        if (added.has(instr)) {
          edges.push({ from: instr, to: id });
        }
      }
    }

    return { graphNodes: nodes, graphEdges: edges };
  }, [report]);

  useForceGraph(graphNodes, graphEdges);

  const selNode = hover || active;

  const nodeColors: Record<string, string> = {
    instruction: C.cyan,
    cpi: '#FF8717',
    account: C.pur,
  };

  return (<div>
    <Sec title="Attack Surface Map" sub="Interactive call graph — click nodes to inspect trust and attacker footprint">
      <div style={{fontSize:12,color:C.t3,marginBottom:12,display:'flex',gap:16}}>
        <span>● Instruction</span>
        <span>● CPI Target</span>
        <span>● Shared Account</span>
      </div>
    </Sec>

    {/* Interactive call graph */}
    <div style={{
      background:'#fff', border:`1px solid ${C.bdr}`, borderRadius:24,
      padding:16, marginBottom:24, position:'relative', overflow:'hidden',
      minHeight:500,
    }}>
      <svg width="800" height="500" viewBox="0 0 800 500">
        {/* Edges */}
        {graphEdges.map((e,i) => {
          const from = graphNodes.find(n => n.id === e.from);
          const to = graphNodes.find(n => n.id === e.to);
          if (!from || !to) return null;
          const isActive = selNode && (e.from === selNode || e.to === selNode);
          return <g key={`e${i}`}>
            <line
              x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={isActive ? C.cyan : C.bdr}
              strokeWidth={isActive ? 2 : 1}
              strokeOpacity={isActive ? 0.8 : 0.4}
            />
            {e.label && isActive && (
              <text
                x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 6}
                fontSize={9} fill={C.t3} textAnchor="middle"
              >{e.label}</text>
            )}
          </g>;
        })}

        {/* Nodes */}
        {graphNodes.map(n => {
          const isActive = selNode === n.id;
          const color = nodeColors[n.type];
          const size = n.type === 'account' ? 8 : n.type === 'instruction' ? 14 : 10;
          const scoreCol = n.attack_surface_score ? attackSurfaceColor(n.attack_surface_score) : color;

          return <g key={n.id}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover(null)}
            onClick={() => setActive(active === n.id ? null : n.id)}
            style={{ cursor: 'pointer' }}
          >
            {n.type === 'instruction' ? (
              <>
                <circle cx={n.x} cy={n.y} r={size}
                  fill={isActive ? color : '#fff'}
                  stroke={scoreCol}
                  strokeWidth={isActive ? 3 : 2}
                  opacity={selNode && !isActive ? 0.3 : 1}
                />
                <text x={n.x} y={n.y + 20} fontSize={10} fill={C.txt}
                  textAnchor="middle" fontWeight={600}
                  opacity={selNode && !isActive ? 0.3 : 1}
                >{n.label}</text>
                {n.attack_surface_score !== undefined && (
                  <text x={n.x} y={n.y + 32} fontSize={8} fill={scoreCol}
                    textAnchor="middle" fontWeight={600}
                    opacity={selNode && !isActive ? 0.3 : 1}
                  >⬆{n.attack_surface_score}</text>
                )}
              </>
            ) : n.type === 'cpi' ? (
              <>
                <rect x={n.x - 12} y={n.y - 8} width={24} height={16} rx={4}
                  fill={isActive ? color : '#fff'}
                  stroke={color}
                  strokeWidth={isActive ? 2 : 1.5}
                  opacity={selNode && !isActive ? 0.3 : 1}
                />
                <text x={n.x} y={n.y + 4} fontSize={8} fill={isActive ? '#fff' : color}
                  textAnchor="middle" fontWeight={600}
                  opacity={selNode && !isActive ? 0.3 : 1}
                >{n.label.slice(0, 12)}</text>
              </>
            ) : (
              <>
                <circle cx={n.x} cy={n.y} r={size}
                  fill={isActive ? color : '#fff'}
                  stroke={color}
                  strokeWidth={isActive ? 2 : 1.5}
                  opacity={selNode && !isActive ? 0.3 : 1}
                />
                <text x={n.x} y={n.y + 16} fontSize={8} fill={C.t3}
                  textAnchor="middle"
                  opacity={selNode && !isActive ? 0.3 : 1}
                >{n.label}</text>
              </>
            )}
          </g>;
        })}
      </svg>
    </div>

    {/* Selected instruction detail */}
    {selNode && instrNodes.find(n => n.id === selNode) && (() => {
      const node = instrNodes.find(n => n.id === selNode)!;
      const trustForInstr = (report.data_flow.trust_map[selNode] || {}) as Record<string, AccountTrust>;
      const edges = report.call_graph.edges.filter(e => e.from === selNode || e.to === selNode);
      const fp = node.attacker_footprint;

      return <div style={{
        background:'#fff', border:`1px solid ${C.cyan}30`, borderRadius:20,
        padding:24, marginBottom:24,
        boxShadow:'0 4px 24px rgba(85,106,220,0.08)'
      }}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:20}}>
          <span style={{fontSize:16,fontWeight:700,color:C.txt}}>{selNode}</span>
          <span style={{fontSize:10,padding:'2px 8px',borderRadius:100,
            background:`${attackSurfaceColor(node.attack_surface_score)}12`,
            color:attackSurfaceColor(node.attack_surface_score),fontWeight:600
          }}>Attack Surface: {attackSurfaceLabel(node.attack_surface_score)} ({node.attack_surface_score})</span>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,marginBottom:20}}>
          <div>
            <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:10,fontWeight:600}}>Account Trust</div>
            {Object.keys(trustForInstr).length === 0 ? (
              <div style={{fontSize:13,color:C.t3,padding:12,background:'#F8F9FB',borderRadius:12,textAlign:'center'}}>No trust data</div>
            ) : (
              Object.entries(trustForInstr)
                .sort(([,a],[,b]) => TRUST_RISK[b] - TRUST_RISK[a])
                .map(([acct,trust]) => (
                  <div key={acct} style={{
                    display:'flex',alignItems:'center',gap:8,padding:'6px 10px',
                    background:'#F8F9FB',borderRadius:8,marginBottom:4,
                    borderLeft:`3px solid ${TRUST_COLOR[trust]}`
                  }}>
                    <span style={{fontSize:12,flex:1,fontFamily:"'JetBrains Mono',monospace"}}>{acct}</span>
                    <span style={{fontSize:8,padding:'2px 6px',borderRadius:100,background:`${TRUST_COLOR[trust]}12`,color:TRUST_COLOR[trust],fontWeight:600}}>{TRUST_LABEL[trust]}</span>
                  </div>
                ))
            )}
          </div>
          <div>
            <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:10,fontWeight:600}}>Attacker Footprint</div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
              {[
                {l:'Keypairs',v:fp.required_keypairs,col:C.red},
                {l:'Min SOL',v:`~${fp.required_sol.toFixed(3)}`,col:C.amb},
                {l:'Complexity',v:COMPLEXITY_LABEL[fp.complexity],col:fp.complexity==='trivial'?C.red:fp.complexity==='low'?C.amb:C.cyan},
                {l:'On-chain setup',v:fp.on_chain_setup?'Required':'No',col:fp.on_chain_setup?C.red:C.grn},
              ].map(f => (
                <div key={f.l} style={{padding:'8px 12px',background:'#F8F9FB',borderRadius:10}}>
                  <div style={{fontSize:10,color:C.t3,marginBottom:2}}>{f.l}</div>
                  <div style={{fontSize:18,fontWeight:700,color:f.col,fontFamily:"'Playfair Display',serif"}}>{f.v}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {edges.filter(e => e.from === selNode).length > 0 && (
          <div>
            <div style={{fontSize:11,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:10,fontWeight:600}}>CPI Calls</div>
            {edges.filter(e => e.from === selNode).map((e,i) => (
              <div key={i} style={{padding:'8px 12px',background:'#F8F9FB',borderRadius:8,marginBottom:4,border:`1px solid ${C.bdr}`}}>
                <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:4}}>
                  <span style={{fontSize:12,fontWeight:600,color:C.cyan}}>{e.to}</span>
                  <span style={{fontSize:9,padding:'1px 6px',borderRadius:6,background:`${C.cyan}10`,color:C.cyan}}>{e.cpi_type}</span>
                  {e.uses_pda_signer && <span style={{fontSize:9,color:C.grn}}>PDA signer</span>}
                </div>
                <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                  {e.accounts_passed.slice(0,5).map(a => (
                    <span key={a.account_name} style={{fontSize:8,padding:'1px 5px',borderRadius:4,background:`${TRUST_COLOR[a.trust]}10`,color:TRUST_COLOR[a.trust]}}>{a.account_name}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>;
    })()}

    {/* Shared accounts */}
    {report.data_flow.shared_accounts.length > 0 && (
      <Sec title="Shared Accounts" sub="Accounts used across multiple instructions — trust inconsistency = privilege escalation risk">
        {report.data_flow.shared_accounts.map(sa => (
          <div key={sa.account_name} style={{
            padding:'14px 16px',background:'#fff',
            border:`1px solid ${sa.trust_inconsistent ? C.amb : C.bdr}`,
            borderRadius:16,marginBottom:8
          }}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
              <span style={{fontSize:15,fontWeight:600,color:C.txt}}>{sa.account_name}</span>
              {sa.trust_inconsistent && <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${C.amb}12`,color:C.amb,fontWeight:600}}>⚠ trust inconsistent</span>}
              <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${TRUST_COLOR[sa.max_trust_risk]}10`,color:TRUST_COLOR[sa.max_trust_risk],fontWeight:500}}>max: {TRUST_LABEL[sa.max_trust_risk]}</span>
            </div>
            <div style={{display:'flex',gap:5,flexWrap:'wrap'}}>
              {sa.used_in.map(i => <span key={i} style={{fontSize:11,padding:'3px 10px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500,border:`1px solid ${C.cyan}15`}}>{i}</span>)}
            </div>
            {sa.trust_inconsistent && <p style={{fontSize:13,color:C.amb,marginTop:8,lineHeight:1.6}}>Attacker exploiting a weaker instruction may position for a stronger one.</p>}
          </div>
        ))}
      </Sec>
    )}
  </div>);
}
