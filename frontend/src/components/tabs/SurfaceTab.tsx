import React, { useState, useMemo, useRef, useEffect, useCallback } from 'react';
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

        for (const other of nodes) {
          if (other.id === n.id) continue;
          const dx = n.x - other.x, dy = n.y - other.y;
          const dist = Math.max(Math.hypot(dx, dy), 1);
          fx += (dx / dist) * repel / (dist * dist);
          fy += (dy / dist) * repel / (dist * dist);
        }

        for (const e of edges) {
          const target = e.from === n.id ? nodes.find(nd => nd.id === e.to)
            : e.to === n.id ? nodes.find(nd => nd.id === e.from)
            : undefined;
          if (!target) continue;
          const dx = target.x - n.x, dy = target.y - n.y;
          fx += dx * attract;
          fy += dy * attract;
        }

        fx += (centerX - n.x) * 0.001;
        fy += (centerY - n.y) * 0.001;

        n.vx = (n.vx + fx) * damping;
        n.vy = (n.vy + fy) * damping;
        n.x += n.vx;
        n.y += n.vy;

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

const ARROW_ID = 'graph-arrow';
const GLOW_FILTER_ID = 'graph-glow';
const NODE_GRADIENT_INSTR = 'node-grad-instr';
const NODE_GRADIENT_CPI = 'node-grad-cpi';
const NODE_GRADIENT_ACCT = 'node-grad-acct';

function getQuadraticCurve(x1: number, y1: number, x2: number, y2: number): string {
  if (x1 === x2 && y1 === y2) return '';
  const cx = (x1 + x2) / 2;
  const cy = (y1 + y2) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy);
  const nx = -dy / len * 20, ny = dx / len * 20;
  return `M${x1},${y1} Q${cx + nx},${cy + ny} ${x2},${y2}`;
}

export function SurfaceTab({report}:{report:AnalysisReport}) {
  const [active, setActive] = useState<string|null>(null);
  const [hover, setHover] = useState<string|null>(null);
  const [tooltipPos, setTooltipPos] = useState<{x:number;y:number}|null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);

  const instrNodes = report.call_graph.nodes.filter(n => n.node_type === 'instruction');

  const { graphNodes, graphEdges } = useMemo(() => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const added = new Set<string>();
    const rng = (seed: number) => { let s = seed; return () => { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646; }; };

    const instrPositions: Array<{id:string,x:number,y:number}> = [];
    const instrCount = instrNodes.length;
    instrNodes.forEach((n, i) => {
      const id = n.id;
      const angle = (i / instrCount) * Math.PI * 2 - Math.PI / 2;
      const radius = 160 + (i % 3) * 20;
      instrPositions.push({
        id,
        x: 400 + Math.cos(angle) * radius,
        y: 150 + Math.sin(angle) * radius * 0.5,
      });
      const rand = rng(id.length + id.charCodeAt(0));
      nodes.push({
        id, label: id,
        type: 'instruction',
        x: instrPositions[i].x + (rand() - 0.5) * 20,
        y: instrPositions[i].y + (rand() - 0.5) * 20,
        vx: 0, vy: 0,
        attack_surface_score: n.attack_surface_score,
      });
      added.add(id);
    });

    for (const e of report.call_graph.edges) {
      if (!added.has(e.to)) {
        const rand = rng(e.to.length + e.to.charCodeAt(0));
        nodes.push({
          id: e.to, label: e.to.split('::').pop() || e.to,
          type: 'cpi', x: 200 + rand() * 400,
          y: 280 + rand() * 120, vx: 0, vy: 0,
        });
        added.add(e.to);
      }
      edges.push({ from: e.from, to: e.to, label: e.cpi_type, cpi_type: e.cpi_type });
    }

    const acctAdded = new Set<string>();
    report.data_flow.shared_accounts.forEach((sa, i) => {
      if (acctAdded.has(sa.account_name)) return;
      acctAdded.add(sa.account_name);
      const trust = sa.max_trust_risk;
      const id = `acct:${sa.account_name}`;
      const rand = rng(sa.account_name.length + sa.account_name.charCodeAt(0));
      nodes.push({
        id, label: sa.account_name,
        type: 'account',
        x: 100 + i * 60 + rand() * 30,
        y: 410 + rand() * 40,
        vx: 0, vy: 0,
        trust,
      });
      for (const instr of sa.used_in) {
        if (added.has(instr)) {
          edges.push({ from: instr, to: id });
        }
      }
    });

    return { graphNodes: nodes, graphEdges: edges };
  }, [report]);

  useForceGraph(graphNodes, graphEdges);

  const selNode = hover || active;

  const handleMouseMove = useCallback((e: React.MouseEvent, nodeId: string) => {
    if (svgRef.current) {
      const rect = svgRef.current.getBoundingClientRect();
      setTooltipPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
    }
    setHover(nodeId);
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.max(0.3, Math.min(3, z * delta)));
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.target === svgRef.current || (e.target as SVGElement).tagName === 'svg') {
      setIsPanning(true);
      setPanStart({ x: e.clientX, y: e.clientY });
      setPanOffset({ x: pan.x, y: pan.y });
    }
  }, [pan]);

  const handleMouseMovePan = useCallback((e: React.MouseEvent) => {
    if (isPanning) {
      setPan({
        x: panOffset.x + (e.clientX - panStart.x),
        y: panOffset.y + (e.clientY - panStart.y),
      });
    }
  }, [isPanning, panOffset, panStart]);

  const handleMouseUp = useCallback(() => {
    setIsPanning(false);
  }, []);

  const nodeColors: Record<string, string> = {
    instruction: C.cyan,
    cpi: C.amb,
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

    <div style={{
      background: C.bg2, border: `1px solid ${C.bdr}`, borderRadius: 24,
      padding: 0, marginBottom: 24, position: 'relative', overflow: 'hidden',
      minHeight: 500, boxShadow: '0 0 60px rgba(85,106,220,0.05)',
    }}>
      <svg
        ref={svgRef}
        width="100%" height="500"
        viewBox="0 0 800 500"
        style={{ display: 'block', cursor: isPanning ? 'grabbing' : 'grab' }}
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMovePan}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          <marker id={ARROW_ID} viewBox="0 0 10 10" refX="8" refY="5"
            markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 Z" fill={C.bdr} />
          </marker>

          <marker id="arrow-active" viewBox="0 0 10 10" refX="8" refY="5"
            markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L10,5 L0,10 Z" fill={C.cyan} />
          </marker>

          <filter id={GLOW_FILTER_ID} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="glow-strong" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feComponentTransfer in="blur" result="glow">
              <feFuncA type="linear" slope="0.6" />
            </feComponentTransfer>
            <feMerge>
              <feMergeNode in="glow" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <linearGradient id={NODE_GRADIENT_INSTR} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#7B93FF" stopOpacity="1" />
            <stop offset="100%" stopColor={C.cyan} stopOpacity="1" />
          </linearGradient>

          <linearGradient id={NODE_GRADIENT_CPI} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={C.amb} stopOpacity="0.9" />
            <stop offset="100%" stopColor="#FFB472" stopOpacity="0.6" />
          </linearGradient>

          <linearGradient id={NODE_GRADIENT_ACCT} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={C.pur} stopOpacity="0.9" />
            <stop offset="100%" stopColor="#BDA4FF" stopOpacity="0.6" />
          </linearGradient>

          <radialGradient id="node-glow-instr" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={C.cyan} stopOpacity="0.2" />
            <stop offset="100%" stopColor={C.cyan} stopOpacity="0" />
          </radialGradient>

          <filter id="node-shadow">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="rgba(0,0,0,0.12)" />
          </filter>

          <filter id="node-shadow-active">
            <feDropShadow dx="0" dy="2" stdDeviation="8" floodColor="rgba(85,106,220,0.35)" />
          </filter>

          <filter id="label-bg">
            <feMorphology in="SourceAlpha" operator="dilate" radius="2" />
            <feGaussianBlur stdDeviation="1" />
            <feComponentTransfer><feFuncA type="linear" slope="0.85" /></feComponentTransfer>
            <feMerge>
              <feMergeNode />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <g transform={`translate(${pan.x * zoom},${pan.y * zoom}) scale(${zoom})`}>
          {graphEdges.map((e,i) => {
            const from = graphNodes.find(n => n.id === e.from);
            const to = graphNodes.find(n => n.id === e.to);
            if (!from || !to) return null;
            const isActive = selNode && (e.from === selNode || e.to === selNode);
            const path = getQuadraticCurve(from.x, from.y, to.x, to.y);
            if (!path) return null;
            return <g key={`e${i}`}>
              <path
                d={path}
                fill="none"
                stroke={isActive ? C.cyan : C.bdr}
                strokeWidth={isActive ? 2 : 1}
                strokeOpacity={isActive ? 0.7 : 0.25}
                markerEnd={isActive ? 'url(#arrow-active)' : undefined}
                style={{ transition: 'stroke-opacity 200ms ease-out, stroke-width 200ms ease-out' }}
              />
              {e.label && isActive && (
                <text
                  x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 10}
                  fontSize={9} fill={C.t2}
                  textAnchor="middle" fontWeight={500}
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >{e.label}</text>
              )}
            </g>;
          })}

          {graphNodes.map(n => {
            const isActive = selNode === n.id;
            const color = nodeColors[n.type];
            const scoreCol = n.attack_surface_score ? attackSurfaceColor(n.attack_surface_score) : color;

            return <g
              key={n.id}
              onMouseEnter={(e) => handleMouseMove(e, n.id)}
              onMouseLeave={() => { setHover(null); setTooltipPos(null); }}
              onClick={() => setActive(active === n.id ? null : n.id)}
              style={{ cursor: 'pointer' }}
            >
              {n.type === 'instruction' ? (
                <>
                  {isActive && (
                    <circle cx={n.x} cy={n.y} r={32}
                      fill="url(#node-glow-instr)"
                      style={{ transition: 'opacity 200ms ease-out' }}
                    />
                  )}
                  <circle cx={n.x} cy={n.y} r={22}
                    fill={C.bg2} opacity={isActive ? 0.8 : 0}
                    style={{ transition: 'opacity 200ms ease-out' }}
                  />
                  <circle cx={n.x} cy={n.y} r={18}
                    fill={isActive ? `url(#${NODE_GRADIENT_INSTR})` : `url(#${NODE_GRADIENT_INSTR})`}
                    stroke={isActive ? 'rgba(255,255,255,0.6)' : 'rgba(255,255,255,0.3)'}
                    strokeWidth={isActive ? 2.5 : 1.5}
                    opacity={selNode && !isActive ? 0.2 : 1}
                    filter={isActive ? 'url(#node-shadow-active)' : 'url(#node-shadow)'}
                    style={{ transition: 'stroke-width 150ms ease-out, opacity 200ms ease-out' }}
                  />
                  {isActive && (
                    <>
                      <circle cx={n.x} cy={n.y} r={18}
                        fill="none" stroke={C.cyan} strokeWidth={2}
                        opacity="0.5"
                        filter="url(#glow-strong)"
                        style={{ transition: 'opacity 200ms ease-out', pointerEvents: 'none' }}
                      />
                      <circle cx={n.x} cy={n.y} r={22}
                        fill="none" stroke={C.cyan} strokeWidth={1}
                        opacity="0.2"
                        style={{ transition: 'opacity 200ms ease-out', pointerEvents: 'none' }}
                      />
                    </>
                  )}
                  {n.attack_surface_score !== undefined && (
                    <text x={n.x + 22} y={n.y - 14} fontSize={8} fill={scoreCol}
                      textAnchor="start" fontWeight={700}
                      opacity={selNode && !isActive ? 0.2 : 0.8}
                      style={{ fontFamily: "'JetBrains Mono', monospace", transition: 'opacity 200ms ease-out' }}
                    >⬆ {n.attack_surface_score}</text>
                  )}
                </>
              ) : n.type === 'cpi' ? (
                <>
                  <rect x={n.x - 16} y={n.y - 10} width={32} height={20} rx={6}
                    fill={isActive ? `url(#${NODE_GRADIENT_CPI})` : '#fff'}
                    stroke={color}
                    strokeWidth={isActive ? 2.5 : 1.5}
                    opacity={selNode && !isActive ? 0.2 : 1}
                    filter={isActive ? 'url(#node-shadow-active)' : 'url(#node-shadow)'}
                    style={{ transition: 'stroke-width 150ms ease-out, opacity 200ms ease-out' }}
                  />
                  <text x={n.x} y={n.y + 4} fontSize={8} fill={isActive ? '#fff' : color}
                    textAnchor="middle" fontWeight={600}
                    opacity={selNode && !isActive ? 0.2 : 1}
                    style={{ fontFamily: "'JetBrains Mono', monospace", transition: 'opacity 200ms ease-out' }}
                  >{n.label.slice(0, 14)}</text>
                </>
              ) : (
                <>
                  <circle cx={n.x} cy={n.y} r={8}
                    fill={isActive ? `url(#${NODE_GRADIENT_ACCT})` : '#fff'}
                    stroke={color}
                    strokeWidth={isActive ? 2.5 : 1.5}
                    opacity={selNode && !isActive ? 0.2 : 1}
                    filter={isActive ? 'url(#node-shadow-active)' : 'url(#node-shadow)'}
                    style={{ transition: 'stroke-width 150ms ease-out, opacity 200ms ease-out' }}
                  />
                  {n.label.length > 10 ? (
                    <>
                      <text x={n.x + 14} y={n.y - 2} fontSize={8} fill={C.t2}
                        textAnchor="start" fontWeight={500}
                        opacity={selNode && !isActive ? 0.2 : 0.7}
                        style={{ fontFamily: "'JetBrains Mono', monospace", transition: 'opacity 200ms ease-out' }}
                      >{n.label.slice(0, 18)}</text>
                      {isActive && n.label.length > 18 && (
                        <text x={n.x + 14} y={n.y + 8} fontSize={7} fill={C.t3}
                          textAnchor="start"
                          style={{ fontFamily: "'JetBrains Mono', monospace" }}
                        >{n.label.slice(18)}</text>
                      )}
                    </>
                  ) : (
                    <text x={n.x + 14} y={n.y + 2} fontSize={8} fill={C.t2}
                      textAnchor="start" fontWeight={500}
                      opacity={selNode && !isActive ? 0.2 : 0.7}
                      style={{ fontFamily: "'JetBrains Mono', monospace", transition: 'opacity 200ms ease-out' }}
                    >{n.label}</text>
                  )}
                </>
              )}
            </g>;
          })}
        </g>
      </svg>

      {selNode && tooltipPos && !instrNodes.find(n => n.id === selNode) && (
        <div style={{
          position: 'absolute',
          left: Math.min(tooltipPos.x + 16, 600),
          top: Math.max(tooltipPos.y - 40, 8),
          background: 'rgba(255,255,255,0.95)',
          backdropFilter: 'blur(12px)',
          border: `1px solid ${C.bdr}`,
          borderRadius: 12,
          padding: '8px 14px',
          fontSize: 12,
          fontFamily: "'Inter', sans-serif",
          color: C.txt,
          boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
          pointerEvents: 'none',
          zIndex: 10,
          whiteSpace: 'nowrap',
        }}>
          <strong>{selNode.replace('acct:', '')}</strong>
          {graphNodes.find(nd => nd.id === selNode)?.trust && (
            <span style={{ marginLeft: 8, color: TRUST_COLOR[graphNodes.find(nd => nd.id === selNode)!.trust!], fontWeight: 600 }}>
              {TRUST_LABEL[graphNodes.find(nd => nd.id === selNode)!.trust!]}
            </span>
          )}
        </div>
      )}

      <div style={{
        position: 'absolute', bottom: 16, right: 16, display: 'flex', gap: 6,
        opacity: zoom !== 1 ? 1 : 0, transition: 'opacity 200ms',
        pointerEvents: zoom !== 1 ? 'auto' : 'none',
      }}>
        <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
          style={{
            fontSize: 11, padding: '4px 12px', borderRadius: 8,
            border: `1px solid ${C.bdr}`, background: '#fff', cursor: 'pointer',
            color: C.t2, fontFamily: "'Inter', sans-serif", fontWeight: 500,
          }}>Reset</button>
      </div>
    </div>

    {selNode && instrNodes.find(n => n.id === selNode) && (() => {
      const node = instrNodes.find(n => n.id === selNode)!;
      const trustForInstr = (report.data_flow.trust_map[selNode] || {}) as Record<string, AccountTrust>;
      const edges = report.call_graph.edges.filter(e => e.from === selNode || e.to === selNode);
      const fp = node.attacker_footprint;

      return <div style={{
        background: 'rgba(255,255,255,0.85)',
        backdropFilter: 'blur(16px)',
        border: `1px solid ${C.cyan}25`,
        borderRadius: 20,
        padding: 28,
        marginBottom: 24,
        boxShadow: '0 4px 32px rgba(85,106,220,0.1)',
        animation: 'fadeIn 200ms ease-out',
      }}>
        <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:24}}>
          <div style={{
            width:8,height:8,borderRadius:'50%',background:C.cyan,
            boxShadow:`0 0 16px ${C.cyan}50`,
          }} />
          <span style={{fontSize:18,fontWeight:700,color:C.txt,fontFamily:"'Inter',sans-serif",letterSpacing:'-0.01em'}}>{selNode}</span>
          <span style={{
            fontSize:10,padding:'3px 10px',borderRadius:100,
            background:`${attackSurfaceColor(node.attack_surface_score)}15`,
            color:attackSurfaceColor(node.attack_surface_score),fontWeight:600,
            fontFamily:"'Inter',sans-serif",
            border:`1px solid ${attackSurfaceColor(node.attack_surface_score)}25`,
          }}>Attack Surface: {attackSurfaceLabel(node.attack_surface_score)} ({node.attack_surface_score})</span>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:24,marginBottom:24}}>
          <div style={{background:'rgba(248,249,251,0.8)',borderRadius:16,padding:20,border:`1px solid ${C.bdr}`}}>
            <div style={{fontSize:10,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:14,fontWeight:700}}>Account Trust</div>
            {Object.keys(trustForInstr).length === 0 ? (
              <div style={{fontSize:13,color:C.t3,padding:12,background:C.bg,borderRadius:10,textAlign:'center'}}>No trust data</div>
            ) : (
              Object.entries(trustForInstr)
                .sort(([,a],[,b]) => TRUST_RISK[b] - TRUST_RISK[a])
                .map(([acct,trust]) => (
                  <div key={acct} style={{
                    display:'flex',alignItems:'center',gap:10,padding:'8px 12px',
                    background:C.bg,borderRadius:10,marginBottom:6,
                    borderLeft:`3px solid ${TRUST_COLOR[trust]}`
                  }}>
                    <span style={{fontSize:11,flex:1,fontFamily:"'JetBrains Mono',monospace",color:C.txt}}>{acct}</span>
                    <span style={{fontSize:8,padding:'2px 8px',borderRadius:100,background:`${TRUST_COLOR[trust]}12`,color:TRUST_COLOR[trust],fontWeight:700}}>{TRUST_LABEL[trust]}</span>
                  </div>
                ))
            )}
          </div>
          <div style={{background:'rgba(248,249,251,0.8)',borderRadius:16,padding:20,border:`1px solid ${C.bdr}`}}>
            <div style={{fontSize:10,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:14,fontWeight:700}}>Attacker Footprint</div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
              {[
                {l:'Keypairs',v:fp.required_keypairs,col:C.red},
                {l:'Min SOL',v:`~${fp.required_sol.toFixed(3)}`,col:C.amb},
                {l:'Complexity',v:COMPLEXITY_LABEL[fp.complexity],col:fp.complexity==='trivial'?C.red:fp.complexity==='low'?C.amb:C.cyan},
                {l:'On-chain setup',v:fp.on_chain_setup?'Required':'No',col:fp.on_chain_setup?C.red:C.grn},
              ].map(f => (
                <div key={f.l} style={{padding:'10px 14px',background:C.bg,borderRadius:12}}>
                  <div style={{fontSize:10,color:C.t3,marginBottom:4,fontWeight:500}}>{f.l}</div>
                  <div style={{fontSize:18,fontWeight:700,color:f.col,fontFamily:"'JetBrains Mono',monospace"}}>{f.v}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {edges.filter(e => e.from === selNode).length > 0 && (
          <div>
            <div style={{fontSize:10,color:C.t3,textTransform:'uppercase',letterSpacing:'.08em',marginBottom:12,fontWeight:700}}>CPI Calls</div>
            {edges.filter(e => e.from === selNode).map((e,i) => (
              <div key={i} style={{padding:'10px 14px',background:'rgba(248,249,251,0.8)',borderRadius:12,marginBottom:6,border:`1px solid ${C.bdr}`}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <span style={{fontSize:12,fontWeight:600,color:C.cyan,fontFamily:"'JetBrains Mono',monospace"}}>{e.to}</span>
                  <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${C.cyan}12`,color:C.cyan,fontWeight:600}}>{e.cpi_type}</span>
                  {e.uses_pda_signer && <span style={{fontSize:9,color:C.grn,fontWeight:600}}>PDA signer</span>}
                </div>
                <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
                  {e.accounts_passed.slice(0,6).map(a => (
                    <span key={a.account_name} style={{fontSize:8,padding:'2px 6px',borderRadius:6,background:`${TRUST_COLOR[a.trust]}12`,color:TRUST_COLOR[a.trust],fontWeight:600,fontFamily:"'JetBrains Mono',monospace"}}>{a.account_name}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>;
    })()}

    {report.data_flow.shared_accounts.length > 0 && (
      <Sec title="Shared Accounts" sub="Accounts used across multiple instructions — trust inconsistency = privilege escalation risk">
        {report.data_flow.shared_accounts.map(sa => (
          <div key={sa.account_name} style={{
            padding:'14px 16px',background:C.bg2,
            border:`1px solid ${sa.trust_inconsistent ? C.amb : C.bdr}`,
            borderRadius:16,marginBottom:8,
            boxShadow: sa.trust_inconsistent ? `0 0 24px ${C.amb}10` : 'none',
          }}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
              <span style={{fontSize:14,fontWeight:600,color:C.txt,fontFamily:"'JetBrains Mono',monospace"}}>{sa.account_name}</span>
              {sa.trust_inconsistent && <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${C.amb}15`,color:C.amb,fontWeight:700,border:`1px solid ${C.amb}20`}}>⚠ trust inconsistent</span>}
              <span style={{fontSize:9,padding:'2px 8px',borderRadius:100,background:`${TRUST_COLOR[sa.max_trust_risk]}12`,color:TRUST_COLOR[sa.max_trust_risk],fontWeight:600}}>max: {TRUST_LABEL[sa.max_trust_risk]}</span>
            </div>
            <div style={{display:'flex',gap:5,flexWrap:'wrap'}}>
              {sa.used_in.map(i => <span key={i} style={{fontSize:11,padding:'3px 10px',borderRadius:100,background:`${C.cyan}10`,color:C.cyan,fontWeight:500,border:`1px solid ${C.cyan}15`,fontFamily:"'JetBrains Mono',monospace"}}>{i}</span>)}
            </div>
            {sa.trust_inconsistent && <p style={{fontSize:13,color:C.amb,marginTop:8,lineHeight:1.6,fontFamily:"'Inter',sans-serif"}}>Attacker exploiting a weaker instruction may position for a stronger one.</p>}
          </div>
        ))}
      </Sec>
    )}
  </div>);
}
