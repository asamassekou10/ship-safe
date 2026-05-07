'use client';

import { useEffect, useRef, useState } from 'react';
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';
import styles from './AgentNetwork.module.css';

type Kind = 'core' | 'agent' | 'repo' | 'mcp';

type NetNode = SimulationNodeDatum & {
  id: string;
  label: string;
  kind: Kind;
  flashUntil?: number;
};

type LinkSeed = { source: string; target: string };
type SimLink = SimulationLinkDatum<NetNode>;

const seedNodes: NetNode[] = [
  { id: 'core', label: 'Ship Safe', kind: 'core' },
  { id: 'a1', label: 'SecretsAgent', kind: 'agent' },
  { id: 'a2', label: 'AgenticSec', kind: 'agent' },
  { id: 'a3', label: 'MCPSecurity', kind: 'agent' },
  { id: 'a4', label: 'ConfigAuditor', kind: 'agent' },
  { id: 'a5', label: 'DepsScanner', kind: 'agent' },
  { id: 'r1', label: 'api-gateway', kind: 'repo' },
  { id: 'r2', label: 'web-app', kind: 'repo' },
  { id: 'r3', label: 'agent-router', kind: 'repo' },
  { id: 'm1', label: 'mcp/filesystem', kind: 'mcp' },
  { id: 'm2', label: 'mcp/github', kind: 'mcp' },
  { id: 'm3', label: 'mcp/vault', kind: 'mcp' },
];

const seedLinks: LinkSeed[] = [
  { source: 'core', target: 'a1' },
  { source: 'core', target: 'a2' },
  { source: 'core', target: 'a3' },
  { source: 'core', target: 'a4' },
  { source: 'core', target: 'a5' },
  { source: 'a1', target: 'r1' },
  { source: 'a1', target: 'r2' },
  { source: 'a2', target: 'r3' },
  { source: 'a3', target: 'm1' },
  { source: 'a3', target: 'm2' },
  { source: 'a3', target: 'm3' },
  { source: 'a4', target: 'm1' },
  { source: 'a4', target: 'r1' },
  { source: 'a5', target: 'r2' },
  { source: 'a5', target: 'r3' },
];

const findings = [
  { node: 'r1', label: 'Hardcoded sk_live_ in api-gateway/upload.ts', tag: 'SECRET-001', file: 'api-gateway/upload.ts', line: 14, snippet: 'const stripe = new Stripe("sk_live_4eC3XHa0…");', column: 28, hint: 'rotate via stripe.dashboard' },
  { node: 'm3', label: 'mcp/vault token over plaintext HTTP', tag: 'MCP-003', file: '.mcp/config.json', line: 7, snippet: '"transport": "http://vault.internal:8200"', column: 16, hint: 'switch transport to https://' },
  { node: 'r3', label: 'Prompt injection in agent-router tool description', tag: 'LLM-014', file: 'agents/router.ts', line: 88, snippet: 'description: `Run: ${userQuery}` // template-leaked', column: 22, hint: 'sanitize tool descriptions' },
  { node: 'r2', label: 'Outdated next dependency (CVE-2026-12)', tag: 'DEP-029', file: 'package.json', line: 23, snippet: '"next": "14.2.3"', column: 11, hint: 'bump to ^15.5.0' },
  { node: 'm2', label: 'mcp/github allow-list missing', tag: 'MCP-007', file: '.mcp/github.json', line: 4, snippet: '"repos": "*"', column: 11, hint: 'pin to explicit repo list' },
];

export type Finding = typeof findings[number];

type ActivePulse = {
  link: SimLink;
  start: number;
  duration: number;
  reverse: boolean;
};

export type NetworkEvent =
  | { kind: 'pulse'; from: string; to: string; t: number }
  | { kind: 'flash'; node: string; tag: string; t: number }
  | { kind: 'tick'; label: string; t: number };

type Props = {
  onFinding?: (f: Finding) => void;
  onEvent?: (e: NetworkEvent) => void;
};

export default function AgentNetwork({ onFinding, onEvent }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number>(0);
  const pulsesRef = useRef<ActivePulse[]>([]);
  const lastPulseRef = useRef(0);
  const lastFindingRef = useRef(0);
  const lastTickRef = useRef(0);
  const onFindingRef = useRef(onFinding);
  const onEventRef = useRef(onEvent);
  onFindingRef.current = onFinding;
  onEventRef.current = onEvent;
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const wrap = wrapRef.current;
    const canvas = canvasRef.current;
    if (!wrap || !canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const nodes: NetNode[] = seedNodes.map((n) => ({ ...n }));
    const links: SimLink[] = seedLinks.map((l) => ({ source: l.source, target: l.target }));

    let width = 0;
    let height = 0;
    let dpr = 1;
    const core = nodes.find((n) => n.id === 'core')!;

    const resize = () => {
      const rect = wrap.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // Pin core to centre — bolt SVG sits there
      core.fx = width / 2;
      core.fy = height / 2;
      sim.force('center', forceCenter(width / 2, height / 2));
      sim.alpha(0.6).restart();
    };

    const sim = forceSimulation<NetNode>(nodes)
      .force(
        'link',
        forceLink<NetNode, SimLink>(links)
          .id((d) => d.id)
          .distance((l) => {
            const tgt = (typeof l.target === 'object' ? l.target : nodes.find((n) => n.id === l.target)) as NetNode | undefined;
            return tgt?.kind === 'core' ? 95 : 70;
          })
          .strength(0.55),
      )
      .force('charge', forceManyBody<NetNode>().strength((d) => (d.kind === 'core' ? -380 : -180)))
      .force(
        'collide',
        forceCollide<NetNode>().radius((d) => (d.kind === 'core' ? 36 : 24)),
      )
      .alphaDecay(0.04);

    setReady(true);

    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    resize();

    const colorFor = (kind: Kind, isFlash: boolean) => {
      if (isFlash) return { fill: 'rgba(248, 113, 113, 0.95)', glow: 'rgba(248, 113, 113, 0.45)' };
      switch (kind) {
        case 'core':
          return { fill: 'rgba(34, 211, 238, 0.0)', glow: 'rgba(34, 211, 238, 0.45)' };
        case 'agent':
          return { fill: 'rgba(34, 211, 238, 0.85)', glow: 'rgba(34, 211, 238, 0.28)' };
        case 'repo':
          return { fill: 'rgba(226, 232, 240, 0.92)', glow: 'rgba(226, 232, 240, 0.18)' };
        case 'mcp':
          return { fill: 'rgba(148, 163, 184, 0.85)', glow: 'rgba(148, 163, 184, 0.20)' };
      }
    };

    const radiusFor = (kind: Kind) => (kind === 'core' ? 22 : kind === 'agent' ? 7 : 5);

    const draw = (now: number) => {
      ctx.clearRect(0, 0, width, height);

      // Edges — dashed blueprint
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(79, 93, 117, 0.45)';
      ctx.setLineDash([4, 5]);
      links.forEach((l) => {
        const s = l.source as NetNode;
        const t = l.target as NetNode;
        if (s?.x == null || t?.x == null) return;
        ctx.beginPath();
        ctx.moveTo(s.x!, s.y!);
        ctx.lineTo(t.x!, t.y!);
        ctx.stroke();
      });
      ctx.setLineDash([]);

      // Pulses
      const alivePulses: ActivePulse[] = [];
      pulsesRef.current.forEach((p) => {
        const t = (now - p.start) / p.duration;
        if (t >= 1) {
          const target = (p.reverse ? p.link.source : p.link.target) as NetNode;
          if (target) target.flashUntil = now + 600;
          return;
        }
        alivePulses.push(p);
        const a = (p.reverse ? p.link.target : p.link.source) as NetNode;
        const b = (p.reverse ? p.link.source : p.link.target) as NetNode;
        if (a?.x == null || b?.x == null) return;
        const x = a.x! + (b.x! - a.x!) * t;
        const y = a.y! + (b.y! - a.y!) * t;
        const grad = ctx.createRadialGradient(x, y, 0, x, y, 14);
        grad.addColorStop(0, 'rgba(34, 211, 238, 0.85)');
        grad.addColorStop(0.4, 'rgba(34, 211, 238, 0.3)');
        grad.addColorStop(1, 'rgba(34, 211, 238, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(x, y, 14, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = 'rgba(255, 255, 255, 0.95)';
        ctx.beginPath();
        ctx.arc(x, y, 2.2, 0, Math.PI * 2);
        ctx.fill();
      });
      pulsesRef.current = alivePulses;

      // Nodes (skip core — bolt SVG handles that)
      ctx.font = '500 10.5px var(--font-geist-mono, ui-monospace, monospace)';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      nodes.forEach((n) => {
        if (n.x == null || n.y == null) return;
        if (n.kind === 'core') return;
        const isFlash = (n.flashUntil ?? 0) > now;
        const { fill, glow } = colorFor(n.kind, isFlash);
        const r = radiusFor(n.kind) + (isFlash ? 3 : 0);

        // Outer glow
        const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 4.2);
        grad.addColorStop(0, glow);
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r * 4.2, 0, Math.PI * 2);
        ctx.fill();

        // Node body
        ctx.fillStyle = fill;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fill();

        // Label
        ctx.fillStyle = 'rgba(184, 179, 176, 0.85)';
        ctx.fillText(n.label, n.x, n.y + r + 6);
      });
    };

    const tick = (now: number) => {
      if (!reduced && now - lastPulseRef.current > 1100) {
        lastPulseRef.current = now;
        const link = links[Math.floor(Math.random() * links.length)];
        const reverse = Math.random() < 0.3;
        pulsesRef.current.push({ link, start: now, duration: 1400 + Math.random() * 500, reverse });
        const src = (reverse ? link.target : link.source) as NetNode | string;
        const dst = (reverse ? link.source : link.target) as NetNode | string;
        const fromId = typeof src === 'string' ? src : src.id;
        const toId = typeof dst === 'string' ? dst : dst.id;
        onEventRef.current?.({ kind: 'pulse', from: fromId, to: toId, t: now });
      }
      if (!reduced && now - lastFindingRef.current > 5500) {
        lastFindingRef.current = now;
        const f = findings[Math.floor(Math.random() * findings.length)];
        const node = nodes.find((n) => n.id === f.node);
        if (node) node.flashUntil = now + 1200;
        onFindingRef.current?.(f);
        onEventRef.current?.({ kind: 'flash', node: f.node, tag: f.tag, t: now });
      }
      if (!reduced && now - lastTickRef.current > 9000) {
        lastTickRef.current = now;
        onEventRef.current?.({ kind: 'tick', label: 'scan complete', t: now });
      }
      draw(now);
      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);

    if (reduced) {
      sim.alpha(1).tick(160).stop();
      draw(performance.now());
    }

    return () => {
      cancelAnimationFrame(rafRef.current);
      ro.disconnect();
      sim.stop();
    };
  }, []);

  return (
    <div ref={wrapRef} className={styles.wrap}>
      <canvas ref={canvasRef} className={styles.canvas} aria-hidden="true" />
      {/* Brand bolt at the pinned core position */}
      <div className={styles.coreMark} aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 2L4 13h7l-1 9 9-12h-7l1-8z" />
        </svg>
      </div>
      {!ready && <div className={styles.skeleton} aria-hidden="true" />}
    </div>
  );
}
