'use client';
import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useToast } from '@/app/app/Toast';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import s from './scan-detail.module.css';

/* ── Types ────────────────────────────────────────────── */

interface Finding {
  file: string;
  line?: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  rule: string;
  title: string;
  description?: string;
  fix?: string;
  cwe?: string;
  owasp?: string;
}

interface DepVuln {
  severity: string;
  package: string;
  description: string;
}

interface RemediationItem {
  priority: number;
  severity: string;
  category: string;
  categoryLabel?: string;
  title: string;
  file?: string;
  action: string;
  effort?: string;
}

interface AgentResult {
  agent: string;
  category: string;
  findingCount: number;
  success: boolean;
  error?: string;
}

interface CategoryInfo {
  label: string;
  findingCount: number;
  deduction: number;
  counts: { critical: number; high: number; medium: number; low: number };
}

interface Report {
  score?: number;
  grade?: string;
  gradeLabel?: string;
  totalFindings?: number;
  totalDepVulns?: number;
  categories?: Record<string, CategoryInfo>;
  findings?: Finding[];
  depVulns?: DepVuln[];
  remediationPlan?: RemediationItem[];
  agents?: AgentResult[];
  [key: string]: unknown;
}

interface ScanData {
  id: string;
  repo: string;
  branch: string;
  status: string;
  score: number | null;
  grade: string | null;
  findings: number;
  secrets: number;
  vulns: number;
  cves: number;
  duration: number | null;
  report: Report | null;
  options: Record<string, boolean> | null;
  createdAt: string;
}

/* ── Helpers ──────────────────────────────────────────── */

const scoreColor = (n: number) => n >= 80 ? '#16a34a' : n >= 60 ? '#d97706' : '#dc2626';
const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
};

function CatIcon({ k }: { k: string }) {
  const p = 'currentColor';
  switch (k) {
    case 'secrets':      return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><circle cx="8" cy="15" r="5"/><path d="M13 15h3l1-1 1 1 1-1 1 1v-3l-5-5"/></svg>;
    case 'injection':    return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>;
    case 'deps':         return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>;
    case 'auth':         return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>;
    case 'config':       return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>;
    case 'supply-chain': return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>;
    case 'api':          return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>;
    case 'llm':          return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><path d="M12 2a10 10 0 100 20A10 10 0 0012 2z"/><path d="M12 8v4l3 3"/></svg>;
    default:             return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={p} strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
  }
}

type Tab = 'findings' | 'remediation' | 'deps' | 'agents' | 'raw';

/* ── Score Gauge (SVG semicircle) ─────────────────────── */

function ScoreGauge({ score, grade }: { score: number; grade: string | null }) {
  const [display, setDisplay] = useState(0);
  const R = 68;
  const cx = 90;
  const cy = 90;
  const arcLen = Math.PI * R; // half circumference
  const dashArray = arcLen;
  const dashOffset = arcLen * (1 - display / 100);
  const color = scoreColor(score);

  useEffect(() => {
    const duration = 1600;
    const start = performance.now();
    function tick(now: number) {
      const p = Math.min((now - start) / duration, 1);
      const ep = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(ep * score));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }, [score]);

  const label = score >= 90 ? 'Ship it!' : score >= 75 ? 'Looking good' : score >= 60 ? 'Needs work' : 'At risk';

  return (
    <div className={s.gaugeWrap}>
      <svg viewBox="0 0 180 100" className={s.gaugeSvg} aria-label={`Security score: ${score} out of 100`}>
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#dc2626" />
            <stop offset="40%" stopColor="#d97706" />
            <stop offset="75%" stopColor="#06b6d4" />
            <stop offset="100%" stopColor="#16a34a" />
          </linearGradient>
          <filter id="gaugeGlow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>
        {/* Track */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round"
        />
        {/* Filled arc */}
        <path
          d={`M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dashArray}`}
          strokeDashoffset={`${dashOffset}`}
          style={{ transition: 'stroke-dashoffset 1.6s cubic-bezier(0.16,1,0.3,1), stroke 0.4s' }}
          filter="url(#gaugeGlow)"
        />
        {/* Score number */}
        <text x={cx} y={cy - 10} textAnchor="middle" className={s.gaugeNum} fill={color}>{display}</text>
        <text x={cx} y={cy + 8} textAnchor="middle" className={s.gaugeDen} fill="var(--text-dim)">/100</text>
      </svg>
      <div className={s.gaugeFooter}>
        {grade && <span className={s.gaugeGrade} style={{ color }}>{grade}</span>}
        <span className={s.gaugeLabel} style={{ color }}>{label}</span>
      </div>
      <div className={s.gaugeGlowRing} style={{ boxShadow: `0 0 40px ${color}22, 0 0 80px ${color}0a` }} />
    </div>
  );
}

/* ── Severity Donut Chart ─────────────────────────────── */

function SeverityDonut({ findings }: { findings: Finding[] }) {
  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const data = (['critical', 'high', 'medium', 'low'] as const)
    .filter(s => counts[s] > 0)
    .map(s => ({ name: s, value: counts[s], color: SEV_COLORS[s] }));

  if (data.length === 0) return null;

  return (
    <div className={s.donutWrap}>
      <div className={s.donutTitle}>Severity breakdown</div>
      <ResponsiveContainer width="100%" height={140}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="70%"
            innerRadius={42}
            outerRadius={58}
            startAngle={180}
            endAngle={0}
            paddingAngle={2}
            dataKey="value"
            animationBegin={0}
            animationDuration={1200}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} stroke="none" />
            ))}
          </Pie>
          <Tooltip
            formatter={(value, name) => [value, String(name).charAt(0).toUpperCase() + String(name).slice(1)]}
            contentStyle={{ fontSize: 12, fontFamily: 'var(--font-mono)', background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8 }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className={s.donutLegend}>
        {data.map(d => (
          <div key={d.name} className={s.donutLegendItem}>
            <span className={s.donutDot} style={{ background: d.color }} />
            <span className={s.donutLegendName}>{d.name}</span>
            <span className={s.donutLegendCount}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── OWASP Category Bar Chart ─────────────────────────── */

function OWASPChart({ categories }: { categories: Record<string, CategoryInfo> }) {
  const data = Object.entries(categories)
    .filter(([, c]) => c.findingCount > 0)
    .sort(([, a], [, b]) => b.findingCount - a.findingCount)
    .map(([, c]) => ({
      name: c.label.length > 14 ? c.label.slice(0, 13) + '…' : c.label,
      findings: c.findingCount,
      deduction: c.deduction,
      fill: c.counts.critical > 0 ? SEV_COLORS.critical
          : c.counts.high > 0    ? SEV_COLORS.high
          : c.counts.medium > 0  ? SEV_COLORS.medium
          : SEV_COLORS.low,
    }));

  if (data.length === 0) return null;

  return (
    <div className={s.barChartWrap}>
      <div className={s.barChartTitle}>Findings by category</div>
      <ResponsiveContainer width="100%" height={data.length * 38 + 20}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 40, bottom: 0, left: 0 }}
          barCategoryGap="30%"
        >
          <CartesianGrid horizontal={false} stroke="var(--border)" />
          <XAxis
            type="number"
            tick={{ fontSize: 11, fontFamily: 'var(--font-mono)', fill: 'var(--text-dim)' }}
            axisLine={false} tickLine={false}
            allowDecimals={false}
          />
          <YAxis
            type="category"
            dataKey="name"
            width={94}
            tick={{ fontSize: 11, fontFamily: 'var(--font-sans)', fill: '#6b7280' }}
            axisLine={false} tickLine={false}
          />
          <Tooltip
            formatter={(v) => [String(v) + ' findings']}
            contentStyle={{ fontSize: 12, fontFamily: 'var(--font-mono)', background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8 }}
          />
          <Bar dataKey="findings" radius={[0, 5, 5, 0]} animationBegin={200} animationDuration={1000}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.fill} fillOpacity={0.85} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── Scanning Steps (shown during progress) ──────────── */

const SCAN_STEPS = [
  { label: 'Cloning repository', desc: 'Fetching source code from GitHub', duration: 4000 },
  { label: 'Scanning for secrets', desc: 'Checking for leaked API keys, tokens, and credentials', duration: 3000 },
  { label: 'Running 18 security agents', desc: 'Injection, auth bypass, SSRF, supply chain, LLM red team, MCP security, agent config...', duration: 8000 },
  { label: 'Auditing dependencies', desc: 'Checking packages for known CVEs with EPSS scoring', duration: 5000 },
  { label: 'Computing OWASP 2025 score', desc: 'Weighing findings across 8 categories with confidence tuning', duration: 2000 },
  { label: 'Generating remediation plan', desc: 'Prioritizing fixes by severity, effort, and exploitability', duration: 2000 },
];

function ScanProgress({ startedAt }: { startedAt: string }) {
  const [activeStep, setActiveStep] = useState(0);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const tick = () => setElapsed(Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);

  useEffect(() => {
    const elapsed = Date.now() - new Date(startedAt).getTime();
    let cumulative = 0;
    let initialStep = 0;
    for (let i = 0; i < SCAN_STEPS.length; i++) {
      cumulative += SCAN_STEPS[i].duration;
      if (elapsed < cumulative) break;
      initialStep = Math.min(i + 1, SCAN_STEPS.length - 1);
    }
    setActiveStep(initialStep);

    const timers: ReturnType<typeof setTimeout>[] = [];
    cumulative = 0;
    for (let i = 0; i < SCAN_STEPS.length; i++) {
      cumulative += SCAN_STEPS[i].duration;
      const remaining = cumulative - elapsed;
      if (remaining > 0) timers.push(setTimeout(() => setActiveStep(Math.min(i + 1, SCAN_STEPS.length - 1)), remaining));
    }
    return () => timers.forEach(clearTimeout);
  }, [startedAt]);

  return (
    <div className={s.progressCard}>
      <div className={s.progressHeader}>
        <span className={s.pulseOrb} />
        <span className={s.runningText}>Scan in progress</span>
        <span className={s.progressPct}>{elapsed}s · {Math.round((activeStep / SCAN_STEPS.length) * 100)}%</span>
      </div>
      <div className={s.progressBar}>
        <div className={s.progressFill} style={{ width: `${(activeStep / SCAN_STEPS.length) * 100}%` }} />
      </div>
      <div className={s.progressSteps}>
        {SCAN_STEPS.map((step, i) => {
          const state = i < activeStep ? 'done' : i === activeStep ? 'active' : 'pending';
          return (
            <div key={i} className={`${s.progressStep} ${s[`step_${state}`]}`}>
              <div className={s.stepIndicator}>
                {state === 'done' ? (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="7" fill="#16a34a" fillOpacity="0.15"/><path d="M3.5 7l2.5 2.5 4.5-4.5" stroke="#16a34a" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                ) : state === 'active' ? (
                  <span className={s.stepSpinner} />
                ) : (
                  <span className={s.stepDot} />
                )}
              </div>
              <div className={s.stepContent}>
                <span className={s.stepLabel}>{step.label}</span>
                <span className={s.stepDesc}>{step.desc}</span>
              </div>
            </div>
          );
        })}
      </div>
      <p className={s.progressHint}>This page updates automatically when the scan completes.</p>
    </div>
  );
}

/* ── Component ────────────────────────────────────────── */

export default function ScanDetail() {
  const params = useParams();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('findings');
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [catFilter, setCatFilter] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  const [showRaw, setShowRaw] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [scoreTrend, setScoreTrend] = useState<{ score: number; date: string }[]>([]);
  const [badgeCopied, setBadgeCopied] = useState(false);
  const { toast } = useToast();
  const router = useRouter();

  async function handleRescan() {
    if (!scan) return;
    setRescanning(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: scan.repo, branch: scan.branch, method: 'github', options: scan.options ?? {} }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast(data.error || 'Failed to start scan', 'error');
        setRescanning(false);
        return;
      }
      toast('New scan started', 'success');
      router.push(`/app/scans/${data.id}`);
    } catch {
      toast('Network error. Please try again.', 'error');
      setRescanning(false);
    }
  }

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    async function fetchScan() {
      const res = await fetch(`/api/scans/${params.id}`); // ship-safe-ignore — relative URL to own API; params.id is a DB record ID, not a user-supplied URL
      if (res.ok) {
        const data = await res.json();
        setScan(data);
        if (data.status === 'done' || data.status === 'failed') {
          clearInterval(interval);
          if (data.status === 'done' && data.repo) {
            fetch(`/api/scans?repo=${encodeURIComponent(data.repo)}&limit=10`)
              .then(r => r.json())
              .then(d => {
                const trend = (d.scans || [])
                  .filter((sc: { status: string; score: number | null }) => sc.status === 'done' && sc.score !== null)
                  .map((sc: { score: number; createdAt: string }) => ({ score: sc.score, date: sc.createdAt }))
                  .reverse();
                if (trend.length > 1) setScoreTrend(trend);
              });
          }
        }
      }
      setLoading(false);
    }
    fetchScan();
    interval = setInterval(fetchScan, 1000);
    return () => clearInterval(interval);
  }, [params.id]);

  function toggleFinding(i: number) {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });
  }

  if (loading) return (
    <div className={s.page}>
      <div className={s.loadingState}>
        <span className={s.loadingSpinner} />
        <span>Loading scan…</span>
      </div>
    </div>
  );

  if (!scan) return (
    <div className={s.page}>
      <p style={{ color: 'var(--text-dim)' }}>Scan not found.</p>
      <Link href="/app" className="btn btn-ghost" style={{ marginTop: '1rem' }}>Back to dashboard</Link>
    </div>
  );

  const report = scan.report;
  const findings = report?.findings ?? [];
  const depVulns = report?.depVulns ?? [];
  const remediation = report?.remediationPlan ?? [];
  const agents = report?.agents ?? [];
  const categories = report?.categories;

  const filtered = findings
    .filter(f => !sevFilter || f.severity === sevFilter)
    .filter(f => !catFilter || f.category === catFilter)
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  const sevCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; }, {} as Record<string, number>);

  const topCritical = [...findings]
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))
    .slice(0, 3)
    .filter(f => f.severity === 'critical' || f.severity === 'high');

  const badgeMarkdown = scan.score !== null && scan.grade
    ? `[![Ship Safe](https://www.shipsafecli.com/api/badge?score=${scan.score}&grade=${scan.grade})](https://www.shipsafecli.com)`
    : null;

  function copyBadge() {
    if (!badgeMarkdown) return;
    navigator.clipboard.writeText(badgeMarkdown);
    setBadgeCopied(true);
    setTimeout(() => setBadgeCopied(false), 2000);
  }

  return (
    <div className={s.page}>
      {/* Back link */}
      <Link href="/app" className={s.backLink}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
        Dashboard
      </Link>

      {/* Header */}
      <div className={s.header}>
        <div className={s.headerLeft}>
          <h1 className={s.repoName}>{scan.repo}</h1>
          <div className={s.headerMeta}>
            <span className={s.metaChip}>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M6 3v12"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 01-9 9"/></svg>
              {scan.branch}
            </span>
            <span className={s.metaChip}>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
              {new Date(scan.createdAt).toLocaleString()}
            </span>
            {scan.duration && (
              <span className={s.metaChip}>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                {scan.duration.toFixed(1)}s
              </span>
            )}
          </div>
        </div>
        <div className={s.actionRow}>
          {(scan.status === 'done' || scan.status === 'failed') && (
            <button
              className={`btn btn-ghost ${s.actionBtn}`}
              onClick={handleRescan}
              disabled={rescanning}
            >
              {rescanning ? (
                <span style={{ display:'inline-block', width:12, height:12, border:'2px solid currentColor', borderTopColor:'transparent', borderRadius:'50%', animation:'spin 0.7s linear infinite' }} />
              ) : (
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-5"/></svg>
              )}
              {rescanning ? 'Starting…' : 'Scan again'}
            </button>
          )}
          {scan.status === 'done' && (
            <>
              <a href={`/api/reports?scanId=${scan.id}&format=pdf`} className={`btn btn-ghost ${s.actionBtn}`} download>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                PDF
              </a>
              <a href={`/api/reports?scanId=${scan.id}&format=csv`} className={`btn btn-ghost ${s.actionBtn}`} download>CSV</a>
              <a href={`/api/reports?scanId=${scan.id}&format=markdown`} className={`btn btn-ghost ${s.actionBtn}`} download>MD</a>
            </>
          )}
        </div>
      </div>

      {/* Running */}
      {scan.status === 'running' && <ScanProgress startedAt={scan.createdAt} />}

      {/* Pending */}
      {scan.status === 'pending' && (
        <div className={s.progressCard}>
          <div className={s.progressHeader}>
            <span className={s.pulseOrb} style={{ background: 'var(--yellow)', boxShadow: '0 0 8px var(--yellow)' }} />
            <span style={{ color: 'var(--yellow)', fontWeight: 600 }}>Queued</span>
          </div>
          <p className={s.progressHint}>Your scan is in the queue and will start shortly.</p>
        </div>
      )}

      {/* Failed */}
      {scan.status === 'failed' && (
        <div className={s.failedBanner}>
          <strong>Scan failed.</strong>
          {report && typeof report === 'object' && 'error' in report && <p>{String(report.error)}</p>}
        </div>
      )}

      {/* ── Done: full results ──────────────────────────── */}
      {scan.status === 'done' && (
        <>
          {/* Visual summary row: gauge + donut + stats */}
          <div className={s.summaryRow}>
            {/* Score gauge */}
            {scan.score !== null && (
              <div className={s.gaugeCard}>
                <ScoreGauge score={scan.score} grade={scan.grade} />
              </div>
            )}

            {/* Severity donut */}
            {findings.length > 0 && (
              <div className={s.donutCard}>
                <SeverityDonut findings={findings} />
              </div>
            )}

            {/* Stat cards */}
            <div className={s.statCardsCol}>
              {([
                { label: 'Total findings', value: scan.findings, color: scan.findings > 0 ? 'var(--red)' : 'var(--green)', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> },
                { label: 'Secrets', value: scan.secrets, color: scan.secrets > 0 ? 'var(--red)' : 'var(--green)', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="8" cy="15" r="5"/><path d="M13 15h3l1-1 1 1 1-1 1 1v-3l-5-5"/></svg> },
                { label: 'Code vulns', value: scan.vulns, color: scan.vulns > 0 ? 'var(--sev-high)' : 'var(--green)', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg> },
                { label: 'CVEs', value: scan.cves, color: scan.cves > 0 ? 'var(--sev-high)' : 'var(--green)', icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg> },
              ] as { label: string; value: number; color: string; icon: React.ReactNode }[]).map(st => (
                <div key={st.label} className={s.miniStatCard}>
                  <div>
                    <span className={s.miniStatValue} style={{ color: st.color }}>{st.value}</span>
                    <span className={s.miniStatLabel}>{st.label}</span>
                  </div>
                  <span className={s.miniStatIcon} style={{ color: st.color, opacity: 0.5 }}>{st.icon}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Fix these first */}
          {topCritical.length > 0 && (
            <div className={s.fixFirst}>
              <div className={s.fixFirstHeader}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Fix these first</span>
                <span className={s.fixFirstSub}>Top {topCritical.length} priority finding{topCritical.length !== 1 ? 's' : ''}</span>
              </div>
              <div className={s.fixFirstItems}>
                {topCritical.map((f, i) => (
                  <div key={i} className={s.fixFirstItem}>
                    <span className={s.sevBadge} style={{ background: SEV_COLORS[f.severity] + '18', color: SEV_COLORS[f.severity], borderColor: SEV_COLORS[f.severity] + '40' }}>{f.severity}</span>
                    <div className={s.fixFirstBody}>
                      <div className={s.fixFirstTitle}>{f.title}</div>
                      <div className={s.fixFirstFile}>{f.file}{f.line ? `:${f.line}` : ''}</div>
                      {f.fix && <div className={s.fixFirstFix}>{f.fix}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Score trend */}
          {scoreTrend.length > 1 && (
            <div className={s.trendSection}>
              <div className={s.trendTitle}>Score trend for {scan.repo}</div>
              <div className={s.trendChart}>
                {scoreTrend.map((pt, i) => {
                  const prev = i > 0 ? scoreTrend[i - 1].score : pt.score;
                  const delta = pt.score - prev;
                  return (
                    <div key={i} className={s.trendBar} title={`${new Date(pt.date).toLocaleDateString()}: ${pt.score}`}>
                      <div
                        className={s.trendFill}
                        style={{
                          height: `${pt.score}%`,
                          background: pt.score >= 80 ? 'var(--green)' : pt.score >= 60 ? 'var(--yellow)' : 'var(--red)',
                          opacity: i === scoreTrend.length - 1 ? 1 : 0.5,
                        }}
                      />
                      {i === scoreTrend.length - 1 && (
                        <span className={s.trendLabel}>{pt.score}</span>
                      )}
                      {i > 0 && delta !== 0 && i === scoreTrend.length - 1 && (
                        <span className={s.trendDelta} style={{ color: delta > 0 ? 'var(--green)' : 'var(--red)' }}>
                          {delta > 0 ? '+' : ''}{delta}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Category cards */}
          {categories && Object.keys(categories).length > 0 && (
            <div className={s.catSection}>
              <div className={s.catSectionTitle}>Category breakdown</div>
              <div className={s.categories}>
                {Object.entries(categories).map(([key, cat]) => {
                  const worstSev = cat.counts.critical > 0 ? 'critical' : cat.counts.high > 0 ? 'high' : cat.counts.medium > 0 ? 'medium' : cat.findingCount > 0 ? 'low' : null;
                  return (
                    <button
                      key={key}
                      className={`${s.catCard} ${catFilter === key ? s.catCardActive : ''}`}
                      onClick={() => { setCatFilter(catFilter === key ? null : key); setTab('findings'); }}
                    >
                      <div className={s.catIcon} style={{
                        background: cat.findingCount > 0 ? `${SEV_COLORS[worstSev!]}12` : 'var(--bg-elevated)',
                        color: cat.findingCount > 0 ? SEV_COLORS[worstSev!] : 'var(--text-dim)',
                      }}>
                        <CatIcon k={key} />
                      </div>
                      <div className={s.catInfo}>
                        <div className={s.catName}>{cat.label}</div>
                        <div className={s.catCount}>{cat.findingCount} finding{cat.findingCount !== 1 ? 's' : ''}</div>
                      </div>
                      {cat.deduction > 0 && <span className={s.catDeduction}>-{cat.deduction}pts</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* OWASP bar chart */}
          {categories && Object.keys(categories).some(k => categories[k].findingCount > 0) && (
            <div className={s.chartSection}>
              <OWASPChart categories={categories} />
            </div>
          )}

          {/* Tabs */}
          <div className={s.tabsRow}>
            <div className={s.tabs}>
              {([
                ['findings', 'Findings', findings.length],
                ['remediation', 'Fix Plan', remediation.length],
                ...(depVulns.length > 0 ? [['deps', 'CVEs', depVulns.length]] : []),
                ...(agents.length > 0 ? [['agents', 'Coverage', agents.length]] : []),
              ] as [Tab, string, number | null][]).map(([id, label, count]) => (
                <button
                  key={id}
                  className={`${s.tab} ${tab === id ? s.active : ''}`}
                  onClick={() => setTab(id)}
                >
                  {label}
                  {count !== null && <span className={s.tabCount}>{count}</span>}
                </button>
              ))}
            </div>
            {report && (
              <button className={s.rawToggle} onClick={() => setShowRaw(v => !v)}>
                {showRaw ? 'Hide' : 'Raw JSON'}
              </button>
            )}
          </div>

          {/* Tab: Findings */}
          {tab === 'findings' && (
            <div className={s.findingsSection}>
              {/* Severity filter pills */}
              <div className={s.filterRow}>
                {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                  const count = sevCounts[sev] ?? 0;
                  if (count === 0) return null;
                  return (
                    <button
                      key={sev}
                      className={`${s.filterPill} ${sevFilter === sev ? s.filterActive : ''}`}
                      style={sevFilter === sev ? { borderColor: SEV_COLORS[sev], color: SEV_COLORS[sev], background: `${SEV_COLORS[sev]}10` } : {}}
                      onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
                    >
                      <span className={s.filterDot} style={{ background: SEV_COLORS[sev] }} />
                      {sev} <span className={s.filterCount}>{count}</span>
                    </button>
                  );
                })}
                {catFilter && (
                  <button
                    className={`${s.filterPill} ${s.filterActive}`}
                    onClick={() => setCatFilter(null)}
                  >
                    {categories?.[catFilter]?.label ?? catFilter}
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M18 6L6 18M6 6l12 12"/></svg>
                  </button>
                )}
                {(sevFilter || catFilter) && (
                  <button className={s.clearFilters} onClick={() => { setSevFilter(null); setCatFilter(null); }}>Clear all</button>
                )}
              </div>

              {filtered.length === 0 ? (
                <div className={s.emptyTab}>
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  {findings.length === 0 ? 'No findings — your code looks clean!' : 'No findings match the current filters.'}
                </div>
              ) : (
                <div className={s.findingsList}>
                  {filtered.map((f, i) => (
                    <div
                      key={i}
                      className={`${s.findingCard} ${s[`sev_${f.severity}`]}`}
                      onClick={() => toggleFinding(i)}
                    >
                      <div className={s.findingTop}>
                        <span className={`${s.severityBadge} ${s[`severity_${f.severity}`]}`}>{f.severity}</span>
                        <span className={s.findingTitle}>{f.title}</span>
                        {f.file && (
                          <span className={s.findingFile}>{f.file}{f.line ? `:${f.line}` : ''}</span>
                        )}
                        <svg className={`${s.chevron} ${expandedFindings.has(i) ? s.chevronOpen : ''}`} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M6 9l6 6 6-6"/></svg>
                      </div>
                      {expandedFindings.has(i) && (
                        <div className={s.findingExpanded}>
                          {f.description && <p className={s.findingDesc}>{f.description}</p>}
                          {f.fix && (
                            <div className={s.findingFix}>
                              <span className={s.fixLabel}>Fix</span>
                              {f.fix}
                            </div>
                          )}
                          <div className={s.findingMeta}>
                            <span className={s.findingTag}>{f.rule}</span>
                            {f.cwe && <span className={s.findingTag}>CWE-{f.cwe}</span>}
                            {f.owasp && <span className={s.findingTag}>{f.owasp}</span>}
                            <span className={s.findingTag}>{categories?.[f.category]?.label ?? f.category}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: Fix Plan (Kanban columns) */}
          {tab === 'remediation' && (
            <div>
              {remediation.length === 0 ? (
                <div className={s.emptyTab}>
                  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                  No remediation steps needed.
                </div>
              ) : (
                <div className={s.kanban}>
                  {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                    const items = remediation.filter(r => r.severity === sev);
                    if (items.length === 0) return null;
                    const labels: Record<string, string> = { critical: 'Fix Now', high: 'Fix This Sprint', medium: 'Backlog', low: 'Informational' };
                    return (
                      <div key={sev} className={s.kanbanCol}>
                        <div className={s.kanbanHeader} style={{ borderColor: SEV_COLORS[sev], color: SEV_COLORS[sev] }}>
                          <span className={s.kanbanDot} style={{ background: SEV_COLORS[sev] }} />
                          <span>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                          <span className={s.kanbanSub}>{labels[sev]}</span>
                          <span className={s.kanbanCount}>{items.length}</span>
                        </div>
                        <div className={s.kanbanItems}>
                          {items.map((r, i) => (
                            <div key={i} className={s.kanbanCard}>
                              <div className={s.kanbanCardTop}>
                                <span className={s.kanbanPriority}>#{r.priority}</span>
                                {r.effort && (
                                  <span className={`${s.effortBadge} ${s[`effort_${r.effort}`]}`}>{r.effort}</span>
                                )}
                              </div>
                              <div className={s.kanbanTitle}>{r.title}</div>
                              <p className={s.kanbanAction}>{r.action}</p>
                              {r.file && <span className={s.kanbanFile}>{r.file}</span>}
                              {r.categoryLabel && <span className={s.kanbanCat}>{r.categoryLabel}</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Tab: CVEs */}
          {tab === 'deps' && (
            <div>
              {depVulns.length === 0 ? (
                <div className={s.emptyTab}>No dependency vulnerabilities found.</div>
              ) : (
                <div className={s.depVulnList}>
                  {depVulns.map((d, i) => (
                    <div key={i} className={`${s.depVuln} ${s[`sev_${d.severity}`]}`}>
                      <span className={`${s.severityBadge} ${s[`severity_${d.severity}`]}`}>{d.severity}</span>
                      <span className={s.depPkg}>{d.package}</span>
                      <span className={s.depDesc}>{d.description}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: Agents */}
          {tab === 'agents' && (
            <div className={s.agentGrid}>
              {agents.map((a, i) => {
                const color = !a.success ? 'var(--red)' : a.findingCount > 0 ? 'var(--yellow)' : 'var(--green)';
                return (
                  <div key={i} className={s.agentCard}>
                    <div className={s.agentStatus} style={{ background: `${color}15`, borderColor: `${color}30` }}>
                      <span className={s.agentDot} style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
                    </div>
                    <div className={s.agentBody}>
                      <span className={s.agentName}>{a.agent}</span>
                      <span className={s.agentFindings} style={{ color }}>
                        {a.success ? `${a.findingCount} finding${a.findingCount !== 1 ? 's' : ''}` : 'error'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Raw JSON (collapsible) */}
          {showRaw && report && (
            <div className={s.rawJson}>
              <pre>{JSON.stringify(report, null, 2)}</pre>
            </div>
          )}

          {/* Badge */}
          {badgeMarkdown && (
            <div className={s.badgeSection}>
              <div className={s.badgeHeader}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                <span>Add a badge to your README</span>
              </div>
              <div className={s.badgePreview}>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={`/api/badge?score=${scan.score}&grade=${scan.grade}`} alt={`Ship Safe ${scan.grade}`} />
              </div>
              <div className={s.badgeCode} onClick={copyBadge} title="Click to copy">
                <code>{badgeMarkdown}</code>
                <button className={s.badgeCopy}>
                  {badgeCopied
                    ? <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    : <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                  }
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
