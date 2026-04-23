'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import styles from './run.module.css';

// ── Report parser ─────────────────────────────────────────────────────────────

function stripAnsi(s: string) {
  return s
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x9b[0-9;]*[A-Za-z]/g, '');
}

interface ParsedFinding {
  severity: string;
  title: string;
  location?: string;
  cve?: string;
  remediation?: string;
}

interface ParsedAgent {
  name: string;
  role: string;
  count: number;
}

interface ParsedReport {
  target: string | null;
  riskPosture: string | null;
  findings: ParsedFinding[];
  agents: ParsedAgent[];
  roadmap: { immediate?: string; shortTerm?: string; longTerm?: string };
}

function parseReport(raw: string): ParsedReport {
  const s = stripAnsi(raw)
    // strip Hermes box-drawing chrome
    .split('\n')
    .filter(l => !l.trim().startsWith('╭') && !l.trim().startsWith('╰') && !l.trim().startsWith('│'))
    .filter(l => !l.trim().startsWith('EXACTLY this format'))
    .filter(l => !l.trim().startsWith('FINDING: {"severity"'))
    .filter(l => !l.trim().match(/^─{6,}$/))
    .filter(l => !l.trim().startsWith('[2J') && !l.trim().startsWith('[H'))
    .join('\n');

  // Structured FINDING: lines
  const findings: ParsedFinding[] = [];
  const findingRe = /^FINDING:\s*(\{.+\})\s*$/gm;
  let m: RegExpExecArray | null;
  while ((m = findingRe.exec(s)) !== null) {
    try { const f = JSON.parse(m[1]); if (f.severity && f.title) findings.push(f); } catch { /* skip */ }
  }

  // Bullet fallback: [HIGH] Title — location
  if (findings.length === 0) {
    const bulletRe = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)\s*[—–-]+\s*(.+)/gi;
    while ((m = bulletRe.exec(s)) !== null) {
      findings.push({ severity: m[1].toLowerCase(), title: m[2].trim(), location: m[3].trim() });
    }
  }

  // Agent sections
  const agents: ParsedAgent[] = [];
  const agentRe = /###\s+(.+?)\s*(?:\(([^)]+)\))?\s*[—–-]+\s*(\d+)\s*finding/gi;
  while ((m = agentRe.exec(s)) !== null) {
    agents.push({ name: m[1].trim(), role: m[2]?.trim() ?? '', count: parseInt(m[3], 10) });
  }

  // Risk posture
  const riskM = s.match(/Overall risk posture:\s*(.+)/i);

  // Roadmap
  const imm  = s.match(/\*\*Immediate[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const stm  = s.match(/\*\*Short-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const ltm  = s.match(/\*\*Long-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);

  // Target
  const targetM = raw.match(/assessments?\s+of\s+\*\*([^*]+)\*\*/i);

  return {
    target:      targetM?.[1]?.trim() ?? null,
    riskPosture: riskM?.[1]?.trim() ?? null,
    findings,
    agents,
    roadmap: {
      immediate: imm?.[1]?.trim(),
      shortTerm: stm?.[1]?.trim(),
      longTerm:  ltm?.[1]?.trim(),
    },
  };
}

// ── Report renderer ───────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#94a3b8',
};
const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.1)', high: 'rgba(249,115,22,0.1)',
  medium: 'rgba(234,179,8,0.1)',   low: 'rgba(59,130,246,0.1)', info: 'rgba(148,163,184,0.1)',
};

function riskColor(rp: string) {
  const l = rp.toLowerCase();
  if (l.includes('critical')) return '#ef4444';
  if (l.includes('high'))     return '#f97316';
  if (l.includes('medium'))   return '#eab308';
  return '#22c55e';
}

function ReportRenderer({ raw }: { raw: string }) {
  const r = parseReport(raw);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
  for (const f of r.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const total = r.findings.length;

  return (
    <div className={styles.parsedReport}>

      {/* Risk posture */}
      {r.riskPosture && (
        <div className={styles.riskBanner} style={{ borderColor: riskColor(r.riskPosture) + '44', background: riskColor(r.riskPosture) + '11' }}>
          <span className={styles.riskLabel}>Overall Risk Posture</span>
          <span className={styles.riskValue} style={{ color: riskColor(r.riskPosture) }}>
            {r.riskPosture.split('—')[0].trim()}
          </span>
          {r.riskPosture.includes('—') && (
            <span className={styles.riskDesc}>{r.riskPosture.split('—').slice(1).join('—').trim()}</span>
          )}
        </div>
      )}

      {/* Severity counts */}
      {total > 0 && (
        <div className={styles.sevRow}>
          {(['critical','high','medium','low','info'] as const).map(s => (
            <div key={s} className={styles.sevStat}>
              <span className={styles.sevNum} style={{ color: SEV_COLORS[s] }}>{counts[s] ?? 0}</span>
              <span className={styles.sevLabel}>{s}</span>
            </div>
          ))}
        </div>
      )}

      {/* Findings table */}
      {r.findings.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Findings ({total})</div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Severity</th><th>Issue</th><th>Location</th><th>Remediation</th>
              </tr>
            </thead>
            <tbody>
              {r.findings.map((f, i) => (
                <tr key={i}>
                  <td>
                    <span className={styles.sevBadge} style={{ color: SEV_COLORS[f.severity], background: SEV_BG[f.severity] }}>
                      {f.severity.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <strong>{f.title}</strong>
                    {f.cve && <div className={styles.cve}>{f.cve}</div>}
                  </td>
                  <td><code className={styles.loc}>{f.location ?? '—'}</code></td>
                  <td className={styles.fix}>{f.remediation ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {total === 0 && (
        <div className={styles.clean}>✓ No findings — clean!</div>
      )}

      {/* Agent summary */}
      {r.agents.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Agent Team</div>
          <div className={styles.agentGrid}>
            {r.agents.map((a, i) => (
              <div key={i} className={styles.agentCard}>
                <div className={styles.agentName}>{a.name}</div>
                <div className={styles.agentRole}>{a.role}</div>
                <div className={styles.agentCount} style={{ color: a.count > 0 ? '#f97316' : '#22c55e' }}>
                  {a.count} finding{a.count !== 1 ? 's' : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Remediation roadmap */}
      {(r.roadmap.immediate || r.roadmap.shortTerm || r.roadmap.longTerm) && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Remediation Roadmap</div>
          <div className={styles.roadmap}>
            {r.roadmap.immediate && (
              <div className={styles.roadmapItem}>
                <div className={styles.roadmapLabel} style={{ color: '#ef4444' }}>⚡ Immediate (24–48h)</div>
                <div className={styles.roadmapText}>{r.roadmap.immediate}</div>
              </div>
            )}
            {r.roadmap.shortTerm && (
              <div className={styles.roadmapItem}>
                <div className={styles.roadmapLabel} style={{ color: '#f97316' }}>📅 Short-term (1–2 weeks)</div>
                <div className={styles.roadmapText}>{r.roadmap.shortTerm}</div>
              </div>
            )}
            {r.roadmap.longTerm && (
              <div className={styles.roadmapItem}>
                <div className={styles.roadmapLabel} style={{ color: '#eab308' }}>🏗 Long-term (1–3 months)</div>
                <div className={styles.roadmapText}>{r.roadmap.longTerm}</div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface AgentRunNode {
  id:          string;
  role:        string | null;
  status:      string;
  parentRunId: string | null;
  startedAt:   string;
  completedAt: string | null;
  tokensUsed:  number | null;
  deployment:  { agent: { id: string; name: string } };
  _count:      { messages: number; findings: number };
}

interface TeamRunData {
  id:          string;
  target:      string;
  status:      string;
  phase:       string;
  report:      string | null;
  startedAt:   string;
  completedAt: string | null;
  team:        { id: string; name: string };
  agentRuns:   AgentRunNode[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const ROLE_LABELS: Record<string, string> = {
  lead:        'Lead',
  pen_tester:  'Pen Tester',
  red_team:    'Red Team',
  secrets:     'Secrets Scanner',
  cve_analyst: 'CVE Analyst',
  custom:      'Custom',
};

const PHASES = ['planning', 'delegating', 'synthesizing', 'done'] as const;

function duration(start: string, end: string | null): string {
  if (!end) return '';
  const s = Math.floor((new Date(end).getTime() - new Date(start).getTime()) / 1000);
  if (s < 60)   return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function timeAgo(d: string): string {
  const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function phaseIndex(phase: string): number {
  return PHASES.indexOf(phase as typeof PHASES[number]);
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function TeamRunPage() {
  const { id } = useParams<{ id: string }>();
  const [run,        setRun]        = useState<TeamRunData | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState('');
  const [cancelling, setCancelling] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    const res = await fetch(`/api/team-runs/${id}`);
    if (!res.ok) { setError('Run not found'); setLoading(false); return; }
    const data = await res.json();
    setRun(data.teamRun);
    setLoading(false);
    return data.teamRun as TeamRunData;
  }, [id]);

  useEffect(() => {
    load().then(r => {
      if (!r || r.status !== 'running') return;
      // Poll every 4s while running
      pollRef.current = setInterval(async () => {
        const updated = await load();
        if (updated && updated.status !== 'running') {
          clearInterval(pollRef.current!);
        }
      }, 4000);
    });
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [load]);

  async function cancelRun() {
    if (!run || cancelling) return;
    setCancelling(true);
    await fetch(`/api/team-runs/${id}`, { method: 'DELETE' });
    await load();
    setCancelling(false);
  }

  if (loading) return <div className={styles.page} style={{ color: 'var(--text-muted)' }}>Loading…</div>;
  if (error)   return <div className={styles.page} style={{ color: 'var(--red)' }}>{error}</div>;
  if (!run)    return null;

  // Build tree: lead runs + sub-agent runs by parentRunId
  const leadRuns = run.agentRuns.filter(r => r.role === 'lead');
  const subRuns  = run.agentRuns.filter(r => r.role !== 'lead');

  // Group sub-runs by parentRunId
  const byParent: Record<string, AgentRunNode[]> = {};
  for (const r of subRuns) {
    const key = r.parentRunId ?? '__root__';
    if (!byParent[key]) byParent[key] = [];
    byParent[key].push(r);
  }

  const curPhaseIdx = phaseIndex(run.phase);
  const totalFindings = run.agentRuns.reduce((n, r) => n + r._count.findings, 0);

  return (
    <div className={styles.page}>
      <Link href={`/app/agent-teams/${run.team.id}`} className={styles.backLink}>
        ← {run.team.name}
      </Link>

      {/* Header */}
      <div className={styles.header}>
        <div className={styles.titleRow}>
          <h1 className={styles.title}>Team Assessment</h1>
          <span className={`${styles.statusBadge} ${
            run.status === 'running'   ? styles.statusRunning   :
            run.status === 'completed' ? styles.statusCompleted :
            styles.statusError
          }`}>
            {run.status === 'running' ? <><span className={styles.spinner} /> {run.phase}</> : run.status}
          </span>
          {run.status === 'running' && (
            <button
              onClick={cancelRun}
              disabled={cancelling}
              className={styles.cancelBtn}
            >
              {cancelling ? 'Cancelling…' : 'Cancel'}
            </button>
          )}
        </div>
        <p className={styles.teamName}>{run.team.name}</p>
        <div className={styles.target}>{run.target}</div>
        <div className={styles.metaBar}>
          <span>Started {timeAgo(run.startedAt)}</span>
          {run.completedAt && <span>Duration: {duration(run.startedAt, run.completedAt)}</span>}
          <span>{run.agentRuns.length} agent run{run.agentRuns.length !== 1 ? 's' : ''}</span>
          {totalFindings > 0 && <span className={styles.findingsBadge}>{totalFindings} finding{totalFindings !== 1 ? 's' : ''}</span>}
        </div>
      </div>

      {/* Phase progress bar */}
      <div className={styles.phaseBar}>
        {PHASES.map((p, i) => (
          <div
            key={p}
            className={`${styles.phase} ${
              i < curPhaseIdx ? styles.phaseDone :
              i === curPhaseIdx && run.status === 'running' ? styles.phaseActive : ''
            }`}
          >
            {i < curPhaseIdx ? '✓ ' : ''}{p}
          </div>
        ))}
      </div>

      {/* Agent run tree */}
      <div className={styles.tree}>
        {leadRuns.length === 0 && run.status === 'running' && (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.83rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span className={styles.spinner} /> Waiting for lead agent to start…
          </div>
        )}

        {leadRuns.map((lead, li) => {
          const children = byParent[lead.id] ?? [];
          const isSynth  = li > 0; // second lead run = synthesis
          return (
            <div key={lead.id} className={styles.leadRow}>
              <RunNode
                node={lead}
                label={isSynth ? 'Lead (Synthesis)' : 'Lead (Planning)'}
                isSynth={isSynth}
              />
              {children.length > 0 && (
                <div className={styles.childrenRow}>
                  {children.map(child => (
                    <RunNode key={child.id} node={child} />
                  ))}
                </div>
              )}
              {/* Show pending sub-agents when lead is done planning but subs haven't started */}
              {!isSynth && lead.status === 'completed' && children.length === 0 && run.status === 'running' && (
                <div className={styles.childrenRow}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span className={styles.spinner} /> Sub-agents initialising…
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {run.status === 'running' && (
          <p className={styles.pollNote}>Auto-refreshing every 4s…</p>
        )}
      </div>

      {/* Final report */}
      {run.report && run.status !== 'error' && (
        <div className={styles.reportCard}>
          <div className={styles.reportTitle}>Final Security Report</div>
          <ReportRenderer raw={run.report} />
        </div>
      )}
      {run.status === 'error' && run.report && (
        <div className={styles.reportCard} style={{ borderColor: 'rgba(239,68,68,0.3)' }}>
          <div className={styles.reportTitle} style={{ color: '#ef4444' }}>Error</div>
          <div className={styles.reportText} style={{ color: '#ef4444' }}>
            {stripAnsi(run.report).replace(/\x1b\[[^m]*m/g, '').trim()}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sub-component: individual run node ────────────────────────────────────────

function RunNode({ node, label, isSynth }: { node: AgentRunNode; label?: string; isSynth?: boolean }) {
  const roleCls  = node.role ?? 'custom';
  const roleText = label ?? (ROLE_LABELS[node.role ?? ''] ?? node.role ?? 'Agent');
  const tagCls   = `roleTag_${roleCls}`;

  return (
    <div className={`${styles.runNode} ${styles[roleCls] ?? ''} ${isSynth ? '' : ''}`}>
      <div className={styles.runNodeTop}>
        <span className={`${styles.runRole} ${styles[tagCls] ?? ''}`}>{roleText}</span>
        <span className={styles.runAgentName}>{node.deployment.agent.name}</span>
        <span className={`${styles.runNodeStatus} ${
          node.status === 'running'   ? styles.nodeRunning   :
          node.status === 'completed' ? styles.nodeCompleted :
          styles.nodeError
        }`}>
          {node.status === 'running' && <span className={styles.spinner} style={{ marginRight: 4 }} />}
          {node.status}
        </span>
      </div>
      <div className={styles.runNodeMeta}>
        {node.status === 'running' ? (
          <span>Running…</span>
        ) : (
          <span>{duration(node.startedAt, node.completedAt)}</span>
        )}
        {node._count.findings > 0 && (
          <span className={styles.findingsBadge}>{node._count.findings} finding{node._count.findings !== 1 ? 's' : ''}</span>
        )}
        {node.tokensUsed != null && node.tokensUsed > 0 && (
          <span>{node.tokensUsed.toLocaleString()} tokens</span>
        )}
        <Link
          href={`/app/agents/${node.deployment.agent.id}`}
          style={{ color: 'var(--cyan)', textDecoration: 'none', fontSize: '0.72rem' }}
          onClick={e => e.stopPropagation()}
        >
          Agent →
        </Link>
      </div>
    </div>
  );
}
