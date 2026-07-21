'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import Link from 'next/link';
import { track } from '@vercel/analytics/react';
import styles from './findings.module.css';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

interface Finding {
  id:          string;
  source:      'agent' | 'scan';
  severity:    string;
  title:       string;
  location:    string | null;
  cve:         string | null;
  remediation: string | null;
  status:      string;
  createdAt:   string;
  repo:        string | null;
  branch:      string | null;
  agent?:      { id: string; name: string; slug: string };
  run?:        { id: string; startedAt: string };
  scan?:       { id: string; findingKey: string } | null;
}

interface Summary { critical: number; high: number; medium: number; low: number; info: number }

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUSES   = ['open', 'acknowledged', 'fixed', 'false_positive'] as const;

function timeAgo(date: string) {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function FindingsPage() {
  const [findings,  setFindings]  = useState<Finding[]>([]);
  const [summary,   setSummary]   = useState<Summary>({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const [loading,   setLoading]   = useState(true);
  const [severity,  setSeverity]  = useState('');
  const [status,    setStatus]    = useState('open');
  const [source,    setSource]    = useState<'all' | 'scan' | 'agent'>('all');

  // Trend stats
  interface DailyPoint { date: string; critical: number; high: number; medium: number; low: number; info: number }
  const [daily,     setDaily]     = useState<DailyPoint[]>([]);
  const [mttrHours, setMttrHours] = useState<number | null>(null);
  const [openByAge, setOpenByAge] = useState<{ lt1d: number; d1to7: number; d7to30: number; gt30d: number } | null>(null);
  const [showChart, setShowChart] = useState(false);

  // GitHub issue modal
  const [ghModal,    setGhModal]    = useState<string | null>(null); // findingId
  const [ghRepo,     setGhRepo]     = useState('');   // "owner/repo"
  const [ghCreating, setGhCreating] = useState(false);
  const [ghError,    setGhError]    = useState('');
  const [ghSuccess,  setGhSuccess]  = useState('');   // issue URL
  const ghInputRef = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams({ limit: '200' });
    if (severity) params.set('severity', severity);
    if (status)   params.set('status',   status);
    params.set('source', source);
    const res = await fetch(`/api/findings?${params}`);
    if (res.ok) {
      const data = await res.json();
      setFindings(data.findings ?? []);
      setSummary(data.summary ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    }
    setLoading(false);
  }, [severity, source, status]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    fetch('/api/findings/stats').then(r => r.json()).then(d => {
      if (d.daily)    setDaily(d.daily);
      if (d.mttrHours !== undefined) setMttrHours(d.mttrHours);
      if (d.openByAge) setOpenByAge(d.openByAge);
    }).catch(() => {});
  }, []);

  async function handleCreateIssue() {
    if (!ghModal || !ghRepo.trim()) return;
    const [owner, repo] = ghRepo.trim().split('/');
    if (!owner || !repo) { setGhError('Enter as owner/repo e.g. acme/my-app'); return; }
    setGhCreating(true);
    setGhError('');
    setGhSuccess('');
    const res = await fetch(`/api/findings/${ghModal}/github-issue`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ owner, repo }),
    });
    const data = await res.json();
    setGhCreating(false);
    if (!res.ok) { setGhError(data.error || 'Failed to create issue'); return; }
    track('Finding GitHub Issue Created', { source: 'agent' });
    setGhSuccess(data.url);
  }

  function openGhModal(findingId: string) {
    setGhModal(findingId);
    setGhError('');
    setGhSuccess('');
    setTimeout(() => ghInputRef.current?.focus(), 50);
  }

  async function handleStatus(finding: Finding, newStatus: string) {
    const endpoint = finding.source === 'scan' ? '/api/findings/scan-state' : `/api/findings/${finding.id}`;
    const body = finding.source === 'scan'
      ? { scanId: finding.scan?.id, findingKey: finding.scan?.findingKey, status: newStatus }
      : { status: newStatus };
    const res = await fetch(endpoint, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) return;
    track('Finding Status Changed', { status: newStatus, source: finding.source });
    await load();
  }

  const totalOpen = SEVERITIES.reduce((n, s) => n + summary[s], 0);

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Security inbox</h1>
          <p className={styles.subtitle}>Prioritized findings from repository scans and AI agents.</p>
        </div>
        <Link href="/app/scan" className={styles.newScanBtn}>New scan</Link>
      </div>

      {/* Summary tiles */}
      <div className={styles.summaryRow}>
        {SEVERITIES.map(sev => (
          <button
            key={sev}
            className={`${styles.summaryTile} ${styles[`sev_${sev}`]} ${severity === sev ? styles.summaryTileActive : ''}`}
            aria-pressed={severity === sev}
            onClick={() => {
              setSeverity(prev => prev === sev ? '' : sev);
              track('Findings Severity Filtered', { severity: sev, source });
            }}
          >
            <span className={styles.summaryCount}>{summary[sev]}</span>
            <span className={styles.summaryLabel}>{sev}</span>
          </button>
        ))}
      </div>

      {/* Agent trend toggle */}
      {source !== 'scan' && daily.some(d => d.critical + d.high + d.medium + d.low + d.info > 0) && (
        <div className={styles.trendRow}>
          <div className={styles.trendMeta}>
            {mttrHours != null && (
              <span className={styles.mttrBadge}>
                Agent MTTR <strong>{mttrHours < 24 ? `${mttrHours}h` : `${Math.round(mttrHours / 24)}d`}</strong>
              </span>
            )}
            {openByAge && openByAge.gt30d > 0 && (
              <span className={styles.ageBadge}>{openByAge.gt30d} agent open &gt;30d</span>
            )}
          </div>
          <button className={styles.filterBtn} onClick={() => setShowChart(v => !v)}>
            {showChart ? 'Hide trend' : 'Show trend'}
          </button>
        </div>
      )}

      {showChart && (
        <div className={styles.chartCard}>
          <div className={styles.chartTitle}>Agent findings (last 30 days)</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={daily} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <defs>
                {([['critical','#ef4444'],['high','#f97316'],['medium','#ca8a04'],['low','#16a34a']] as const).map(([k,c]) => (
                  <linearGradient key={k} id={`grad_${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={c} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-dim)' }} tickFormatter={d => d.slice(5)} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-dim)' }} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: 'var(--text-muted)', fontSize: 11 }}
              />
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11 }} />
              {([['critical','#ef4444'],['high','#f97316'],['medium','#ca8a04'],['low','#16a34a']] as [string, string][]).map(([k, c]) => (
                <Area key={k} type="monotone" dataKey={k} stroke={c} fill={`url(#grad_${k})`} strokeWidth={1.5} dot={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Filter bar */}
      <div className={styles.filterBar}>
        <div className={styles.filters}>
          <div className={styles.filterGroup}>
            <span className={styles.filterLabel}>Source</span>
            {(['all', 'scan', 'agent'] as const).map(value => (
              <button
                key={value}
                className={`${styles.filterBtn} ${source === value ? styles.filterBtnActive : ''}`}
                onClick={() => {
                  setSource(value);
                  track('Findings Source Filtered', { source: value });
                }}
              >
                {value === 'all' ? 'All' : value === 'scan' ? 'Scans' : 'Agents'}
              </button>
            ))}
          </div>
          <div className={styles.filterGroup}>
            <span className={styles.filterLabel}>Status</span>
            {(['', ...STATUSES] as const).map(s => (
              <button
                key={s || 'all'}
                className={`${styles.filterBtn} ${status === s ? styles.filterBtnActive : ''}`}
                onClick={() => setStatus(s)}
              >
                {s || 'All'}
              </button>
            ))}
          </div>
        </div>
        <button className={styles.refreshBtn} onClick={load}>Refresh</button>
      </div>

      {/* Findings list */}
      {loading ? (
        <div className={styles.emptyState}>Loading…</div>
      ) : findings.length === 0 ? (
        <div className={styles.emptyState}>
          <div className={styles.emptyTitle}>
            {totalOpen === 0 ? 'No open findings' : 'No findings match the current filter'}
          </div>
          <div className={styles.emptyDesc}>
            {totalOpen === 0
              ? 'Run a repository scan or security agent to start building your inbox.'
              : 'Try changing the severity or status filter.'}
          </div>
          {totalOpen === 0 && (
            <div className={styles.emptyActions}>
              <Link href="/app/scan" className={styles.newScanBtn}>Run a scan</Link>
              <Link href="/app/agents/new" className={styles.secondaryBtn}>Create an agent</Link>
            </div>
          )}
        </div>
      ) : (
        <div className={styles.findingList}>
          {findings.map(f => (
            <div key={f.id} className={`${styles.findingCard} ${styles[`sev_${f.severity}_card`]}`}>
              <div className={styles.findingTop}>
                <span className={`${styles.severityBadge} ${styles[`sev_${f.severity}`]}`}>{f.severity}</span>
                <span className={styles.findingTitle}>{f.title}</span>
                <span className={styles.sourceBadge}>{f.source === 'scan' ? 'Scan' : 'Agent'}</span>
                <select
                  className={styles.statusSelect}
                  value={f.status}
                  aria-label={`Status for ${f.title}`}
                  onChange={e => handleStatus(f, e.target.value)}
                >
                  {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                </select>
              </div>

              <div className={styles.findingBody}>
                {f.location && (
                  <div className={styles.metaRow}>
                    <span className={styles.metaKey}>Location</span>
                    <code className={styles.metaVal}>{f.location}</code>
                  </div>
                )}
                {f.cve && (
                  <div className={styles.metaRow}>
                    <span className={styles.metaKey}>CVE</span>
                    <code className={styles.metaVal}>{f.cve}</code>
                  </div>
                )}
                {f.remediation && (
                  <div className={styles.remediation}>{f.remediation}</div>
                )}
              </div>

              <div className={styles.findingFooter}>
                {f.source === 'agent' && f.agent ? (
                  <Link href={`/app/agents/${f.agent.id}`} className={styles.agentLink}>
                    {f.agent.name}
                  </Link>
                ) : f.scan ? (
                  <Link
                    href={`/app/scans/${f.scan.id}`}
                    className={styles.agentLink}
                    onClick={() => track('Finding Opened', { source: 'scan' })}
                  >
                    {f.repo}
                  </Link>
                ) : null}
                <span className={styles.dot}>·</span>
                <span className={styles.findingTime}>{timeAgo(f.createdAt)}</span>
                {f.source === 'agent' ? (
                  <button className={styles.ghBtn} onClick={() => openGhModal(f.id)} title="Create GitHub issue">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
                    Create issue
                  </button>
                ) : f.scan ? (
                  <Link
                    href={`/app/scans/${f.scan.id}`}
                    className={styles.viewReportBtn}
                    onClick={() => track('Finding Opened', { source: 'scan' })}
                  >
                    View report
                  </Link>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      )}
      {/* GitHub Issue Modal */}
      {ghModal && (
        <div className={styles.modalOverlay} onClick={() => setGhModal(null)}>
          <div className={styles.modal} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <span className={styles.modalTitle}>Create GitHub Issue</span>
              <button className={styles.modalClose} onClick={() => setGhModal(null)}>×</button>
            </div>
            {ghSuccess ? (
              <div className={styles.modalBody}>
                <p className={styles.ghSuccess}>Issue created!</p>
                <a href={ghSuccess} target="_blank" rel="noopener noreferrer" className={styles.ghLink}>{ghSuccess}</a>
                <div className={styles.modalActions}>
                  <button className={styles.filterBtn} onClick={() => setGhModal(null)}>Close</button>
                </div>
              </div>
            ) : (
              <div className={styles.modalBody}>
                <label className={styles.modalLabel}>Repository <span style={{ color: 'var(--text-dim)' }}>(owner/repo)</span></label>
                <input
                  ref={ghInputRef}
                  className={styles.modalInput}
                  placeholder="acme/my-app"
                  value={ghRepo}
                  onChange={e => setGhRepo(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleCreateIssue()}
                />
                {ghError && <p className={styles.ghError}>{ghError}</p>}
                <p className={styles.modalHint}>
                  Requires a GitHub token with <code>repo</code> scope — configure it in{' '}
                  <a href="/app/settings" className={styles.agentLink}>Settings → Agent Alerts</a>.
                </p>
                <div className={styles.modalActions}>
                  <button className={styles.filterBtn} onClick={() => setGhModal(null)}>Cancel</button>
                  <button
                    className={styles.ghSubmitBtn}
                    onClick={handleCreateIssue}
                    disabled={ghCreating || !ghRepo.trim()}
                  >
                    {ghCreating ? 'Creating…' : 'Create Issue'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
