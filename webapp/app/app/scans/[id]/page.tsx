'use client';
import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
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
  createdAt: string;
}

/* ── Helpers ──────────────────────────────────────────── */

const scoreColor = (n: number) => n >= 80 ? 'var(--green)' : n >= 60 ? 'var(--yellow)' : 'var(--red)';

const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const catIcons: Record<string, string> = {
  secrets: '🔑', injection: '💉', deps: '📦', auth: '🔒',
  config: '⚙️', 'supply-chain': '🔗', api: '🌐', llm: '🤖',
};

type Tab = 'findings' | 'remediation' | 'deps' | 'agents' | 'raw';

/* ── Component ────────────────────────────────────────── */

export default function ScanDetail() {
  const params = useParams();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('findings');
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [catFilter, setCatFilter] = useState<string | null>(null);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    async function fetchScan() {
      const res = await fetch(`/api/scans/${params.id}`); // ship-safe-ignore — relative URL to own API; params.id is a DB record ID, not a user-supplied URL
      if (res.ok) {
        const data = await res.json();
        setScan(data);
        if (data.status === 'done' || data.status === 'failed') clearInterval(interval);
      }
      setLoading(false);
    }
    fetchScan();
    interval = setInterval(fetchScan, 3000);
    return () => clearInterval(interval);
  }, [params.id]);

  if (loading) {
    return <div className={s.page}><p style={{ color: 'var(--text-dim)' }}>Loading scan...</p></div>;
  }

  if (!scan) {
    return (
      <div className={s.page}>
        <p style={{ color: 'var(--text-dim)' }}>Scan not found.</p>
        <Link href="/app" className="btn btn-ghost" style={{ marginTop: '1rem' }}>Back to dashboard</Link>
      </div>
    );
  }

  const report = scan.report;
  const findings = report?.findings ?? [];
  const depVulns = report?.depVulns ?? [];
  const remediation = report?.remediationPlan ?? [];
  const agents = report?.agents ?? [];
  const categories = report?.categories;

  // Apply filters
  const filtered = findings
    .filter(f => !sevFilter || f.severity === sevFilter)
    .filter(f => !catFilter || f.category === catFilter)
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  return (
    <div className={s.page}>
      {/* Back + Header */}
      <Link href="/app" className={s.backLink}>← Back to dashboard</Link>

      <div className={s.header}>
        <div>
          <h1>{scan.repo}</h1>
          <p className={s.meta}>
            {scan.branch} · {new Date(scan.createdAt).toLocaleString()}
          </p>
        </div>
        {scan.status === 'done' && scan.score !== null && (
          <div className={s.scoreBadge} style={{
            background: scoreColor(scan.score) + '10',
            border: `1px solid ${scoreColor(scan.score)}30`,
          }}>
            <span className={s.gradeText} style={{ color: scoreColor(scan.score) }}>{scan.grade}</span>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span className={s.scoreNum} style={{ color: scoreColor(scan.score) }}>{scan.score}/100</span>
              {scan.duration && <span className={s.duration}>{scan.duration.toFixed(1)}s</span>}
            </div>
          </div>
        )}
      </div>

      {/* Actions bar */}
      {scan.status === 'done' && (
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a href={`/api/reports?scanId=${scan.id}&format=pdf`} className="btn btn-ghost" style={{ fontSize: '0.78rem', padding: '0.4rem 0.75rem' }} download>
            Download Report
          </a>
          <a href={`/api/reports?scanId=${scan.id}&format=csv`} className="btn btn-ghost" style={{ fontSize: '0.78rem', padding: '0.4rem 0.75rem' }} download>
            Export CSV
          </a>
          <a href={`/api/reports?scanId=${scan.id}&format=markdown`} className="btn btn-ghost" style={{ fontSize: '0.78rem', padding: '0.4rem 0.75rem' }} download>
            Markdown
          </a>
        </div>
      )}

      {/* Running */}
      {scan.status === 'running' && (
        <div className={s.runningBanner}>
          <span className={s.pulseOrb} />
          <span className={s.runningText}>Scan in progress...</span>
          <span className={s.runningHint}>Updates automatically when complete.</span>
        </div>
      )}

      {/* Pending */}
      {scan.status === 'pending' && (
        <div className={s.runningBanner}>
          <span className={s.pulseOrb} style={{ background: 'var(--yellow)', boxShadow: '0 0 8px var(--yellow)' }} />
          <span style={{ color: 'var(--yellow)', fontWeight: 600 }}>Queued...</span>
          <span className={s.runningHint}>Scan will start shortly.</span>
        </div>
      )}

      {/* Failed */}
      {scan.status === 'failed' && (
        <div className={s.failedBanner}>
          <strong>Scan failed.</strong>
          {report && typeof report === 'object' && 'error' in report && (
            <p>{String(report.error)}</p>
          )}
        </div>
      )}

      {/* Done — full results */}
      {scan.status === 'done' && (
        <>
          {/* Stats */}
          <div className={s.statsRow}>
            {[
              { label: 'Total Findings', value: scan.findings, color: scan.findings > 0 ? 'var(--red)' : 'var(--green)' },
              { label: 'Secrets', value: scan.secrets, color: scan.secrets > 0 ? 'var(--red)' : 'var(--green)' },
              { label: 'Code Vulns', value: scan.vulns, color: scan.vulns > 0 ? 'var(--yellow)' : 'var(--green)' },
              { label: 'CVEs', value: scan.cves, color: scan.cves > 0 ? 'var(--yellow)' : 'var(--green)' },
            ].map(st => (
              <div key={st.label} className={s.statCard}>
                <span className={s.statValue} style={{ color: st.color }}>{st.value}</span>
                <span className={s.statLabel}>{st.label}</span>
              </div>
            ))}
          </div>

          {/* Category breakdown */}
          {categories && Object.keys(categories).length > 0 && (
            <div className={s.categories}>
              {Object.entries(categories).map(([key, cat]) => (
                <button
                  key={key}
                  className={s.catCard}
                  style={{ cursor: 'pointer', textAlign: 'left' }}
                  onClick={() => { setCatFilter(catFilter === key ? null : key); setTab('findings'); }}
                >
                  <div className={s.catIcon} style={{
                    background: cat.findingCount > 0 ? 'rgba(220,38,38,0.08)' : 'var(--bg-elevated)',
                    color: cat.findingCount > 0 ? 'var(--red)' : 'var(--text-dim)',
                  }}>
                    {catIcons[key] ?? '🛡️'}
                  </div>
                  <div>
                    <div className={s.catName}>{cat.label}</div>
                    <div className={s.catCount}>{cat.findingCount} finding{cat.findingCount !== 1 ? 's' : ''}</div>
                  </div>
                  {cat.deduction > 0 && (
                    <span className={s.catDeduction} style={{ color: 'var(--red)' }}>-{cat.deduction}pts</span>
                  )}
                </button>
              ))}
            </div>
          )}

          {/* Tabs */}
          <div className={s.tabs}>
            <button className={`${s.tab} ${tab === 'findings' ? s.active : ''}`} onClick={() => setTab('findings')}>
              Findings<span className={s.tabCount}>{findings.length}</span>
            </button>
            <button className={`${s.tab} ${tab === 'remediation' ? s.active : ''}`} onClick={() => setTab('remediation')}>
              Fix Plan<span className={s.tabCount}>{remediation.length}</span>
            </button>
            {depVulns.length > 0 && (
              <button className={`${s.tab} ${tab === 'deps' ? s.active : ''}`} onClick={() => setTab('deps')}>
                CVEs<span className={s.tabCount}>{depVulns.length}</span>
              </button>
            )}
            {agents.length > 0 && (
              <button className={`${s.tab} ${tab === 'agents' ? s.active : ''}`} onClick={() => setTab('agents')}>
                Agents<span className={s.tabCount}>{agents.length}</span>
              </button>
            )}
            <button className={`${s.tab} ${tab === 'raw' ? s.active : ''}`} onClick={() => setTab('raw')}>
              Raw JSON
            </button>
          </div>

          {/* Tab: Findings */}
          {tab === 'findings' && (
            <div className={s.findingsSection}>
              {/* Filters */}
              <div className={s.filterRow}>
                {['critical', 'high', 'medium', 'low'].map(sev => {
                  const count = findings.filter(f => f.severity === sev).length;
                  if (count === 0) return null;
                  return (
                    <button
                      key={sev}
                      className={`${s.filterBtn} ${sevFilter === sev ? s.active : ''}`}
                      onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
                    >
                      {sev} ({count})
                    </button>
                  );
                })}
                {catFilter && (
                  <button className={`${s.filterBtn} ${s.active}`} onClick={() => setCatFilter(null)}>
                    {categories?.[catFilter]?.label ?? catFilter} ✕
                  </button>
                )}
              </div>

              {filtered.length === 0 ? (
                <div className={s.emptyTab}>
                  {findings.length === 0 ? 'No findings — your code looks clean!' : 'No findings match the current filters.'}
                </div>
              ) : (
                <div className={s.findingsList}>
                  {filtered.map((f, i) => (
                    <div key={i} className={s.findingCard}>
                      <div className={s.findingTop}>
                        <span className={`${s.severityBadge} ${s[`severity${f.severity.charAt(0).toUpperCase() + f.severity.slice(1)}` as keyof typeof s] ?? ''}`}>
                          {f.severity}
                        </span>
                        <span className={s.findingTitle}>{f.title}</span>
                        {f.file && (
                          <span className={s.findingFile}>
                            {f.file}{f.line ? `:${f.line}` : ''}
                          </span>
                        )}
                      </div>
                      {f.description && <p className={s.findingDesc}>{f.description}</p>}
                      {f.fix && <div className={s.findingFix}>{f.fix}</div>}
                      <div className={s.findingMeta}>
                        <span className={s.findingTag}>{f.rule}</span>
                        {f.cwe && <span className={s.findingTag}>CWE-{f.cwe}</span>}
                        {f.owasp && <span className={s.findingTag}>{f.owasp}</span>}
                        <span className={s.findingTag}>{categories?.[f.category]?.label ?? f.category}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: Remediation */}
          {tab === 'remediation' && (
            <div>
              {remediation.length === 0 ? (
                <div className={s.emptyTab}>No remediation steps needed.</div>
              ) : (
                <div className={s.remediationList}>
                  {remediation.map((r, i) => (
                    <div key={i} className={s.remCard}>
                      <span className={s.remPriority}>{r.priority}</span>
                      <div className={s.remBody}>
                        <div className={s.findingTop}>
                          <span className={`${s.severityBadge} ${s[`severity${r.severity.charAt(0).toUpperCase() + r.severity.slice(1)}` as keyof typeof s] ?? ''}`}>
                            {r.severity}
                          </span>
                          <span className={s.remTitle}>{r.title}</span>
                        </div>
                        <p className={s.remAction}>{r.action}</p>
                        {r.file && <span className={s.findingFile} style={{ fontSize: '0.72rem' }}>{r.file}</span>}
                        <div className={s.remMeta}>
                          {r.effort && (
                            <span className={`${s.effortBadge} ${s[`effort${r.effort.charAt(0).toUpperCase() + r.effort.slice(1)}` as keyof typeof s] ?? ''}`}>
                              {r.effort} effort
                            </span>
                          )}
                          {r.categoryLabel && <span className={s.findingTag}>{r.categoryLabel}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
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
                    <div key={i} className={s.depVuln}>
                      <span className={`${s.severityBadge} ${s[`severity${d.severity.charAt(0).toUpperCase() + d.severity.slice(1)}` as keyof typeof s] ?? ''}`}>
                        {d.severity}
                      </span>
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
              {agents.map((a, i) => (
                <div key={i} className={s.agentCard}>
                  <span className={s.agentDot} style={{
                    background: !a.success ? 'var(--red)' : a.findingCount > 0 ? 'var(--yellow)' : 'var(--green)',
                  }} />
                  <span className={s.agentName}>{a.agent}</span>
                  <span className={s.agentFindings}>
                    {a.success ? `${a.findingCount}` : 'err'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Tab: Raw JSON */}
          {tab === 'raw' && report && (
            <div className={s.rawJson}>
              <pre>{JSON.stringify(report, null, 2)}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
