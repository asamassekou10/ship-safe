'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import styles from './agent.module.css';

interface Tool { name: string; sourceUrl?: string }

interface Deployment {
  id: string;
  version: number;
  status: string;
  securityScore: number | null;
  subdomain: string | null;
  deployLog: string | null;
  startedAt: string | null;
  stoppedAt: string | null;
  createdAt: string;
}

interface Agent {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  tools: Tool[];
  memoryProvider: string;
  maxDepth: number;
  skills: string[];
  envVars: Record<string, string>;
  ciProvider: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  deployments: Deployment[];
}

type Tab = 'overview' | 'deployments' | 'logs' | 'settings';

function timeAgo(date: string) {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function statusMeta(status: string): { label: string; cls: string } {
  if (status === 'deployed')  return { label: 'Live',      cls: 'statusLive' };
  if (status === 'deploying') return { label: 'Deploying', cls: 'statusPending' };
  if (status === 'running')   return { label: 'Running',   cls: 'statusLive' };
  if (status === 'stopped')   return { label: 'Stopped',   cls: 'statusStopped' };
  if (status === 'failed')    return { label: 'Failed',    cls: 'statusFailed' };
  if (status === 'pending')   return { label: 'Pending',   cls: 'statusPending' };
  return { label: 'Draft', cls: 'statusDraft' };
}

function scoreColor(n: number) {
  if (n >= 80) return 'var(--green)';
  if (n >= 60) return 'var(--yellow)';
  return 'var(--red)';
}

const SUBDOMAIN_BASE = process.env.NEXT_PUBLIC_SUBDOMAIN_BASE || 'agents.shipsafecli.com';

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router  = useRouter();

  const [agent, setAgent]         = useState<Agent | null>(null);
  const [loading, setLoading]     = useState(true);
  const [tab, setTab]             = useState<Tab>('overview');
  const [deploying, setDeploying] = useState(false);
  const [stopping, setStopping]   = useState(false);
  const [deleting, setDeleting]   = useState(false);
  const [error, setError]         = useState('');
  const [logLines, setLogLines]   = useState<string[]>([]);
  const [logsOpen, setLogsOpen]   = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const esRef  = useRef<EventSource | null>(null);

  const load = useCallback(async () => {
    const res  = await fetch(`/api/agents/${id}`);
    if (!res.ok) { setError('Agent not found'); setLoading(false); return; }
    const data = await res.json();
    setAgent(data.agent);
    setLoading(false);
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Auto-poll while deploying
  useEffect(() => {
    if (!agent) return;
    const isTransient = agent.status === 'deploying' || agent.status === 'pending';
    if (!isTransient) return;
    const t = setInterval(() => {
      fetch(`/api/agents/${id}/status`)
        .then(r => r.json())
        .then(d => {
          if (d.agentStatus && d.agentStatus !== agent.status) {
            load();
          }
        })
        .catch(() => {});
    }, 3000);
    return () => clearInterval(t);
  }, [agent, id, load]);

  // Scroll logs to bottom
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logLines]);

  function openLogs() {
    if (esRef.current) { esRef.current.close(); esRef.current = null; }
    setLogLines([]);
    setLogsOpen(true);
    setTab('logs');
    const es = new EventSource(`/api/agents/${id}/logs`);
    es.onmessage = e => {
      try {
        const line = JSON.parse(e.data);
        if (typeof line === 'string') setLogLines(prev => [...prev.slice(-500), line]);
      } catch {}
    };
    es.addEventListener('close', () => es.close());
    es.onerror = () => { es.close(); esRef.current = null; };
    esRef.current = es;
  }

  function closeLogs() {
    if (esRef.current) { esRef.current.close(); esRef.current = null; }
    setLogsOpen(false);
  }

  useEffect(() => () => { esRef.current?.close(); }, []);

  async function handleDeploy() {
    setError('');
    setDeploying(true);
    try {
      const res = await fetch(`/api/agents/${id}/deploy`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Deploy failed');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Deploy failed');
    } finally {
      setDeploying(false);
    }
  }

  async function handleStop() {
    setError('');
    setStopping(true);
    try {
      const res = await fetch(`/api/agents/${id}/stop`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok && res.status !== 207) throw new Error(data.error || 'Stop failed');
      closeLogs();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Stop failed');
    } finally {
      setStopping(false);
    }
  }

  async function handleDelete() {
    if (!confirm(`Delete "${agent?.name}"? This cannot be undone.`)) return; // ship-safe-ignore
    setDeleting(true);
    await fetch(`/api/agents/${id}`, { method: 'DELETE' });
    router.push('/app/agents');
  }

  if (loading) return (
    <div className={styles.page}><div className={styles.skeleton} /></div>
  );
  if (error && !agent) return (
    <div className={styles.page}><div className={styles.errorState}>{error}</div></div>
  );
  if (!agent) return null;

  const { label, cls } = statusMeta(agent.status);
  const lastDeploy     = agent.deployments[0];
  const isLive         = agent.status === 'deployed' || agent.status === 'running';
  const isDeploying    = agent.status === 'deploying' || deploying;
  const LLM_KEYS       = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY'];
  const hasLLMKey      = LLM_KEYS.some(k => (agent.envVars as Record<string,string>)[k]?.trim());

  return (
    <div className={styles.page}>
      {/* ── Header ─────────────────────────────────────────── */}
      <div className={styles.header}>
        <Link href="/app/agents" className={styles.back}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="15 18 9 12 15 6"/></svg>
          Agents
        </Link>
        <div className={styles.titleRow}>
          <div className={styles.titleLeft}>
            <h1 className={styles.title}>{agent.name}</h1>
            <span className={`${styles.statusBadge} ${styles[cls]}`}>
              {isDeploying && <span className={styles.spinner} aria-hidden="true" />}
              {label}
            </span>
          </div>
          <div className={styles.headerActions}>
            {isLive ? (
              <>
                <Link href={`/app/agents/${id}/console`} className={styles.consoleBtn}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                  Console
                </Link>
                <button className={styles.logsBtn} onClick={() => tab === 'logs' ? setTab('overview') : openLogs()}>
                  {tab === 'logs' ? 'Hide logs' : 'Logs'}
                </button>
                <button className={styles.stopBtn} onClick={handleStop} disabled={stopping}>
                  {stopping ? 'Stopping…' : 'Stop'}
                </button>
              </>
            ) : (
              <div className={styles.deployWrap}>
                <button
                  className={styles.deployBtn}
                  onClick={handleDeploy}
                  disabled={isDeploying || !hasLLMKey}
                  title={!hasLLMKey ? 'Add an LLM API key first (edit the agent)' : undefined}
                >
                  {isDeploying ? (
                    <><span className={styles.spinner} aria-hidden="true" />Deploying…</>
                  ) : 'Deploy'}
                </button>
                {!hasLLMKey && (
                  <span className={styles.noKeyHint}>
                    <Link href={`/app/agents/${id}/edit`}>Add API key</Link> to enable deploy
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
        {agent.description && <p className={styles.desc}>{agent.description}</p>}
        {lastDeploy?.subdomain && isLive && (
          <a
            href={`https://${lastDeploy.subdomain}.${SUBDOMAIN_BASE}`}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.liveUrl}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            {lastDeploy.subdomain}.{SUBDOMAIN_BASE} ↗
          </a>
        )}
        {error && <div className={styles.errorBanner}>{error}</div>}
      </div>

      {/* ── Tabs ───────────────────────────────────────────── */}
      <div className={styles.tabs}>
        {(['overview', 'deployments', 'logs', 'settings'] as Tab[]).map(t => (
          <button
            key={t}
            className={`${styles.tab} ${tab === t ? styles.tabActive : ''}`}
            onClick={() => {
              setTab(t);
              if (t === 'logs' && isLive && !logsOpen) openLogs();
              if (t !== 'logs') closeLogs();
            }}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* ── Overview ───────────────────────────────────────── */}
      {tab === 'overview' && (
        <div className={styles.tabContent}>
          <div className={styles.statsRow}>
            <div className={styles.stat}>
              <div className={styles.statValue}>{agent.tools.length}</div>
              <div className={styles.statLabel}>Tools</div>
            </div>
            <div className={styles.stat}>
              <div className={styles.statValue}>{agent.maxDepth}</div>
              <div className={styles.statLabel}>Max depth</div>
            </div>
            <div className={styles.stat}>
              <div className={styles.statValue}>{agent.deployments.length}</div>
              <div className={styles.statLabel}>Deployments</div>
            </div>
            {lastDeploy?.securityScore != null && (
              <div className={styles.stat}>
                <div className={styles.statValue} style={{ color: scoreColor(lastDeploy.securityScore) }}>
                  {lastDeploy.securityScore}/100
                </div>
                <div className={styles.statLabel}>Security score</div>
              </div>
            )}
          </div>

          <div className={styles.section}>
            <div className={styles.sectionTitle}>Configuration</div>
            <div className={styles.configCard}>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Memory provider</span>
                <span className={styles.configVal}>{agent.memoryProvider}</span>
              </div>
              <div className={styles.configRow}>
                <span className={styles.configKey}>CI provider</span>
                <span className={styles.configVal}>{agent.ciProvider}</span>
              </div>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Delegation depth</span>
                <span className={styles.configVal}>{agent.maxDepth}</span>
              </div>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Created</span>
                <span className={styles.configVal}>{timeAgo(agent.createdAt)}</span>
              </div>
            </div>
          </div>

          <div className={styles.section}>
            <div className={styles.sectionTitle}>Tools ({agent.tools.length})</div>
            <div className={styles.toolList}>
              {agent.tools.map(t => (
                <span key={t.name} className={styles.toolTag}>{t.name}</span>
              ))}
              {agent.tools.length === 0 && <span className={styles.dimText}>No tools configured</span>}
            </div>
          </div>

          {!isLive && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>Ready to deploy</div>
              <div className={styles.nextCard}>
                <div className={styles.nextIcon}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </div>
                <div>
                  <div className={styles.nextTitle}>Deploy to VPS</div>
                  <div className={styles.nextDesc}>
                    Click <strong>Deploy</strong> to start your agent on a Ship Safe-managed VPS.
                    It will get its own subdomain at <code>{agent.slug}.{SUBDOMAIN_BASE}</code>.
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Deployments ────────────────────────────────────── */}
      {tab === 'deployments' && (
        <div className={styles.tabContent}>
          {agent.deployments.length === 0 ? (
            <div className={styles.emptyState}>
              <div className={styles.emptyTitle}>No deployments yet</div>
              <div className={styles.emptyDesc}>Click Deploy to start your first deployment.</div>
            </div>
          ) : (
            <div className={styles.deployList}>
              {agent.deployments.map(d => {
                const dm = statusMeta(d.status);
                return (
                  <div key={d.id} className={styles.deployCard}>
                    <div className={styles.deployTop}>
                      <span className={styles.deployVersion}>v{d.version}</span>
                      <span className={`${styles.statusBadge} ${styles[dm.cls]}`}>{dm.label}</span>
                      {d.securityScore != null && (
                        <span className={styles.deployScore} style={{ color: scoreColor(d.securityScore) }}>
                          {d.securityScore}/100
                        </span>
                      )}
                      <span className={styles.deployTime}>{timeAgo(d.createdAt)}</span>
                    </div>
                    {d.subdomain && (
                      <div className={styles.deployUrl}>{d.subdomain}.{SUBDOMAIN_BASE}</div>
                    )}
                    {d.deployLog && (
                      <pre className={styles.deployLog}>{d.deployLog}</pre>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Logs ───────────────────────────────────────────── */}
      {tab === 'logs' && (
        <div className={styles.tabContent}>
          {!isLive ? (
            <div className={styles.emptyState}>
              <div className={styles.emptyTitle}>Agent is not running</div>
              <div className={styles.emptyDesc}>Deploy the agent first to view live logs.</div>
            </div>
          ) : (
            <div className={styles.logsCard}>
              <div className={styles.logsHeader}>
                <span className={styles.logsBadge}>
                  <span className={styles.logsDot} />
                  Live
                </span>
                <span className={styles.logsNote}>{logLines.length} lines</span>
              </div>
              <div className={styles.logsList} ref={logRef}>
                {logLines.length === 0 ? (
                  <span className={styles.logsEmpty}>Waiting for output…</span>
                ) : (
                  logLines.map((line, i) => (
                    <div key={i} className={styles.logLine}>{line}</div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Settings ───────────────────────────────────────── */}
      {tab === 'settings' && (
        <div className={styles.tabContent}>
          <div className={styles.section}>
            <div className={styles.sectionTitle}>Agent info</div>
            <div className={styles.configCard}>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Agent ID</span>
                <span className={`${styles.configVal} ${styles.mono}`}>{agent.id}</span>
              </div>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Slug</span>
                <span className={`${styles.configVal} ${styles.mono}`}>{agent.slug}</span>
              </div>
              <div className={styles.configRow}>
                <span className={styles.configKey}>Last updated</span>
                <span className={styles.configVal}>{timeAgo(agent.updatedAt)}</span>
              </div>
            </div>
          </div>

          <div className={styles.section}>
            <div className={styles.dangerZone}>
              <div className={styles.dangerTitle}>Danger zone</div>
              <div className={styles.dangerRow}>
                <div>
                  <div className={styles.dangerLabel}>Delete this agent</div>
                  <div className={styles.dangerDesc}>Permanently removes the agent and all deployment history.</div>
                </div>
                <button className={styles.deleteBtn} onClick={handleDelete} disabled={deleting}>
                  {deleting ? 'Deleting…' : 'Delete Agent'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
