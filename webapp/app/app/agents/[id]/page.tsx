'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import styles from './agent.module.css';

interface Tool { name: string; sourceUrl?: string }

interface AgentRunSummary {
  id:            string;
  status:        string;
  startedAt:     string;
  completedAt:   string | null;
  tokensUsed:    number | null;
  triggerId:     string | null;
  messageCount:  number;
  findingCount:  number;
  firstMessage:  string | null;
  deployVersion: number;
}

interface ChatMsg {
  id:        string;
  role:      string;
  content:   string;
  createdAt: string;
  tokensUsed?: number | null;
}

interface Finding {
  id:          string;
  severity:    string;
  title:       string;
  location:    string | null;
  cve:         string | null;
  remediation: string | null;
  status:      string;
  createdAt:   string;
  run:         { id: string; startedAt: string };
}

interface Trigger {
  id:          string;
  type:        'webhook' | 'cron';
  label:       string;
  secret:      string;
  cronExpr:    string | null;
  promptTpl:   string;
  enabled:     boolean;
  lastFiredAt: string | null;
  createdAt:   string;
}

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

interface OrgInfo { id: string; name: string; slug: string }

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
  orgId: string | null;
  createdAt: string;
  updatedAt: string;
  deployments: Deployment[];
}

type Tab = 'overview' | 'deployments' | 'logs' | 'triggers' | 'findings' | 'runs' | 'settings';

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
  const [saving, setSaving]       = useState(false);
  const [saveOk, setSaveOk]       = useState(false);
  const [error, setError]         = useState('');

  // Edit form state (synced from agent on load)
  const [editName, setEditName]       = useState('');
  const [editDesc, setEditDesc]       = useState('');
  const [editEnvVars, setEditEnvVars] = useState<Array<{ key: string; value: string }>>([]);
  const [logLines, setLogLines]   = useState<string[]>([]);
  const [logsOpen, setLogsOpen]   = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const esRef  = useRef<EventSource | null>(null);

  // Runs
  const [runs,        setRuns]        = useState<AgentRunSummary[]>([]);
  const [runsLoaded,  setRunsLoaded]  = useState(false);
  const [expandedRun, setExpandedRun] = useState<string | null>(null);
  const [runMessages, setRunMessages] = useState<Record<string, ChatMsg[]>>({});

  // Findings
  const [findings,         setFindings]         = useState<Finding[]>([]);
  const [findingsLoaded,   setFindingsLoaded]   = useState(false);
  const [ghModal,          setGhModal]          = useState<string | null>(null);
  const [ghRepo,           setGhRepo]           = useState('');
  const [ghCreating,       setGhCreating]       = useState(false);
  const [ghError,          setGhError]          = useState('');
  const [ghSuccess,        setGhSuccess]        = useState('');
  const ghInputRef = useRef<HTMLInputElement>(null);

  // Team sharing
  const [isOwner,       setIsOwner]       = useState(true);
  const [userOrgs,      setUserOrgs]      = useState<OrgInfo[]>([]);
  const [shareOrgId,    setShareOrgId]    = useState('');
  const [sharing,       setSharing]       = useState(false);
  const [shareOk,       setShareOk]       = useState('');
  const [shareErr,      setShareErr]      = useState('');

  // Triggers
  const [triggers,      setTriggers]      = useState<Trigger[]>([]);
  const [showTrigForm,  setShowTrigForm]  = useState(false);
  const [trigType,      setTrigType]      = useState<'webhook' | 'cron'>('webhook');
  const [trigLabel,     setTrigLabel]     = useState('');
  const [trigCron,      setTrigCron]      = useState('0 * * * *');
  const [trigPrompt,    setTrigPrompt]    = useState('You have been triggered. Here is the event context:\n\n{payload}');
  const [trigSaving,    setTrigSaving]    = useState(false);
  const [copiedId,      setCopiedId]      = useState<string | null>(null);

  const load = useCallback(async () => {
    const res  = await fetch(`/api/agents/${id}`);
    if (!res.ok) { setError('Agent not found'); setLoading(false); return; }
    const data = await res.json();
    setAgent(data.agent);
    setIsOwner(data.isOwner !== false);
    setShareOrgId(data.agent.orgId ?? '');
    setEditName(data.agent.name);
    setEditDesc(data.agent.description ?? '');
    setEditEnvVars(
      Object.entries((data.agent.envVars as Record<string, string>) ?? {}).map(
        ([key, value]) => ({ key, value })
      )
    );
    setLoading(false);
  }, [id]);

  async function handleSave() {
    setSaving(true);
    setSaveOk(false);
    setError('');
    try {
      const envVarsObj = Object.fromEntries(
        editEnvVars.filter(e => e.key.trim()).map(e => [e.key.trim(), e.value])
      );
      const res = await fetch(`/api/agents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: editName.trim(), description: editDesc.trim(), envVars: envVarsObj }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      await load(); // reload full agent (including deployments) to avoid missing fields
      setSaveOk(true);
      setTimeout(() => setSaveOk(false), 2500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (tab === 'triggers') loadTriggers(); }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === 'findings') loadFindings(); }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === 'runs')     loadRuns();     }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === 'settings' && userOrgs.length === 0) loadUserOrgs(); }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

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

  async function loadRuns() {
    const res = await fetch(`/api/agents/${id}/runs`);
    if (res.ok) {
      const { runs: r } = await res.json();
      setRuns(r ?? []);
      setRunsLoaded(true);
    }
  }

  async function loadRunMessages(runId: string) {
    if (runMessages[runId]) { setExpandedRun(prev => prev === runId ? null : runId); return; }
    const res = await fetch(`/api/agents/${id}/chat?runId=${runId}`);
    if (res.ok) {
      const { messages } = await res.json();
      setRunMessages(prev => ({ ...prev, [runId]: messages ?? [] }));
      setExpandedRun(runId);
    }
  }

  async function loadFindings() {
    const res = await fetch(`/api/agents/${id}/findings`);
    if (res.ok) {
      const { findings: f } = await res.json();
      setFindings(f ?? []);
      setFindingsLoaded(true);
    }
  }

  async function handleFindingStatus(findingId: string, status: string) {
    await fetch(`/api/findings/${findingId}`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ status }),
    });
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status } : f));
  }

  function openGhModal(findingId: string) {
    setGhModal(findingId);
    setGhError('');
    setGhSuccess('');
    setTimeout(() => ghInputRef.current?.focus(), 50);
  }

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
    setGhSuccess(data.url);
  }

  async function loadUserOrgs() {
    const res = await fetch('/api/orgs');
    if (res.ok) {
      const data = await res.json();
      setUserOrgs(data.orgs ?? []);
    }
  }

  async function handleShare() {
    if (!shareOrgId) return;
    setSharing(true); setShareOk(''); setShareErr('');
    const res = await fetch(`/api/agents/${id}/share`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId: shareOrgId }),
    });
    const data = await res.json();
    setSharing(false);
    if (!res.ok) { setShareErr(data.error || 'Failed to share'); return; }
    setAgent(prev => prev ? { ...prev, orgId: data.agent.orgId } : prev);
    setShareOk(`Shared with ${data.agent.org?.name ?? 'org'}`);
  }

  async function handleUnshare() {
    setSharing(true); setShareOk(''); setShareErr('');
    const res = await fetch(`/api/agents/${id}/share`, { method: 'DELETE' });
    setSharing(false);
    if (!res.ok) { setShareErr('Failed to unshare'); return; }
    setAgent(prev => prev ? { ...prev, orgId: null } : prev);
    setShareOrgId('');
    setShareOk('Agent is now private');
  }

  async function loadTriggers() {
    const res = await fetch(`/api/agents/${id}/triggers`);
    if (res.ok) {
      const { triggers: t } = await res.json();
      setTriggers(t ?? []);
    }
  }

  async function handleCreateTrigger() {
    setTrigSaving(true);
    try {
      const res = await fetch(`/api/agents/${id}/triggers`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          type:      trigType,
          label:     trigLabel,
          cronExpr:  trigType === 'cron' ? trigCron : undefined,
          promptTpl: trigPrompt,
        }),
      });
      if (res.ok) {
        setShowTrigForm(false);
        setTrigLabel('');
        await loadTriggers();
      }
    } finally {
      setTrigSaving(false);
    }
  }

  async function handleDeleteTrigger(triggerId: string) {
    await fetch(`/api/agents/${id}/triggers/${triggerId}`, { method: 'DELETE' });
    setTriggers(prev => prev.filter(t => t.id !== triggerId));
  }

  async function handleToggleTrigger(triggerId: string, enabled: boolean) {
    await fetch(`/api/agents/${id}/triggers/${triggerId}`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ enabled }),
    });
    setTriggers(prev => prev.map(t => t.id === triggerId ? { ...t, enabled } : t));
  }

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1800);
    }).catch(() => {});
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
        {(['overview', 'deployments', 'logs', 'triggers', 'findings', 'runs', 'settings'] as Tab[]).map(t => (
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
            {t === 'triggers' && triggers.length > 0 && (
              <span className={styles.triggerCount}>{triggers.length}</span>
            )}
            {t === 'findings' && findings.filter(f => f.status === 'open').length > 0 && (
              <span className={styles.findingCount}>{findings.filter(f => f.status === 'open').length}</span>
            )}
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

      {/* ── Triggers ───────────────────────────────────────── */}
      {tab === 'triggers' && (
        <div className={styles.tabContent}>
          <div className={styles.section}>
            <div className={styles.sectionHeaderRow}>
              <div className={styles.sectionTitle}>Triggers</div>
              <button className={styles.addTriggerBtn} onClick={() => setShowTrigForm(v => !v)}>
                {showTrigForm ? 'Cancel' : '+ Add trigger'}
              </button>
            </div>
            <p className={styles.sectionDesc}>
              Triggers let your agent act automatically — on a schedule or when an external system sends a webhook.
            </p>

            {/* Create form */}
            {showTrigForm && (
              <div className={styles.triggerForm}>
                <div className={styles.trigTypeRow}>
                  {(['webhook', 'cron'] as const).map(t => (
                    <button
                      key={t}
                      className={`${styles.trigTypeBtn} ${trigType === t ? styles.trigTypeBtnActive : ''}`}
                      onClick={() => setTrigType(t)}
                    >
                      {t === 'webhook' ? '🔗 Webhook' : '⏰ Schedule'}
                    </button>
                  ))}
                </div>

                <div className={styles.editField}>
                  <label className={styles.editLabel}>Label <span className={styles.optional}>(optional)</span></label>
                  <input
                    className={styles.editInput}
                    value={trigLabel}
                    onChange={e => setTrigLabel(e.target.value)}
                    placeholder={trigType === 'webhook' ? 'e.g. GitHub push' : 'e.g. Nightly scan'}
                  />
                </div>

                {trigType === 'cron' && (
                  <div className={styles.editField}>
                    <label className={styles.editLabel}>Cron expression</label>
                    <input
                      className={`${styles.editInput} ${styles.mono}`}
                      value={trigCron}
                      onChange={e => setTrigCron(e.target.value)}
                      placeholder="0 * * * *"
                    />
                    <span className={styles.editHint}>
                      Standard 5-field cron (UTC). <code>0 * * * *</code> = every hour.
                    </span>
                  </div>
                )}

                <div className={styles.editField}>
                  <label className={styles.editLabel}>Agent prompt</label>
                  <textarea
                    className={`${styles.editInput} ${styles.trigPromptArea}`}
                    value={trigPrompt}
                    onChange={e => setTrigPrompt(e.target.value)}
                    rows={4}
                  />
                  <span className={styles.editHint}><code>{'{payload}'}</code> is replaced with the webhook body (or schedule timestamp for cron).</span>
                </div>

                <div className={styles.editActions}>
                  <button
                    className={styles.saveBtn}
                    onClick={handleCreateTrigger}
                    disabled={trigSaving || (trigType === 'cron' && !trigCron.trim())}
                  >
                    {trigSaving ? 'Creating…' : 'Create trigger'}
                  </button>
                </div>
              </div>
            )}

            {/* Trigger list */}
            {triggers.length === 0 && !showTrigForm && (
              <div className={styles.emptyState}>
                <div className={styles.emptyTitle}>No triggers yet</div>
                <div className={styles.emptyDesc}>Add a webhook or schedule to automate your agent.</div>
              </div>
            )}

            {triggers.map(trig => {
              const webhookUrl = `${typeof window !== 'undefined' ? window.location.origin : ''}/api/trigger/${trig.id}`;
              return (
                <div key={trig.id} className={`${styles.triggerCard} ${!trig.enabled ? styles.triggerDisabled : ''}`}>
                  <div className={styles.triggerCardTop}>
                    <span className={styles.triggerTypeChip}>
                      {trig.type === 'webhook' ? '🔗 Webhook' : '⏰ Schedule'}
                    </span>
                    <span className={styles.triggerLabel}>{trig.label || (trig.type === 'cron' ? trig.cronExpr : 'Unnamed')}</span>
                    <div className={styles.triggerActions}>
                      <button
                        className={`${styles.triggerToggle} ${trig.enabled ? styles.triggerToggleOn : ''}`}
                        onClick={() => handleToggleTrigger(trig.id, !trig.enabled)}
                        title={trig.enabled ? 'Disable' : 'Enable'}
                      >
                        {trig.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                      <button
                        className={styles.triggerDelete}
                        onClick={() => handleDeleteTrigger(trig.id)}
                        title="Delete trigger"
                      >×</button>
                    </div>
                  </div>

                  {trig.type === 'webhook' && (
                    <>
                      <div className={styles.triggerRow}>
                        <span className={styles.triggerRowLabel}>URL</span>
                        <code className={styles.triggerUrl}>{webhookUrl}</code>
                        <button
                          className={styles.copyBtn}
                          onClick={() => copyToClipboard(webhookUrl, `url-${trig.id}`)}
                        >
                          {copiedId === `url-${trig.id}` ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                      <div className={styles.triggerRow}>
                        <span className={styles.triggerRowLabel}>Auth</span>
                        <code className={styles.triggerUrl}>Bearer {trig.secret.slice(0, 8)}…</code>
                        <button
                          className={styles.copyBtn}
                          onClick={() => copyToClipboard(`Bearer ${trig.secret}`, `secret-${trig.id}`)}
                        >
                          {copiedId === `secret-${trig.id}` ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </>
                  )}

                  {trig.type === 'cron' && (
                    <div className={styles.triggerRow}>
                      <span className={styles.triggerRowLabel}>Schedule</span>
                      <code className={styles.triggerUrl}>{trig.cronExpr}</code>
                    </div>
                  )}

                  <div className={styles.triggerMeta}>
                    Last fired: {trig.lastFiredAt ? timeAgo(trig.lastFiredAt) : 'Never'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Findings ───────────────────────────────────────── */}
      {tab === 'findings' && (
        <div className={styles.tabContent}>
          <div className={styles.section}>
            <div className={styles.sectionHeaderRow}>
              <div className={styles.sectionTitle}>Security Findings</div>
              <button className={styles.addTriggerBtn} onClick={loadFindings}>Refresh</button>
            </div>
            <p className={styles.sectionDesc}>
              Issues surfaced by your agent during runs. Update the status as you triage each finding.
            </p>

            {!findingsLoaded ? (
              <div className={styles.emptyState}><div className={styles.emptyDesc}>Loading…</div></div>
            ) : findings.length === 0 ? (
              <div className={styles.emptyState}>
                <div className={styles.emptyTitle}>No findings yet</div>
                <div className={styles.emptyDesc}>Run the agent and it will surface security issues here.</div>
              </div>
            ) : (
              <>
                {/* Severity summary */}
                <div className={styles.findingSummaryRow}>
                  {(['critical','high','medium','low','info'] as const).map(sev => {
                    const n = findings.filter(f => f.severity === sev && f.status === 'open').length;
                    if (n === 0) return null;
                    return (
                      <span key={sev} className={`${styles.severityChip} ${styles[`sev_${sev}`]}`}>
                        {sev} <strong>{n}</strong>
                      </span>
                    );
                  })}
                </div>

                <div className={styles.findingList}>
                  {findings.map(f => (
                    <div key={f.id} className={`${styles.findingCard} ${styles[`sev_${f.severity}_card`]}`}>
                      <div className={styles.findingCardTop}>
                        <span className={`${styles.severityBadge} ${styles[`sev_${f.severity}`]}`}>{f.severity}</span>
                        <span className={styles.findingTitle}>{f.title}</span>
                        <select
                          className={styles.findingStatusSelect}
                          value={f.status}
                          onChange={e => handleFindingStatus(f.id, e.target.value)}
                        >
                          <option value="open">Open</option>
                          <option value="acknowledged">Acknowledged</option>
                          <option value="fixed">Fixed</option>
                          <option value="false_positive">False positive</option>
                        </select>
                      </div>
                      {f.location && (
                        <div className={styles.findingMeta}>
                          <span className={styles.findingMetaKey}>Location</span>
                          <code className={styles.findingMetaVal}>{f.location}</code>
                        </div>
                      )}
                      {f.cve && (
                        <div className={styles.findingMeta}>
                          <span className={styles.findingMetaKey}>CVE</span>
                          <code className={styles.findingMetaVal}>{f.cve}</code>
                        </div>
                      )}
                      {f.remediation && (
                        <div className={styles.findingRemediation}>{f.remediation}</div>
                      )}
                      <div className={styles.findingFooterRow}>
                        <span className={styles.triggerMeta}>
                          Found {timeAgo(f.createdAt)} · Run {f.run.id.slice(0, 8)}
                        </span>
                        <button className={styles.ghBtn} onClick={() => openGhModal(f.id)} title="Create GitHub issue">
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
                          Issue
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

      )}

      {/* ── Settings ───────────────────────────────────────── */}
      {tab === 'settings' && (
        <div className={styles.tabContent}>

          {/* ── Edit form ── */}
          <div className={styles.section}>
            <div className={styles.sectionTitle}>Edit agent</div>

            <div className={styles.editField}>
              <label className={styles.editLabel}>Name</label>
              <input
                className={styles.editInput}
                value={editName}
                onChange={e => setEditName(e.target.value)}
                placeholder="Agent name"
              />
            </div>

            <div className={styles.editField}>
              <label className={styles.editLabel}>Description</label>
              <input
                className={styles.editInput}
                value={editDesc}
                onChange={e => setEditDesc(e.target.value)}
                placeholder="What does this agent do?"
              />
            </div>

            <div className={styles.editField}>
              <label className={styles.editLabel}>Environment variables</label>
              <div className={styles.editHint}>
                Use <code>ANTHROPIC_API_KEY</code> or <code>OPENROUTER_API_KEY</code>.
                Plain <code>OPENAI_API_KEY</code> is not supported by Hermes — use{' '}
                <a href="https://openrouter.ai" target="_blank" rel="noopener">OpenRouter</a> instead.
              </div>
              <div className={styles.envRows}>
                {editEnvVars.map((ev, i) => (
                  <div key={i} className={styles.envRow}>
                    <input
                      className={`${styles.editInput} ${styles.envKey}`}
                      value={ev.key}
                      onChange={e => {
                        const next = [...editEnvVars];
                        next[i] = { ...next[i], key: e.target.value };
                        setEditEnvVars(next);
                      }}
                      placeholder="KEY"
                    />
                    <input
                      className={`${styles.editInput} ${styles.envVal}`}
                      value={ev.value}
                      onChange={e => {
                        const next = [...editEnvVars];
                        next[i] = { ...next[i], value: e.target.value };
                        setEditEnvVars(next);
                      }}
                      placeholder="value"
                      type={ev.key.toLowerCase().includes('key') || ev.key.toLowerCase().includes('secret') ? 'password' : 'text'}
                    />
                    <button
                      className={styles.envRemove}
                      onClick={() => setEditEnvVars(editEnvVars.filter((_, j) => j !== i))}
                      title="Remove"
                    >×</button>
                  </div>
                ))}
                <button
                  className={styles.envAdd}
                  onClick={() => setEditEnvVars([...editEnvVars, { key: '', value: '' }])}
                >+ Add variable</button>
              </div>
            </div>

            <div className={styles.editActions}>
              <button
                className={styles.saveBtn}
                onClick={handleSave}
                disabled={saving || !editName.trim()}
              >
                {saving ? 'Saving…' : saveOk ? 'Saved!' : 'Save changes'}
              </button>
            </div>
          </div>

          {/* ── Team sharing ── */}
          {isOwner && (
            <div className={styles.section}>
              <div className={styles.sectionTitle}>Team sharing</div>
              {agent?.orgId ? (
                <div className={styles.configCard}>
                  <div className={styles.configRow}>
                    <span className={styles.configKey}>Shared with</span>
                    <span className={styles.configVal}>
                      {userOrgs.find(o => o.id === agent.orgId)?.name ?? agent.orgId}
                    </span>
                  </div>
                  <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <button className={styles.deleteBtn} onClick={handleUnshare} disabled={sharing}>
                      {sharing ? 'Updating…' : 'Make private'}
                    </button>
                    {shareOk  && <span style={{ fontSize: '0.78rem', color: 'var(--green)' }}>{shareOk}</span>}
                    {shareErr && <span style={{ fontSize: '0.78rem', color: 'var(--red)' }}>{shareErr}</span>}
                  </div>
                </div>
              ) : userOrgs.length === 0 ? (
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', margin: 0 }}>
                  You are not a member of any org. <a href="/app/team" className={styles.liveUrl}>Create or join an org</a> to share agents with teammates.
                </p>
              ) : (
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <select
                    className={styles.editInput}
                    value={shareOrgId}
                    onChange={e => setShareOrgId(e.target.value)}
                    style={{ maxWidth: 200 }}
                  >
                    <option value="">Select an org…</option>
                    {userOrgs.map(o => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                  <button className={styles.deployBtn} onClick={handleShare} disabled={sharing || !shareOrgId}>
                    {sharing ? 'Sharing…' : 'Share with org'}
                  </button>
                  {shareOk  && <span style={{ fontSize: '0.78rem', color: 'var(--green)' }}>{shareOk}</span>}
                  {shareErr && <span style={{ fontSize: '0.78rem', color: 'var(--red)' }}>{shareErr}</span>}
                </div>
              )}
            </div>
          )}

          {/* ── Agent info ── */}
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

      {/* ── Runs ───────────────────────────────────────────── */}
      {tab === 'runs' && (
        <div className={styles.tabContent}>
          <div className={styles.section}>
            <div className={styles.sectionHeaderRow}>
              <div className={styles.sectionTitle}>Run History</div>
              <button className={styles.addTriggerBtn} onClick={loadRuns}>Refresh</button>
            </div>
            <p className={styles.sectionDesc}>
              Every conversation and autonomous trigger run — with token usage, findings, and full message history.
            </p>

            {!runsLoaded ? (
              <div className={styles.emptyState}><div className={styles.emptyDesc}>Loading…</div></div>
            ) : runs.length === 0 ? (
              <div className={styles.emptyState}>
                <div className={styles.emptyTitle}>No runs yet</div>
                <div className={styles.emptyDesc}>Chat with the agent or set up a trigger to start runs.</div>
              </div>
            ) : (
              <div className={styles.runList}>
                {runs.map(r => {
                  const duration = r.completedAt && r.startedAt
                    ? Math.round((new Date(r.completedAt).getTime() - new Date(r.startedAt).getTime()) / 1000)
                    : null;
                  const isOpen = expandedRun === r.id;
                  const msgs = runMessages[r.id] ?? [];

                  return (
                    <div key={r.id} className={styles.runCard}>
                      <div
                        className={styles.runCardTop}
                        onClick={() => loadRunMessages(r.id)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={e => e.key === 'Enter' && loadRunMessages(r.id)}
                      >
                        <span className={`${styles.runStatus} ${styles[`runStatus_${r.status}`]}`}>
                          {r.status}
                        </span>
                        <span className={styles.runSource}>
                          {r.triggerId ? '⚡ trigger' : '💬 chat'}
                        </span>
                        <span className={styles.runPreview}>
                          {r.firstMessage ? r.firstMessage.slice(0, 80) + (r.firstMessage.length > 80 ? '…' : '') : '—'}
                        </span>
                        <div className={styles.runMeta}>
                          {r.findingCount > 0 && (
                            <span className={styles.runFindings}>{r.findingCount} finding{r.findingCount > 1 ? 's' : ''}</span>
                          )}
                          {r.tokensUsed != null && <span className={styles.runTokens}>{r.tokensUsed.toLocaleString()} tok</span>}
                          {duration != null && <span className={styles.runDuration}>{duration}s</span>}
                          <span className={styles.runTime}>{timeAgo(r.startedAt)}</span>
                        </div>
                        <span className={`${styles.runChevron} ${isOpen ? styles.runChevronOpen : ''}`}>›</span>
                      </div>

                      {isOpen && (
                        <div className={styles.runMessages}>
                          {msgs.length === 0 ? (
                            <div className={styles.runMsgEmpty}>Loading messages…</div>
                          ) : (
                            msgs.map(m => (
                              <div key={m.id} className={`${styles.runMsg} ${styles[`runMsg_${m.role}`]}`}>
                                <span className={styles.runMsgRole}>{m.role}</span>
                                <span className={styles.runMsgContent}>{m.content}</span>
                              </div>
                            ))
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── GitHub Issue Modal (page-level, position:fixed) ── */}
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
                  <button className={styles.copyBtn} onClick={() => setGhModal(null)}>Close</button>
                </div>
              </div>
            ) : (
              <div className={styles.modalBody}>
                <label className={styles.modalLabel}>
                  Repository <span style={{ color: 'var(--text-dim)' }}>(owner/repo)</span>
                </label>
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
                  Requires a GitHub token — configure in{' '}
                  <a href="/app/settings" className={styles.liveUrl}>Settings → Agent Alerts</a>.
                </p>
                <div className={styles.modalActions}>
                  <button className={styles.logsBtn} onClick={() => setGhModal(null)}>Cancel</button>
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
