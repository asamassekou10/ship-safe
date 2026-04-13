'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import styles from './agent.module.css';

interface Tool { name: string; sourceUrl?: string }

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

type Tab = 'overview' | 'deployments' | 'logs' | 'triggers' | 'settings';

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
        {(['overview', 'deployments', 'logs', 'triggers', 'settings'] as Tab[]).map(t => (
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
    </div>
  );
}
