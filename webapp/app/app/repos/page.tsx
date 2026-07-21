'use client';
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { track } from '@vercel/analytics/react';
import styles from './repos.module.css';

interface MonitoredRepo {
  id: string;
  repo: string;
  branch: string;
  schedule: string | null;
  lastScanAt: string | null;
  lastScore: number | null;
  lastGrade: string | null;
  enabled: boolean;
}

const schedules = [
  { value: '0 9 * * 1', label: 'Weekly' },
  { value: '0 9 * * *', label: 'Daily' },
  { value: '0 */6 * * *', label: 'Every 6 hours' },
  { value: '0 0 1 * *', label: 'Monthly' },
];

const scoreColor = (score: number) => score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';

function timeAgo(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isOverdue(repo: MonitoredRepo) {
  if (!repo.enabled || !repo.schedule || !repo.lastScanAt) return false;
  const maximumAge: Record<string, number> = {
    '0 */6 * * *': 12 * 60 * 60 * 1000,
    '0 9 * * *': 36 * 60 * 60 * 1000,
    '0 9 * * 1': 10 * 24 * 60 * 60 * 1000,
    '0 0 1 * *': 45 * 24 * 60 * 60 * 1000,
  };
  const threshold = maximumAge[repo.schedule];
  return threshold ? Date.now() - new Date(repo.lastScanAt).getTime() > threshold : false;
}

function protectionState(repo: MonitoredRepo) {
  if (!repo.enabled) return { label: 'Paused', tone: 'muted' };
  if (!repo.lastScanAt) return { label: 'Baseline needed', tone: 'warning' };
  if (repo.lastScore !== null && repo.lastScore < 80) return { label: 'Needs attention', tone: 'danger' };
  if (isOverdue(repo)) return { label: 'Scan overdue', tone: 'warning' };
  return { label: 'Protected', tone: 'success' };
}

export default function ReposPage() {
  const [repos, setRepos] = useState<MonitoredRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [adding, setAdding] = useState(false);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [confirmRemoveId, setConfirmRemoveId] = useState<string | null>(null);
  const [newRepo, setNewRepo] = useState('');
  const [newBranch, setNewBranch] = useState('main');
  const [newSchedule, setNewSchedule] = useState('0 9 * * 1');
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/repos')
      .then(async response => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to load repositories');
        const nextRepos = data.repos || [];
        setRepos(nextRepos);
        setShowAdd(nextRepos.length === 0);
      })
      .catch(err => setError(err instanceof Error ? err.message : 'Unable to load repositories'))
      .finally(() => setLoading(false));
  }, []);

  const stats = useMemo(() => ({
    active: repos.filter(repo => repo.enabled).length,
    attention: repos.filter(repo => repo.enabled && repo.lastScore !== null && repo.lastScore < 80).length,
    baseline: repos.filter(repo => repo.enabled && (!repo.lastScanAt || isOverdue(repo))).length,
  }), [repos]);

  async function addRepo(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setAdding(true);
    let repoValue = newRepo.trim();
    const githubMatch = repoValue.match(/github\.com\/([^/]+\/[^/]+)/);
    if (githubMatch) repoValue = githubMatch[1].split(/[?#]/)[0].replace(/\.git$/, '').replace(/\/$/, '');

    const response = await fetch('/api/repos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo: repoValue, branch: newBranch.trim(), schedule: newSchedule }),
    });
    const data = await response.json();
    setAdding(false);
    if (!response.ok) { setError(data.error || 'Unable to monitor repository'); return; }
    setRepos(previous => [data, ...previous.filter(repo => repo.id !== data.id)]);
    setNewRepo('');
    setShowAdd(false);
    track('Repository Monitoring Enabled', { schedule: newSchedule });
  }

  async function updateRepo(id: string, patch: Partial<Pick<MonitoredRepo, 'schedule' | 'enabled'>>) {
    setSavingId(id);
    setError('');
    const response = await fetch('/api/repos', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, ...patch }),
    });
    const data = await response.json();
    setSavingId(null);
    if (!response.ok) { setError(data.error || 'Unable to update repository'); return; }
    setRepos(previous => previous.map(repo => repo.id === id ? data : repo));
    track('Repository Monitoring Updated', {
      action: patch.enabled === false ? 'paused' : patch.enabled === true ? 'resumed' : 'schedule',
    });
  }

  async function removeRepo(id: string) {
    setSavingId(id);
    const response = await fetch('/api/repos', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    setSavingId(null);
    if (!response.ok) { setError('Unable to remove repository'); return; }
    setRepos(previous => previous.filter(repo => repo.id !== id));
    setConfirmRemoveId(null);
    track('Repository Monitoring Removed');
  }

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1>Repositories</h1>
          <p>Keep important code on a recurring security schedule.</p>
        </div>
        <button className={styles.primaryButton} onClick={() => setShowAdd(value => !value)}>
          {showAdd ? 'Close' : 'Add repository'}
        </button>
      </header>

      {!loading && repos.length > 0 && (
        <section className={styles.summary} aria-label="Repository protection summary">
          <div><strong>{stats.active}</strong><span>Protected</span></div>
          <div><strong className={stats.attention > 0 ? styles.dangerText : ''}>{stats.attention}</strong><span>Need attention</span></div>
          <div><strong className={stats.baseline > 0 ? styles.warningText : ''}>{stats.baseline}</strong><span>Need scan</span></div>
        </section>
      )}

      {showAdd && (
        <form className={styles.addPanel} onSubmit={addRepo}>
          <div className={styles.addIntro}>
            <strong>Monitor a GitHub repository</strong>
            <span>Ship Safe will scan the selected branch on schedule.</span>
          </div>
          <div className={styles.addGrid}>
            <label className={styles.fieldWide}>
              <span>Repository</span>
              <input
                type="text"
                placeholder="owner/repository"
                value={newRepo}
                onChange={event => setNewRepo(event.target.value)}
                autoFocus
              />
            </label>
            <label>
              <span>Branch</span>
              <input value={newBranch} onChange={event => setNewBranch(event.target.value)} placeholder="main" />
            </label>
            <label>
              <span>Schedule</span>
              <select value={newSchedule} onChange={event => setNewSchedule(event.target.value)}>
                {schedules.map(schedule => <option key={schedule.value} value={schedule.value}>{schedule.label}</option>)}
              </select>
            </label>
          </div>
          <div className={styles.addActions}>
            <span>The first scheduled run creates your security baseline.</span>
            <button className={styles.primaryButton} type="submit" disabled={!newRepo.trim() || adding}>
              {adding ? 'Adding...' : 'Start monitoring'}
            </button>
          </div>
        </form>
      )}

      {error && <p className={styles.error} role="alert">{error}</p>}

      {loading ? (
        <div className={styles.skeleton} aria-label="Loading repositories">
          {[0, 1, 2].map(item => <div key={item} />)}
        </div>
      ) : repos.length === 0 ? (
        <div className={styles.emptyState}>
          <div className={styles.emptyIcon}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          </div>
          <strong>Continuous protection starts here</strong>
          <p>Add your first repository above. You can pause monitoring or change its schedule at any time.</p>
        </div>
      ) : (
        <section className={styles.repoList} aria-label="Monitored repositories">
          {repos.map(repo => {
            const state = protectionState(repo);
            return (
              <article key={repo.id} className={`${styles.repoRow} ${!repo.enabled ? styles.repoPaused : ''}`}>
                <div className={styles.repoMain}>
                  <div className={styles.repoHeading}>
                    <strong>{repo.repo}</strong>
                    <span className={`${styles.stateBadge} ${styles[`state_${state.tone}`]}`}>{state.label}</span>
                  </div>
                  <div className={styles.repoMeta}>
                    <code>{repo.branch}</code>
                    <span>{repo.lastScanAt ? `Scanned ${timeAgo(repo.lastScanAt)}` : 'No baseline scan yet'}</span>
                  </div>
                </div>

                <div className={styles.repoControls}>
                  {repo.lastScore !== null && (
                    <div className={styles.score} style={{ color: scoreColor(repo.lastScore) }}>
                      <strong>{repo.lastGrade}</strong><span>{repo.lastScore}</span>
                    </div>
                  )}
                  <label className={styles.scheduleControl}>
                    <select
                      aria-label={`Schedule for ${repo.repo}`}
                      value={repo.schedule ?? ''}
                      disabled={!repo.enabled || savingId === repo.id}
                      onChange={event => updateRepo(repo.id, { schedule: event.target.value || null })}
                    >
                      <option value="">Manual</option>
                      {schedules.map(schedule => <option key={schedule.value} value={schedule.value}>{schedule.label}</option>)}
                    </select>
                  </label>
                  <Link href={`/app/history?repo=${encodeURIComponent(repo.repo)}`} className={styles.secondaryButton}>History</Link>
                  <Link
                    href={`/app/scan?repo=${encodeURIComponent(repo.repo)}&branch=${encodeURIComponent(repo.branch)}`}
                    className={styles.secondaryButton}
                    onClick={() => track('Monitored Repository Scan Started')}
                  >
                    Scan now
                  </Link>
                  <button
                    className={styles.iconButton}
                    title={repo.enabled ? 'Pause monitoring' : 'Resume monitoring'}
                    aria-label={repo.enabled ? `Pause monitoring ${repo.repo}` : `Resume monitoring ${repo.repo}`}
                    disabled={savingId === repo.id}
                    onClick={() => updateRepo(repo.id, { enabled: !repo.enabled })}
                  >
                    {repo.enabled ? (
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10 9v6M14 9v6"/><circle cx="12" cy="12" r="9"/></svg>
                    ) : (
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m10 8 6 4-6 4Z"/><circle cx="12" cy="12" r="9"/></svg>
                    )}
                  </button>
                  {confirmRemoveId === repo.id ? (
                    <div className={styles.confirmRemove}>
                      <button onClick={() => removeRepo(repo.id)} disabled={savingId === repo.id}>Remove</button>
                      <button onClick={() => setConfirmRemoveId(null)}>Cancel</button>
                    </div>
                  ) : (
                    <button
                      className={`${styles.iconButton} ${styles.removeButton}`}
                      title="Remove repository"
                      aria-label={`Remove ${repo.repo}`}
                      onClick={() => setConfirmRemoveId(repo.id)}
                    >
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 7h16M9 7V4h6v3M8 11v6M12 11v6M16 11v6M6 7l1 14h10l1-14"/></svg>
                    </button>
                  )}
                </div>
              </article>
            );
          })}
        </section>
      )}
    </div>
  );
}
