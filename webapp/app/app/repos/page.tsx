'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
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

const scheduleLabels: Record<string, string> = {
  '0 9 * * 1': 'Weekly (Mon 9am)',
  '0 9 * * *': 'Daily (9am)',
  '0 */6 * * *': 'Every 6 hours',
  '0 0 1 * *': 'Monthly (1st)',
};

const scoreColor = (s: number) => s >= 80 ? 'var(--green)' : s >= 60 ? 'var(--yellow)' : 'var(--red)';

export default function ReposPage() {
  const [repos, setRepos] = useState<MonitoredRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [newRepo, setNewRepo] = useState('');
  const [newBranch, setNewBranch] = useState('main');
  const [newSchedule, setNewSchedule] = useState('0 9 * * 1');
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/repos').then(r => r.json()).then(d => { setRepos(d.repos || []); setLoading(false); });
  }, []);

  async function addRepo() {
    setError('');
    let repoValue = newRepo.trim();
    const ghMatch = repoValue.match(/github\.com\/([^/]+\/[^/]+)/);
    if (ghMatch) repoValue = ghMatch[1].replace(/\.git$/, '');

    const res = await fetch('/api/repos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo: repoValue, branch: newBranch, schedule: newSchedule }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    setRepos(prev => [data, ...prev.filter(r => r.id !== data.id)]);
    setNewRepo('');
  }

  async function removeRepo(id: string) {
    await fetch('/api/repos', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    setRepos(prev => prev.filter(r => r.id !== id));
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Monitored Repos</h1>
          <p className={styles.subtitle}>Track repositories and run scheduled scans automatically</p>
        </div>
      </div>

      {/* Add repo */}
      <div className={styles.addSection}>
        <div className={styles.addRow}>
          <input
            type="text"
            placeholder="owner/repo or GitHub URL"
            value={newRepo}
            onChange={e => setNewRepo(e.target.value)}
            className={styles.input}
          />
          <input
            type="text"
            placeholder="branch"
            value={newBranch}
            onChange={e => setNewBranch(e.target.value)}
            className={styles.inputSmall}
          />
          <select value={newSchedule} onChange={e => setNewSchedule(e.target.value)} className={styles.select}>
            <option value="0 9 * * 1">Weekly</option>
            <option value="0 9 * * *">Daily</option>
            <option value="0 */6 * * *">Every 6h</option>
            <option value="0 0 1 * *">Monthly</option>
          </select>
          <button onClick={addRepo} className="btn btn-primary" disabled={!newRepo.trim()}>
            Monitor
          </button>
        </div>
        {error && <p className={styles.error}>{error}</p>}
      </div>

      {/* Repo list */}
      {loading ? (
        <p style={{ color: 'var(--text-dim)' }}>Loading...</p>
      ) : repos.length === 0 ? (
        <div className={styles.emptyState}>
          <p>No monitored repos yet. Add a repository above to start tracking its security score over time.</p>
        </div>
      ) : (
        <div className={styles.repoList}>
          {repos.map(repo => (
            <div key={repo.id} className={styles.repoRow}>
              <div className={styles.repoLeft}>
                <div className={styles.repoIcon}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" /></svg>
                </div>
                <div>
                  <div className={styles.repoName}>{repo.repo}</div>
                  <div className={styles.repoMeta}>
                    {repo.branch} · {repo.schedule ? (scheduleLabels[repo.schedule] || repo.schedule) : 'Manual'}
                    {repo.lastScanAt && ` · Last scan ${new Date(repo.lastScanAt).toLocaleDateString()}`}
                  </div>
                </div>
              </div>
              <div className={styles.repoRight}>
                {repo.lastScore !== null && repo.lastGrade && (
                  <div className={styles.scoreChip} style={{
                    color: scoreColor(repo.lastScore),
                    borderColor: scoreColor(repo.lastScore) + '40',
                    background: scoreColor(repo.lastScore) + '10',
                  }}>
                    <span className={styles.scoreGrade}>{repo.lastGrade}</span>
                    <span className={styles.scoreNum}>{repo.lastScore}</span>
                  </div>
                )}
                <Link href={`/app/scan?repo=${encodeURIComponent(repo.repo)}&branch=${repo.branch}`} className={styles.scanNow}>
                  Scan now
                </Link>
                <button onClick={() => removeRepo(repo.id)} className={styles.removeBtn}>✕</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
