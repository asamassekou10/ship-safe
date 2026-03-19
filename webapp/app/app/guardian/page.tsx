'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import styles from './guardian.module.css';

interface GuardianRun {
  id: string;
  repo: string;
  prNumber: number;
  prTitle: string | null;
  prBranch: string;
  baseBranch: string;
  status: string;
  failureType: string | null;
  fixSummary: string | null;
  attempts: number;
  createdAt: string;
  updatedAt: string;
}

interface GuardianConfig {
  id: string;
  repo: string;
  enabled: boolean;
  autoFixFalsePositives: boolean;
  autoFixRealIssues: boolean;
  autoMerge: boolean;
  mergeStrategy: string;
  requireApproval: boolean;
  minScoreToMerge: number;
  maxAttempts: number;
}

function timeAgo(date: string) {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function statusClass(status: string) {
  if (status === 'merged') return styles.statusMerged;
  if (status === 'failed') return styles.statusFailed;
  if (status === 'blocked') return styles.statusBlocked;
  return styles.statusActive;
}

export default function GuardianPage() {
  const [runs, setRuns] = useState<GuardianRun[]>([]);
  const [config, setConfig] = useState<GuardianConfig | null>(null);
  const [triggerRepo, setTriggerRepo] = useState('');
  const [triggerPR, setTriggerPR] = useState('');
  const [error, setError] = useState('');

  const loadData = useCallback(async () => {
    const [runsRes, configRes] = await Promise.all([
      fetch('/api/guardian/runs'),
      fetch('/api/guardian/config'),
    ]);
    const runsData = await runsRes.json();
    const configData = await configRes.json();
    setRuns(runsData.runs || []);
    // Use the default (*) config or first config
    const configs = configData.configs || [];
    setConfig(configs.find((c: GuardianConfig) => c.repo === '*') || configs[0] || null);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function triggerGuardian() {
    setError('');
    const pr = parseInt(triggerPR, 10);
    if (!triggerRepo || !pr) { setError('Enter repo (owner/repo) and PR number'); return; }
    const res = await fetch('/api/guardian/trigger', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo: triggerRepo, prNumber: pr }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    setTriggerRepo('');
    setTriggerPR('');
    loadData();
  }

  async function retryRun(id: string) {
    await fetch(`/api/guardian/runs/${id}/retry`, { method: 'POST' });
    loadData();
  }

  async function updateConfig(field: string, value: unknown) {
    const repo = config?.repo || '*';
    const res = await fetch('/api/guardian/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repo, [field]: value }),
    });
    const data = await res.json();
    if (res.ok) setConfig(data.config);
  }

  // Stats
  const merged = runs.filter(r => r.status === 'merged').length;
  const failed = runs.filter(r => r.status === 'failed').length;
  const active = runs.filter(r => !['merged', 'failed', 'blocked'].includes(r.status)).length;
  const fixedCount = runs.filter(r => r.fixSummary).length;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1>PR Guardian</h1>
        <p className={styles.subtitle}>Automated PR review, fix, and merge pipeline</p>
      </div>

      {/* Stats */}
      <div className={styles.statsRow}>
        <div className={styles.statCard}>
          <div className={styles.statValue} style={{ color: 'var(--cyan)' }}>{runs.length}</div>
          <div className={styles.statLabel}>Total Runs</div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statValue} style={{ color: 'var(--green)' }}>{merged}</div>
          <div className={styles.statLabel}>Auto-Merged</div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statValue} style={{ color: 'var(--yellow)' }}>{fixedCount}</div>
          <div className={styles.statLabel}>Fixes Applied</div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statValue} style={{ color: active > 0 ? 'var(--cyan)' : 'var(--text-dim)' }}>{active}</div>
          <div className={styles.statLabel}>Active</div>
        </div>
      </div>

      {/* Manual Trigger */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Trigger Guardian</div>
        <div className={styles.triggerForm}>
          <input
            className={styles.input}
            placeholder="owner/repo"
            value={triggerRepo}
            onChange={e => setTriggerRepo(e.target.value)}
          />
          <input
            className={styles.input}
            placeholder="PR #"
            value={triggerPR}
            onChange={e => setTriggerPR(e.target.value)}
            style={{ maxWidth: '100px' }}
          />
          <button onClick={triggerGuardian} className="btn btn-primary" style={{ fontSize: '0.82rem', padding: '0.55rem 1rem', whiteSpace: 'nowrap' }}>
            Run Guardian
          </button>
        </div>
        {error && <p style={{ color: 'var(--red)', fontSize: '0.82rem' }}>{error}</p>}
      </div>

      {/* Config */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Configuration</div>
        <div className={styles.configCard}>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Auto-fix false positives</div>
              <div className={styles.configDesc}>Add ship-safe-ignore comments for confirmed false positives</div>
            </div>
            <button
              className={`${styles.toggle} ${config?.autoFixFalsePositives !== false ? styles.toggleOn : ''}`}
              onClick={() => updateConfig('autoFixFalsePositives', !(config?.autoFixFalsePositives !== false))}
            />
          </div>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Auto-fix real issues</div>
              <div className={styles.configDesc}>Generate and commit code fixes for real vulnerabilities</div>
            </div>
            <button
              className={`${styles.toggle} ${config?.autoFixRealIssues ? styles.toggleOn : ''}`}
              onClick={() => updateConfig('autoFixRealIssues', !config?.autoFixRealIssues)}
            />
          </div>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Auto-merge</div>
              <div className={styles.configDesc}>Merge PRs automatically after all checks pass</div>
            </div>
            <button
              className={`${styles.toggle} ${config?.autoMerge ? styles.toggleOn : ''}`}
              onClick={() => updateConfig('autoMerge', !config?.autoMerge)}
            />
          </div>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Merge strategy</div>
            </div>
            <select
              className={styles.select}
              value={config?.mergeStrategy || 'squash'}
              onChange={e => updateConfig('mergeStrategy', e.target.value)}
            >
              <option value="squash">Squash</option>
              <option value="merge">Merge commit</option>
              <option value="rebase">Rebase</option>
            </select>
          </div>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Require approval before merge</div>
            </div>
            <button
              className={`${styles.toggle} ${config?.requireApproval !== false ? styles.toggleOn : ''}`}
              onClick={() => updateConfig('requireApproval', !(config?.requireApproval !== false))}
            />
          </div>
          <div className={styles.configRow}>
            <div>
              <div className={styles.configLabel}>Minimum score to merge</div>
            </div>
            <input
              type="number"
              className={styles.scoreInput}
              value={config?.minScoreToMerge ?? 80}
              min={0}
              max={100}
              onChange={e => updateConfig('minScoreToMerge', parseInt(e.target.value, 10))}
            />
          </div>
        </div>
      </div>

      {/* Runs */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Recent Runs</div>
        {runs.length === 0 ? (
          <div className={styles.empty}>
            No Guardian runs yet. Trigger one manually or enable Guardian on a monitored repo.
          </div>
        ) : (
          <div className={styles.runList}>
            {runs.map(run => (
              <Link href={`/app/guardian/${run.id}`} key={run.id} className={styles.runCard}>
                <div className={styles.runInfo}>
                  <div className={styles.runRepo}>
                    {run.repo} <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>#{run.prNumber}</span>
                  </div>
                  <div className={styles.runMeta}>
                    {run.prTitle || run.prBranch} &middot; {timeAgo(run.createdAt)}
                    {run.fixSummary && ` · ${run.fixSummary}`}
                  </div>
                </div>
                <div className={styles.runRight}>
                  <span className={`${styles.statusBadge} ${statusClass(run.status)}`}>
                    {run.status}
                  </span>
                  {(run.status === 'failed' || run.status === 'blocked') && (
                    <button
                      className={styles.retryBtn}
                      onClick={e => { e.preventDefault(); retryRun(run.id); }}
                    >
                      Retry
                    </button>
                  )}
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
