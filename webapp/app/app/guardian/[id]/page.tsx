'use client';
import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import styles from './run-detail.module.css';

interface TimelineEntry {
  timestamp: string;
  event: string;
  detail?: string;
}

interface DiagnosedFinding {
  file?: string;
  line?: number;
  severity?: string;
  title?: string;
  reason?: string;
}

interface GuardianRun {
  id: string;
  repo: string;
  prNumber: number;
  prTitle: string | null;
  prBranch: string;
  baseBranch: string;
  status: string;
  scanId: string | null;
  ciRunId: number | null;
  ciStatus: string | null;
  failureType: string | null;
  failureLogs: string | null;
  diagnosis: {
    findings?: DiagnosedFinding[];
    falsePositives?: DiagnosedFinding[];
    realIssues?: DiagnosedFinding[];
  } | null;
  fixCommitSha: string | null;
  fixSummary: string | null;
  mergeStrategy: string | null;
  mergeSha: string | null;
  attempts: number;
  timeline: TimelineEntry[];
  createdAt: string;
  updatedAt: string;
}

function getDotClass(event: string): string {
  const e = event.toLowerCase();
  if (e.includes('merged') || e.includes('passed') || e.includes('complete')) return styles.dotGreen;
  if (e.includes('failed') || e.includes('error')) return styles.dotRed;
  if (e.includes('blocked') || e.includes('diagnosis') || e.includes('waiting')) return styles.dotYellow;
  return styles.dotCyan;
}

function statusClass(status: string) {
  if (status === 'merged') return styles.statusMerged;
  if (status === 'failed') return styles.statusFailed;
  if (status === 'blocked') return styles.statusBlocked;
  return styles.statusActive;
}

export default function GuardianRunDetail() {
  const params = useParams();
  const id = params.id as string;
  const [run, setRun] = useState<GuardianRun | null>(null);
  const [loading, setLoading] = useState(true);

  const loadRun = useCallback(async () => {
    const res = await fetch(`/api/guardian/runs/${id}`);
    if (res.ok) {
      const data = await res.json();
      setRun(data.run);
    }
    setLoading(false);
  }, [id]);

  useEffect(() => {
    loadRun();
    // Poll while in active state
    const interval = setInterval(() => {
      if (run && !['merged', 'failed', 'blocked'].includes(run.status)) {
        loadRun();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [loadRun, run?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  async function retry() {
    await fetch(`/api/guardian/runs/${id}/retry`, { method: 'POST' });
    loadRun();
  }

  if (loading) return <div className={styles.loading}>Loading...</div>;
  if (!run) return <div className={styles.loading}>Run not found</div>;

  const [owner, repo] = run.repo.split('/');
  const prUrl = `https://github.com/${owner}/${repo}/pull/${run.prNumber}`;

  return (
    <div className={styles.page}>
      <Link href="/app/guardian" className={styles.backLink}>
        ← Back to PR Guardian
      </Link>

      <div className={styles.header}>
        <div className={styles.headerInfo}>
          <h1>{run.prTitle || `PR #${run.prNumber}`}</h1>
          <div className={styles.headerMeta}>
            <span>{run.repo}</span>
            <span>{run.prBranch} → {run.baseBranch}</span>
            <a href={prUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--cyan)' }}>
              View on GitHub ↗
            </a>
          </div>
        </div>
        <span className={`${styles.statusBadge} ${statusClass(run.status)}`}>
          {run.status}
        </span>
      </div>

      {/* Actions */}
      {(run.status === 'failed' || run.status === 'blocked') && (
        <div className={styles.actions}>
          <button onClick={retry} className={`${styles.actionBtn} ${styles.actionBtnPrimary}`}>
            Retry Pipeline
          </button>
          <a href={prUrl} target="_blank" rel="noopener noreferrer" className={styles.actionBtn}>
            Open PR on GitHub
          </a>
        </div>
      )}

      {/* Timeline */}
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Timeline</div>
        <div className={styles.timeline}>
          {(run.timeline || []).map((entry, i) => (
            <div key={i} className={styles.timelineEntry}>
              <div className={`${styles.timelineDot} ${getDotClass(entry.event)}`} />
              <div className={styles.timelineEvent}>{entry.event}</div>
              {entry.detail && <div className={styles.timelineDetail}>{entry.detail}</div>}
              <div className={styles.timelineTime}>
                {new Date(entry.timestamp).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Diagnosis */}
      {run.diagnosis && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Diagnosis</div>

          {run.diagnosis.falsePositives && run.diagnosis.falsePositives.length > 0 && (
            <div className={styles.diagCard}>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--yellow)' }}>
                False Positives ({run.diagnosis.falsePositives.length})
              </div>
              {run.diagnosis.falsePositives.map((f, i) => (
                <div key={i} className={styles.diagRow}>
                  <div>
                    <div>{f.title || 'Finding'}</div>
                    <div className={styles.diagFile}>{f.file}{f.line ? `:${f.line}` : ''}</div>
                  </div>
                  <span className={`${styles.fpBadge} ${styles.fpBadgeFalse}`}>
                    {f.reason || 'False positive'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {run.diagnosis.realIssues && run.diagnosis.realIssues.length > 0 && (
            <div className={styles.diagCard}>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--red)' }}>
                Real Issues ({run.diagnosis.realIssues.length})
              </div>
              {run.diagnosis.realIssues.map((f, i) => (
                <div key={i} className={styles.diagRow}>
                  <div>
                    <div>{f.title || 'Finding'}</div>
                    <div className={styles.diagFile}>{f.file}{f.line ? `:${f.line}` : ''}</div>
                  </div>
                  <span className={`${styles.fpBadge} ${styles.fpBadgeReal}`}>
                    {f.severity || 'issue'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Fix details */}
      {run.fixCommitSha && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Fix Applied</div>
          <div className={styles.diagCard}>
            <div style={{ fontSize: '0.85rem' }}>{run.fixSummary}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan)', marginTop: '0.5rem' }}>
              <a
                href={`https://github.com/${owner}/${repo}/commit/${run.fixCommitSha}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--cyan)' }}
              >
                {run.fixCommitSha.slice(0, 7)}
              </a>
              {run.attempts > 0 && ` · Attempt ${run.attempts}`}
            </div>
          </div>
        </div>
      )}

      {/* Merge details */}
      {run.mergeSha && (
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Merge</div>
          <div className={styles.diagCard}>
            <div style={{ fontSize: '0.85rem' }}>
              Merged via {run.mergeStrategy || 'squash'}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--green)', marginTop: '0.25rem' }}>
              {run.mergeSha.slice(0, 7)}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
