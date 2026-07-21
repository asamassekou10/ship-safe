import Link from 'next/link';
import styles from './dashboard.module.css';

export type RepositoryPostureItem = {
  repo: string;
  latestScanId: string;
  score: number | null;
  grade: string | null;
  findings: number;
  status: string;
  protected: boolean;
  previousScore: number | null;
  scannedAt: string;
};

function timeAgo(value: string) {
  const elapsed = Date.now() - new Date(value).getTime();
  const days = Math.floor(elapsed / 86400000);
  if (days < 1) return 'Today';
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

function scoreTone(score: number | null) {
  if (score === null) return 'var(--text-dim)';
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  return 'var(--red)';
}

export default function RepositoryPosture({ repositories }: { repositories: RepositoryPostureItem[] }) {
  return (
    <section className={styles.repoPosturePanel} aria-labelledby="repository-posture-title">
      <div className={styles.panelHeader}>
        <div>
          <span className={styles.panelEyebrow}>Repository coverage</span>
          <h2 id="repository-posture-title">Repository posture</h2>
        </div>
        <Link href="/app/repos" className={styles.panelAction}>Manage repositories →</Link>
      </div>

      {repositories.length === 0 ? (
        <div className={styles.repoPostureEmpty}>
          <span>No repository posture is available yet.</span>
          <Link href="/app/scan">Run your first scan →</Link>
        </div>
      ) : (
        <div className={styles.repoPostureTable}>
          <div className={styles.repoPostureHead} aria-hidden="true">
            <span>Repository</span><span>Security score</span><span>Open signals</span><span>Last activity</span><span />
          </div>
          {repositories.map(repository => {
            const delta = repository.score !== null && repository.previousScore !== null
              ? repository.score - repository.previousScore
              : null;
            const tone = scoreTone(repository.score);
            return (
              <div className={styles.repoPostureRow} key={repository.repo}>
                <div className={styles.repoIdentity}>
                  <span className={styles.repoMark}>R</span>
                  <div><strong>{repository.repo}</strong><small>{repository.protected ? 'Continuously monitored' : 'Manual scans'}</small></div>
                </div>
                <div className={styles.repoScoreCell}>
                  <div className={styles.repoScoreMeta}><strong style={{ color: tone }}>{repository.score ?? '—'}</strong><span>{repository.grade ?? 'No grade'}</span>{delta !== null && <small className={delta >= 0 ? styles.deltaUp : styles.deltaDown}>{delta >= 0 ? '+' : ''}{delta}</small>}</div>
                  <div className={styles.repoScoreTrack}><span style={{ width: `${repository.score ?? 0}%`, background: tone }} /></div>
                </div>
                <div className={styles.repoFindingCell}><strong>{repository.findings}</strong><span>{repository.status === 'failed' ? 'Latest scan failed' : 'scan findings'}</span></div>
                <div className={styles.repoTimeCell}><strong>{timeAgo(repository.scannedAt)}</strong><span>{repository.protected ? 'Protected' : 'Unmonitored'}</span></div>
                <div className={styles.repoActions}>
                  <Link href={`/app/history?repo=${encodeURIComponent(repository.repo)}`} aria-label={`View ${repository.repo} scan history`}>History</Link>
                  <Link href={`/app/scans/${repository.latestScanId}`} aria-label={`Open latest ${repository.repo} scan`}>Open →</Link>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
