import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import type { Metadata } from 'next';
import styles from './compare.module.css';

export const metadata: Metadata = { title: 'Compare Scans — Ship Safe' };

const scoreColor = (n: number) => n >= 80 ? 'var(--green)' : n >= 60 ? 'var(--yellow)' : 'var(--red)';

interface Finding {
  title: string;
  file: string;
  line?: number;
  severity: string;
  category: string;
  rule: string;
}

interface Report {
  findings?: Finding[];
  [key: string]: unknown;
}

export default async function ComparePage({
  searchParams,
}: {
  searchParams: Promise<{ a?: string; b?: string }>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');
  const { a, b } = await searchParams;

  // Fetch all user scans for the picker
  const allScans = await prisma.scan.findMany({
    where: { userId: session.user.id, status: 'done' },
    orderBy: { createdAt: 'desc' },
    take: 50,
    select: { id: true, repo: true, branch: true, score: true, grade: true, createdAt: true },
  });

  const scanA = a ? await prisma.scan.findFirst({ where: { id: a, userId: session.user.id } }) : null;
  const scanB = b ? await prisma.scan.findFirst({ where: { id: b, userId: session.user.id } }) : null;

  // Compute diff
  let diff: { added: Finding[]; resolved: Finding[]; changed: Finding[] } | null = null;
  if (scanA && scanB) {
    const findingsA: Finding[] = (scanA.report as Report)?.findings ?? [];
    const findingsB: Finding[] = (scanB.report as Report)?.findings ?? [];
    const keyOf = (f: Finding) => `${f.rule}:${f.file}:${f.line ?? 0}`;
    const setA = new Map(findingsA.map(f => [keyOf(f), f]));
    const setB = new Map(findingsB.map(f => [keyOf(f), f]));
    const added = findingsB.filter(f => !setA.has(keyOf(f)));
    const resolved = findingsA.filter(f => !setB.has(keyOf(f)));
    diff = { added, resolved, changed: [] };
  }

  const scoreDelta = scanA && scanB && scanA.score !== null && scanB.score !== null
    ? scanB.score - scanA.score
    : null;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Compare Scans</h1>
          <p className={styles.subtitle}>See what changed between two scans</p>
        </div>
        <Link href="/app/history" className="btn btn-ghost" style={{ fontSize: '0.82rem' }}>← History</Link>
      </div>

      {/* Scan picker */}
      <div className={styles.picker}>
        <ScanPicker label="Baseline" paramKey="a" selectedId={a} scans={allScans} otherSelected={b} />
        <div className={styles.pickerArrow}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </div>
        <ScanPicker label="Compare to" paramKey="b" selectedId={b} scans={allScans} otherSelected={a} />
      </div>

      {/* Results */}
      {scanA && scanB && diff && (
        <>
          {/* Score summary */}
          <div className={styles.scoreSummary}>
            <div className={styles.scoreCard}>
              <span className={styles.scoreCardLabel}>{new Date(scanA.createdAt).toLocaleDateString()} · {scanA.branch}</span>
              <span className={styles.scoreNum} style={{ color: scanA.score !== null ? scoreColor(scanA.score) : 'var(--text-dim)' }}>
                {scanA.score ?? '—'}
              </span>
              <span className={styles.scoreGrade}>{scanA.grade}</span>
            </div>

            <div className={styles.deltaCard}>
              {scoreDelta !== null && (
                <>
                  <span className={styles.deltaNum} style={{ color: scoreDelta > 0 ? 'var(--green)' : scoreDelta < 0 ? 'var(--red)' : 'var(--text-dim)' }}>
                    {scoreDelta > 0 ? '+' : ''}{scoreDelta}
                  </span>
                  <span className={styles.deltaLabel}>{scoreDelta > 0 ? 'improved' : scoreDelta < 0 ? 'regressed' : 'no change'}</span>
                </>
              )}
              <div className={styles.diffStats}>
                <span className={styles.diffStat} style={{ color: 'var(--green)' }}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  {diff.resolved.length} resolved
                </span>
                <span className={styles.diffStat} style={{ color: diff.added.length > 0 ? 'var(--red)' : 'var(--text-dim)' }}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                  {diff.added.length} new
                </span>
              </div>
            </div>

            <div className={styles.scoreCard}>
              <span className={styles.scoreCardLabel}>{new Date(scanB.createdAt).toLocaleDateString()} · {scanB.branch}</span>
              <span className={styles.scoreNum} style={{ color: scanB.score !== null ? scoreColor(scanB.score) : 'var(--text-dim)' }}>
                {scanB.score ?? '—'}
              </span>
              <span className={styles.scoreGrade}>{scanB.grade}</span>
            </div>
          </div>

          {/* Resolved findings */}
          {diff.resolved.length > 0 && (
            <DiffSection title={`${diff.resolved.length} Resolved`} color="var(--green)" findings={diff.resolved} type="resolved" />
          )}

          {/* New findings */}
          {diff.added.length > 0 && (
            <DiffSection title={`${diff.added.length} New`} color="var(--red)" findings={diff.added} type="added" />
          )}

          {diff.resolved.length === 0 && diff.added.length === 0 && (
            <div className={styles.noChange}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polyline points="20 6 9 17 4 12"/></svg>
              No changes in findings between these two scans.
            </div>
          )}
        </>
      )}

      {(!a || !b) && (
        <div className={styles.pickPrompt}>
          Select two scans above to compare them.
        </div>
      )}
    </div>
  );
}

const SEV_COLORS: Record<string, string> = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a' };

function DiffSection({ title, color, findings, type }: { title: string; color: string; findings: Finding[]; type: 'added' | 'resolved' }) {
  return (
    <div className={styles.diffSection}>
      <div className={styles.diffSectionTitle} style={{ color }}>
        {type === 'resolved'
          ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          : <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        }
        {title}
      </div>
      <div className={styles.diffList}>
        {findings.map((f, i) => (
          <div key={i} className={`${styles.diffItem} ${type === 'added' ? styles.diffAdded : styles.diffResolved}`}>
            <span className={styles.diffSev} style={{ background: SEV_COLORS[f.severity] + '18', color: SEV_COLORS[f.severity], borderColor: SEV_COLORS[f.severity] + '40' }}>
              {f.severity}
            </span>
            <div className={styles.diffBody}>
              <div className={styles.diffTitle}>{f.title}</div>
              <div className={styles.diffFile}>{f.file}{f.line ? `:${f.line}` : ''}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScanPicker({ label, paramKey, selectedId, scans, otherSelected }: {
  label: string;
  paramKey: string;
  selectedId?: string;
  scans: { id: string; repo: string; branch: string; score: number | null; grade: string | null; createdAt: Date }[];
  otherSelected?: string;
}) {
  const selected = scans.find(s => s.id === selectedId);
  return (
    <div className={styles.pickerCard}>
      <div className={styles.pickerLabel}>{label}</div>
      {selected ? (
        <div className={styles.pickerSelected}>
          <div className={styles.pickerRepo}>{selected.repo}</div>
          <div className={styles.pickerMeta}>{selected.branch} · {new Date(selected.createdAt).toLocaleDateString()}</div>
        </div>
      ) : (
        <div className={styles.pickerPlaceholder}>Select a scan</div>
      )}
      <select
        className={styles.pickerSelect}
        defaultValue={selectedId ?? ''}
        // Client-side navigation via form submit would be ideal, but for simplicity
        // we use a native form approach; the link below handles actual navigation
        aria-label={`Select ${label} scan`} // ship-safe-ignore — aria-label string, not a SQL query
      >
        <option value="">— choose —</option>
        {scans.filter(s => s.id !== otherSelected).map(s => (
          <option key={s.id} value={s.id}>
            {s.repo} · {s.branch} · {new Date(s.createdAt).toLocaleDateString()} {s.grade ? `(${s.grade} ${s.score})` : ''}
          </option>
        ))}
      </select>
      {/* Navigation links for each scan option */}
      <div className={styles.pickerLinks}>
        {scans.filter(s => s.id !== otherSelected).slice(0, 8).map(s => (
          <Link
            key={s.id}
            href={paramKey === 'a' ? `/app/compare?a=${s.id}${otherSelected ? `&b=${otherSelected}` : ''}` : `/app/compare?b=${s.id}${otherSelected ? `&a=${otherSelected}` : ''}`}
            className={`${styles.pickerLink} ${s.id === selectedId ? styles.pickerLinkActive : ''}`}
          >
            <span className={styles.pickerLinkRepo}>{s.repo}</span>
            <span className={styles.pickerLinkMeta}>{s.branch} · {new Date(s.createdAt).toLocaleDateString()}</span>
            {s.grade && <span className={styles.pickerLinkScore}>{s.grade}</span>}
          </Link>
        ))}
      </div>
    </div>
  );
}
