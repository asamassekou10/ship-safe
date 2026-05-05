import Link from 'next/link';
import { redirect } from 'next/navigation';
import type { Metadata } from 'next';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import ContentAgentControls from './ContentAgentControls';
import DraftActions from './DraftActions';
import styles from './content-agent.module.css';

export const metadata: Metadata = { title: 'Content Agent — Ship Safe' };

function timeAgo(date: Date | string) {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

export default async function ContentAgentPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const [drafts, runs] = await Promise.all([
    prisma.contentDraft.findMany({
      where: { userId: session.user.id },
      orderBy: { createdAt: 'desc' },
      take: 12,
    }),
    prisma.contentAgentRun.findMany({
      where: { userId: session.user.id },
      orderBy: { createdAt: 'desc' },
      take: 8,
      include: {
        draft: {
          select: {
            id: true,
            title: true,
            slug: true,
          },
        },
      },
    }),
  ]);

  const approvedCount = drafts.filter((draft) => draft.status === 'approved').length;
  const reviewCount = drafts.filter((draft) => draft.status === 'draft').length;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Content Agent</h1>
          <p className={styles.subtitle}>Discover security stories, draft cited blog posts, and review them before publishing.</p>
        </div>
        <ContentAgentControls />
      </div>

      <section className={styles.statsRow}>
        <div className={styles.stat}>
          <span className={styles.statValue}>{drafts.length}</span>
          <span className={styles.statLabel}>Drafts</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>{reviewCount}</span>
          <span className={styles.statLabel}>Needs review</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>{approvedCount}</span>
          <span className={styles.statLabel}>Approved</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.statValue}>{runs.length}</span>
          <span className={styles.statLabel}>Recent runs</span>
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Draft Queue</h2>
          <Link className={styles.secondaryLink} href="/blog">Public blog</Link>
        </div>

        {drafts.length === 0 ? (
          <div className={styles.empty}>
            <div className={styles.emptyTitle}>No content drafts yet</div>
            <p>Run discovery to collect recent sources and create the first reviewable blog draft.</p>
          </div>
        ) : (
          <div className={styles.draftList}>
            {drafts.map((draft) => {
              const tags = asStringArray(draft.tags);
              const guardrails = asStringArray(draft.guardrails);
              return (
                <article key={draft.id} className={styles.draftRow}>
                  <Link href={`/app/content-agent/drafts/${draft.id}`} className={styles.draftMain}>
                    <div className={styles.draftMeta}>
                      <span className={`${styles.status} ${styles[`status_${draft.status}`] ?? ''}`}>{draft.status}</span>
                      <span>{timeAgo(draft.createdAt)}</span>
                    </div>
                    <h3>{draft.title}</h3>
                    <p>{draft.description}</p>
                    <div className={styles.tagRow}>
                      {tags.slice(0, 5).map((tag) => <span key={tag}>{tag}</span>)}
                    </div>
                    {guardrails.length > 0 && (
                      <div className={styles.guardrail}>{guardrails[0]}</div>
                    )}
                  </Link>
                  <DraftActions draftId={draft.id} status={draft.status} />
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Run History</h2>
        </div>
        <div className={styles.runList}>
          {runs.length === 0 ? (
            <div className={styles.runEmpty}>No runs yet.</div>
          ) : runs.map((run) => (
            <div key={run.id} className={styles.runRow}>
              <div>
                <span className={`${styles.status} ${styles[`status_${run.status}`] ?? ''}`}>{run.status}</span>
                <span className={styles.runTime}>{timeAgo(run.createdAt)}</span>
              </div>
              <div className={styles.runDetail}>
                {run.draft?.title ?? asStringArray(run.guardrails)[0] ?? `${run.candidateCount} candidates scanned`}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
