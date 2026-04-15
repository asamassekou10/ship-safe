import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './agents.module.css';
import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Agents — Ship Safe' };

function timeAgo(date: Date | string) {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function statusLabel(status: string) {
  if (status === 'deployed') return { label: 'Live', cls: 'statusLive' };
  if (status === 'stopped')  return { label: 'Stopped', cls: 'statusStopped' };
  if (status === 'failed')   return { label: 'Failed', cls: 'statusFailed' };
  return { label: 'Draft', cls: 'statusDraft' };
}

export default async function AgentsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  const isPaid = plan === 'pro' || plan === 'team' || plan === 'enterprise';
  const freeAgentLimit = 1;

  const agents = await prisma.agent.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: 'desc' },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { status: true, securityScore: true, createdAt: true, subdomain: true },
      },
    },
  });

  const atAgentLimit = !isPaid && agents.length >= freeAgentLimit;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Agents</h1>
          <p className={styles.subtitle}>Build, configure, and deploy Hermes agents from one place.</p>
        </div>
        {atAgentLimit ? (
          <Link href="/pricing" className={styles.newBtn} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-muted)' }} title="Upgrade to Pro for unlimited agents">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Upgrade for more
          </Link>
        ) : (
          <Link href="/app/agents/new" className={styles.newBtn}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New Agent
          </Link>
        )}
      </div>

      {!isPaid && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.6rem 0.9rem', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, marginBottom: '1rem', fontSize: '0.83rem', color: 'var(--text-muted)' }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Free plan: {agents.length}/{freeAgentLimit} agent used.{' '}
          <Link href="/pricing" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>Upgrade to Pro</Link>
          {' '}for unlimited agents.
        </div>
      )}

      {/* How it works */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '2rem' }}>
        {[
          { step: '1', title: 'Create', body: 'Define your agent\'s name, system prompt, and tools. This sets its personality and capabilities — e.g. "Penetration Tester specialising in web APIs".' },
          { step: '2', title: 'Deploy', body: 'Start the agent from the Deploy tab. The orchestrator spins up a Hermes container on your VPS and gives it a live port.' },
          { step: '3', title: 'Run', body: 'Chat with it directly, fire it via webhook, or schedule it with a cron trigger. Every run is saved with full message history and any findings it surfaces.' },
        ].map(({ step, title, body }) => (
          <div key={step} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1rem 1.1rem', display: 'flex', gap: '0.75rem' }}>
            <div style={{ flexShrink: 0, width: 24, height: 24, borderRadius: '50%', background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.7rem', fontWeight: 700, color: 'var(--cyan)', marginTop: '0.1rem' }}>{step}</div>
            <div>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, marginBottom: '0.25rem' }}>{title}</div>
              <div style={{ fontSize: '0.77rem', color: 'var(--text-dim)', lineHeight: 1.5 }}>{body}</div>
            </div>
          </div>
        ))}
      </div>

      {agents.length === 0 ? (
        <div className={styles.empty}>
          <div className={styles.emptyIcon}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
          </div>
          <div className={styles.emptyTitle}>No agents yet</div>
          <div className={styles.emptyDesc}>Create your first Hermes agent. Define its tools, memory, and delegation settings — then deploy it to a live URL.</div>
          <Link href="/app/agents/new" className={styles.emptyCta}>Create your first agent →</Link>
        </div>
      ) : (
        <div className={styles.grid}>
          {agents.map(agent => {
            const lastDeploy = agent.deployments[0];
            const { label, cls } = statusLabel(agent.status);
            const tools = (agent.tools as Array<{ name: string }>) ?? [];
            return (
              <Link key={agent.id} href={`/app/agents/${agent.id}`} className={styles.card}>
                <div className={styles.cardTop}>
                  <div className={styles.cardName}>{agent.name}</div>
                  <span className={`${styles.statusBadge} ${styles[cls]}`}>{label}</span>
                </div>
                {agent.description && (
                  <div className={styles.cardDesc}>{agent.description}</div>
                )}
                <div className={styles.cardMeta}>
                  <span className={styles.metaItem}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    {tools.length} tool{tools.length !== 1 ? 's' : ''}
                  </span>
                  <span className={styles.metaItem}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
                    {agent.memoryProvider}
                  </span>
                  {lastDeploy && (
                    <span className={styles.metaItem}>
                      {timeAgo(lastDeploy.createdAt)}
                    </span>
                  )}
                  {lastDeploy?.securityScore != null && (
                    <span className={styles.scoreChip} style={{ color: lastDeploy.securityScore >= 80 ? 'var(--green)' : lastDeploy.securityScore >= 60 ? 'var(--yellow)' : 'var(--red)' }}>
                      {lastDeploy.securityScore}/100
                    </span>
                  )}
                </div>
                {lastDeploy?.subdomain && (
                  <div className={styles.cardUrl}>{lastDeploy.subdomain}.shipsafecli.com</div>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
