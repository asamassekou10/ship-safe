import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './agents.module.css';
import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'AI Agents — Ship Safe' };

function timeAgo(date: Date | string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(date).getTime()) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function health(status: string, deploymentStatus?: string, runStatus?: string) {
  if (status === 'failed' || deploymentStatus === 'failed' || runStatus === 'error') {
    return { label: 'Needs attention', tone: 'danger' };
  }
  if (deploymentStatus === 'pending') return { label: 'Deploying', tone: 'progress' };
  if (status === 'deployed' && deploymentStatus === 'running') return { label: 'Active', tone: 'success' };
  if (status === 'stopped') return { label: 'Paused', tone: 'muted' };
  return { label: 'Setup needed', tone: 'warning' };
}

export default async function AgentsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const userId = session.user.id;
  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  const isPaid = plan === 'pro' || plan === 'team' || plan === 'enterprise';
  const freeAgentLimit = 1;

  const [agents, openFindingCounts, recentRuns] = await Promise.all([
    prisma.agent.findMany({
      where: { userId },
      orderBy: { updatedAt: 'desc' },
      include: {
        deployments: {
          orderBy: { createdAt: 'desc' },
          take: 1,
          select: { id: true, status: true, securityScore: true, createdAt: true, subdomain: true },
        },
        _count: { select: { triggers: true } },
      },
    }),
    prisma.finding.groupBy({
      by: ['agentId'],
      where: { agent: { userId }, status: 'open' },
      _count: { _all: true },
    }),
    prisma.agentRun.findMany({
      where: { deployment: { agent: { userId } } },
      orderBy: { startedAt: 'desc' },
      take: 100,
      select: {
        id: true,
        status: true,
        startedAt: true,
        _count: { select: { findings: true } },
        deployment: { select: { agentId: true } },
      },
    }),
  ]);

  const openByAgent = new Map(openFindingCounts.map(item => [item.agentId, item._count._all]));
  const latestRunByAgent = new Map<string, (typeof recentRuns)[number]>();
  for (const run of recentRuns) {
    if (!latestRunByAgent.has(run.deployment.agentId)) latestRunByAgent.set(run.deployment.agentId, run);
  }

  const agentRows = agents.map(agent => {
    const deployment = agent.deployments[0];
    const run = latestRunByAgent.get(agent.id);
    return {
      agent,
      deployment,
      run,
      openFindings: openByAgent.get(agent.id) ?? 0,
      health: health(agent.status, deployment?.status, run?.status),
    };
  });

  const activeCount = agentRows.filter(row => row.health.tone === 'success').length;
  const attentionCount = agentRows.filter(row => row.health.tone === 'danger').length;
  const setupCount = agentRows.filter(row => row.health.tone === 'warning').length;
  const totalOpenFindings = agentRows.reduce((total, row) => total + row.openFindings, 0);
  const atAgentLimit = !isPaid && agents.length >= freeAgentLimit;

  const attentionAgent = agentRows.find(row => row.health.tone === 'danger');
  const findingAgent = agentRows.find(row => row.openFindings > 0);
  const setupAgent = agentRows.find(row => row.health.tone === 'warning' || row.health.tone === 'muted');
  const nextAction = attentionAgent
    ? { label: 'Agent health', title: `${attentionAgent.agent.name} needs attention`, detail: 'Review its latest deployment and run status before the next trigger fires.', href: `/app/agents/${attentionAgent.agent.id}`, cta: 'Review agent' }
    : findingAgent
      ? { label: 'Security finding', title: `${findingAgent.openFindings} open finding${findingAgent.openFindings === 1 ? '' : 's'} from ${findingAgent.agent.name}`, detail: 'Triage the latest agent findings and assign a resolution state.', href: '/app/findings', cta: 'Open security inbox' }
      : setupAgent
        ? { label: 'Finish setup', title: `Put ${setupAgent.agent.name} to work`, detail: 'Complete deployment, then add a webhook or schedule so the agent runs automatically.', href: `/app/agents/${setupAgent.agent.id}`, cta: 'Continue setup' }
        : { label: 'Automation', title: 'Your agents are ready', detail: 'Open an agent to run it now, review activity, or adjust its triggers.', href: agentRows[0] ? `/app/agents/${agentRows[0].agent.id}` : '/app/agents/new', cta: agentRows[0] ? 'Open agent' : 'Create agent' };

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1>AI Agents</h1>
          <p>Deploy focused security agents and keep their work moving.</p>
        </div>
        {atAgentLimit ? (
          <Link href="/app/checkout?plan=pro" className={styles.secondaryButton}>View Pro plan</Link>
        ) : (
          <Link href="/app/agents/new" className={styles.primaryButton}>New agent</Link>
        )}
      </header>

      {agents.length > 0 && (
        <>
          <section className={styles.nextAction}>
            <div>
              <span>{nextAction.label}</span>
              <h2>{nextAction.title}</h2>
              <p>{nextAction.detail}</p>
            </div>
            <Link href={nextAction.href} className={styles.primaryButton}>{nextAction.cta}</Link>
          </section>

          <section className={styles.summary} aria-label="Agent health summary">
            <div><strong>{activeCount}</strong><span>Active</span></div>
            <div><strong className={attentionCount > 0 ? styles.dangerText : ''}>{attentionCount}</strong><span>Need attention</span></div>
            <div><strong className={setupCount > 0 ? styles.warningText : ''}>{setupCount}</strong><span>Need setup</span></div>
            <div><strong className={totalOpenFindings > 0 ? styles.dangerText : ''}>{totalOpenFindings}</strong><span>Open findings</span></div>
          </section>
        </>
      )}

      {agents.length === 0 ? (
        <section className={styles.empty}>
          <div className={styles.emptyIcon}>
            <svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 3 4 7v5c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V7l-8-4Z"/><path d="M9 12h6M12 9v6"/></svg>
          </div>
          <h2>Create a focused security agent</h2>
          <p>Start from a tested template, connect an AI provider, and deploy when you are ready.</p>
          <Link href="/app/agents/new" className={styles.primaryButton}>Choose a template</Link>
        </section>
      ) : (
        <section className={styles.agentList} aria-label="Your AI agents">
          {agentRows.map(({ agent, deployment, run, openFindings, health: agentHealth }) => {
            const tools = (agent.tools as Array<{ name: string }>) ?? [];
            const scoreTone = deployment?.securityScore == null
              ? 'muted'
              : deployment.securityScore >= 80 ? 'success' : deployment.securityScore >= 60 ? 'warning' : 'danger';
            return (
              <article key={agent.id} className={styles.agentRow}>
                <div className={styles.agentMain}>
                  <div className={styles.agentHeading}>
                    <Link href={`/app/agents/${agent.id}`}>{agent.name}</Link>
                    <span className={`${styles.healthBadge} ${styles[`tone_${agentHealth.tone}`]}`}>{agentHealth.label}</span>
                  </div>
                  <p>{agent.description || 'No description added yet.'}</p>
                  <div className={styles.agentMeta}>
                    <span>{tools.length} tool{tools.length === 1 ? '' : 's'}</span>
                    <span>{agent._count.triggers} trigger{agent._count.triggers === 1 ? '' : 's'}</span>
                    <span>{run ? `Last run ${timeAgo(run.startedAt)}` : 'No runs yet'}</span>
                    {run && <span className={`${styles.runStatus} ${styles[`tone_${run.status === 'error' ? 'danger' : run.status === 'running' ? 'progress' : 'success'}`]}`}>{run.status}</span>}
                  </div>
                </div>

                <div className={styles.agentSignals}>
                  {deployment?.securityScore != null && (
                    <div className={`${styles.signal} ${styles[`tone_${scoreTone}`]}`}>
                      <strong>{deployment.securityScore}</strong><span>Security</span>
                    </div>
                  )}
                  <div className={`${styles.signal} ${openFindings > 0 ? styles.tone_danger : ''}`}>
                    <strong>{openFindings}</strong><span>Open</span>
                  </div>
                </div>

                <div className={styles.agentActions}>
                  {agent.status === 'deployed' && deployment?.status === 'running' && (
                    <Link href={`/app/agents/${agent.id}/console`} className={styles.secondaryButton}>Open console</Link>
                  )}
                  <Link href={`/app/agents/${agent.id}`} className={styles.primaryButton}>Manage</Link>
                </div>
              </article>
            );
          })}
        </section>
      )}

      {atAgentLimit && (
        <p className={styles.planNote}>Free includes one agent. Your existing agent remains fully manageable.</p>
      )}
    </div>
  );
}
