import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { fireAgentRun } from '@/lib/fire-agent-run';
import { Cron } from 'croner';

/**
 * GET /api/cron
 *
 * Called every minute by Vercel Cron. Finds all enabled cron triggers
 * whose expression matches the current minute and fires them.
 *
 * Protected by CRON_SECRET (set in Vercel env vars).
 */
export async function GET(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (secret) {
    const auth = req.headers.get('authorization') ?? '';
    if (auth !== `Bearer ${secret}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
  }

  const now = new Date();

  // Fetch all enabled cron triggers with a running deployment
  const triggers = await prisma.trigger.findMany({
    where: { type: 'cron', enabled: true, cronExpr: { not: null } },
    include: {
      agent: {
        include: {
          deployments: {
            where:   { status: 'running' },
            orderBy: { createdAt: 'desc' },
            take: 1,
          },
        },
      },
    },
  });

  const fired: string[] = [];

  for (const trigger of triggers) {
    const deployment = trigger.agent.deployments[0];
    if (!deployment?.port || !trigger.cronExpr) continue;

    // Check if this trigger should fire right now.
    // croner's .nextRun(fromDate) gives the next scheduled time after `fromDate`.
    // We consider a trigger due if its last run was > 1 minute ago and the
    // next scheduled time falls within the current minute window.
    let isDue = false;
    try {
      const job = new Cron(trigger.cronExpr, { timezone: 'UTC' });
      // Next run from 1 minute ago
      const windowStart = new Date(now.getTime() - 60_000);
      const next = job.nextRun(windowStart);
      isDue = next !== null && next <= now;
    } catch {
      continue; // invalid cron expr — skip
    }

    if (!isDue) continue;

    // Build message
    const message = trigger.promptTpl.replace(
      '{payload}',
      `Scheduled run at ${now.toISOString()}`
    );

    const run = await prisma.agentRun.create({
      data: { deploymentId: deployment.id, triggerId: trigger.id, status: 'running' },
    });

    await prisma.chatMessage.create({
      data: { runId: run.id, role: 'user', content: message },
    });

    await prisma.trigger.update({
      where: { id: trigger.id },
      data:  { lastFiredAt: now },
    });

    // Fire in background
    fireAgentRun({
      runId:          run.id,
      deploymentPort: deployment.port,
      message,
    }).catch(() => {});

    fired.push(trigger.id);
  }

  return NextResponse.json({ fired, count: fired.length, at: now.toISOString() });
}
