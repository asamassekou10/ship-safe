import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { advanceRun, appendTimeline } from '@/lib/guardian/pipeline';

/**
 * POST /api/guardian/resume — Internal endpoint called by the webhook handler
 * to advance a Guardian pipeline after a check_suite event.
 *
 * Body: { runId, conclusion: "success" | "failure" }
 *
 * This is NOT user-facing — it's called internally by the webhook route.
 */
export async function POST(req: NextRequest) {
  // Simple secret check to prevent external calls
  const internalSecret = req.headers.get('x-guardian-secret');
  if (internalSecret !== (process.env.GITHUB_APP_WEBHOOK_SECRET || 'guardian-internal')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  const { runId, conclusion } = await req.json();
  if (!runId) return NextResponse.json({ error: 'runId required' }, { status: 400 });

  const run = await prisma.pRGuardianRun.findUnique({ where: { id: runId } });
  if (!run || run.status !== 'verifying') {
    return NextResponse.json({ error: 'Run not in verifying state' }, { status: 400 });
  }

  await appendTimeline(runId, 'CI completed', `Conclusion: ${conclusion}`);
  await prisma.pRGuardianRun.update({
    where: { id: runId },
    data: { ciStatus: conclusion },
  });

  advanceRun(runId).catch(console.error);

  return NextResponse.json({ ok: true });
}
