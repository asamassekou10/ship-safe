import { NextRequest, NextResponse } from 'next/server';
import { sendReengagementBatch, reengageEligibleCount } from '@/lib/lifecycle-emails';

/**
 * POST /api/dev/reengage
 * Header: Authorization: Bearer <CRON_SECRET>
 * Body:   { "dryRun": true }            → count eligible users, send nothing
 *         { "limit": 10 }               → send one batch (default 10, max 50)
 *
 * One-time re-engagement to the existing signup backlog. Idempotent: users
 * already sent a 'reengage' email are skipped (EmailEvent unique constraint),
 * so re-running just continues where it left off. Batched for deliverability.
 */
export async function POST(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json({ error: 'CRON_SECRET not set' }, { status: 500 });
  }
  if ((req.headers.get('authorization') ?? '') !== `Bearer ${secret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));

  try {
    if (body.dryRun === true) {
      const eligible = await reengageEligibleCount();
      return NextResponse.json({ dryRun: true, eligible });
    }

    const limit = typeof body.limit === 'number' && body.limit > 0 ? Math.min(body.limit, 50) : 10;
    const result = await sendReengagementBatch(limit);
    const remaining = await reengageEligibleCount();
    return NextResponse.json({ ...result, remaining, limit });
  } catch (err) {
    // Surfaces "table does not exist" if the migration hasn't been applied yet.
    return NextResponse.json({ error: err instanceof Error ? err.message : String(err) }, { status: 500 });
  }
}
