import { NextRequest, NextResponse } from 'next/server';
import { sendTest } from '@/lib/lifecycle-emails';
import type { LifecycleType } from '@/lib/lifecycle-emails';

/**
 * POST /api/dev/test-email
 * Body: { "to": "you@example.com", "type": "welcome" }
 * Header: Authorization: Bearer <CRON_SECRET>
 *
 * Sends one lifecycle template to an arbitrary address for deliverability
 * testing. Protected by CRON_SECRET. Safe to delete once the flow is verified.
 */
const VALID: LifecycleType[] = ['welcome', 'day3_checkin', 'day3_outreach', 'reengage'];

export async function POST(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json({ error: 'CRON_SECRET not set' }, { status: 500 });
  }
  if ((req.headers.get('authorization') ?? '') !== `Bearer ${secret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await req.json().catch(() => ({}));
  const to = typeof body.to === 'string' ? body.to : '';
  const type = body.type as LifecycleType;

  if (!to || !VALID.includes(type)) {
    return NextResponse.json(
      { error: `Provide { to, type }; type must be one of: ${VALID.join(', ')}` },
      { status: 400 },
    );
  }

  const ok = await sendTest(to, type);
  return NextResponse.json({ ok, to, type }, { status: ok ? 200 : 502 });
}
