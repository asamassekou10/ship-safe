import { NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { isAdmin } from '@/lib/is-admin';
import { reengageEligibleCount, sendReengagementBatch } from '@/lib/lifecycle-emails';

// This route is not under a middleware-protected prefix, so it enforces
// auth + admin itself. It sends real marketing email — admin only, batched.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const MAX_BATCH = 50;

async function requireAdmin() {
  const session = await auth();
  if (!session?.user?.id) return { error: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) };
  if (!isAdmin(session.user.email)) return { error: NextResponse.json({ error: 'Forbidden' }, { status: 403 }) };
  return { error: null };
}

export async function GET() {
  const { error } = await requireAdmin();
  if (error) return error;
  return NextResponse.json({ eligible: await reengageEligibleCount() });
}

export async function POST(req: Request) {
  const { error } = await requireAdmin();
  if (error) return error;

  let limit = 20;
  try {
    const body = await req.json();
    if (typeof body?.limit === 'number' && Number.isFinite(body.limit)) {
      limit = Math.min(Math.max(Math.trunc(body.limit), 1), MAX_BATCH);
    }
  } catch {
    // no body → default limit
  }

  const result = await sendReengagementBatch(limit);
  const eligible = await reengageEligibleCount();
  return NextResponse.json({ ...result, eligible });
}
