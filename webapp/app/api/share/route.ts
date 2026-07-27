import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { CANONICAL_URL } from '@/lib/site';

const MAX_REPORT_BYTES = 512 * 1024; // 512 KB

export async function POST(req: NextRequest) {
  const body = await req.text();
  if (body.length > MAX_REPORT_BYTES) {
    return NextResponse.json({ error: 'Report too large' }, { status: 413 });
  }

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(body);
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const shared = await prisma.sharedReport.create({
    data: {
      score:    typeof data.score === 'number' ? data.score : null,
      grade:    typeof data.grade === 'string' ? data.grade : null,
      repo:     typeof data.repo  === 'string' ? data.repo.slice(0, 200) : null,
      findings: typeof data.findings === 'number' ? data.findings : 0,
      report:   data.report as object ?? data,
      expiresAt,
    },
  });

  const url = `${process.env.NEXT_PUBLIC_APP_URL ?? CANONICAL_URL}/share/${shared.token}`;
  return NextResponse.json({ url, token: shared.token, expiresAt });
}
