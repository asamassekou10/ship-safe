import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { scanFindingKey, scanReportFindings } from '@/lib/scan-findings';

const VALID_STATUSES = ['open', 'acknowledged', 'fixed', 'false_positive'];
const FINDING_KEY_PATTERN = /^[a-f0-9]{24}$/;

/** PATCH /api/findings/scan-state — persist triage state for a scan report finding. */
export async function PATCH(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json().catch(() => null) as {
    scanId?: unknown;
    findingKey?: unknown;
    status?: unknown;
  } | null;
  const scanId = typeof body?.scanId === 'string' ? body.scanId : '';
  const findingKey = typeof body?.findingKey === 'string' ? body.findingKey : '';
  const status = typeof body?.status === 'string' ? body.status : '';

  if (!scanId || !FINDING_KEY_PATTERN.test(findingKey) || !VALID_STATUSES.includes(status)) {
    return NextResponse.json({ error: 'Invalid scan finding state' }, { status: 400 });
  }

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId: session.user.id },
    select: { id: true, report: true },
  });
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  const findingExists = scanReportFindings(scan.report).some(finding => scanFindingKey(finding) === findingKey);
  if (!findingExists) return NextResponse.json({ error: 'Finding not found in scan report' }, { status: 404 });

  const state = await prisma.scanFindingState.upsert({
    where: { scanId_findingKey: { scanId, findingKey } },
    create: { scanId, findingKey, status, userId: session.user.id },
    update: { status },
  });

  return NextResponse.json({ state });
}
