import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { scanFindingKey, scanReportFindings } from '@/lib/scan-findings';

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id, userId: session.user.id },
  });

  if (!scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const reportFindings = scanReportFindings(scan.report);
  const findingStates = reportFindings.length > 0
    ? await prisma.scanFindingState.findMany({
        where: { scanId: scan.id, userId: session.user.id },
        select: { findingKey: true, status: true },
      })
    : [];
  const statusByKey = new Map(findingStates.map(state => [state.findingKey, state.status]));

  const report = scan.report && typeof scan.report === 'object' && !Array.isArray(scan.report)
    ? {
        ...scan.report,
        findings: reportFindings.map(finding => {
          const findingKey = scanFindingKey(finding);
          return {
            ...finding,
            findingKey,
            workflowStatus: statusByKey.get(findingKey) ?? 'open',
          };
        }),
      }
    : scan.report;

  return NextResponse.json({ ...scan, report });
}
