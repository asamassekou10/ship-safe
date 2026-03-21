import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join, basename } from 'path';

const execAsync = promisify(exec);
const FREE_MONTHLY_LIMIT = 5;
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = session.user.id;
  const plan = (session.user as Record<string, unknown>).plan as string;

  // Enforce free plan limits
  if (plan === 'free') {
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const count = await prisma.scan.count({
      where: { userId, createdAt: { gte: monthStart } },
    });
    if (count >= FREE_MONTHLY_LIMIT) {
      return NextResponse.json(
        { error: 'Free plan limit reached (5 scans/month). Upgrade to Pro for unlimited scans.' },
        { status: 429 },
      );
    }
  }

  const formData = await req.formData();
  const file = formData.get('file') as File | null;
  const optionsRaw = formData.get('options') as string | null;

  if (!file || !file.name.endsWith('.zip')) {
    return NextResponse.json({ error: 'A .zip file is required' }, { status: 400 });
  }

  if (file.size > MAX_FILE_SIZE) {
    return NextResponse.json({ error: 'File too large. Max 50MB.' }, { status: 400 });
  }

  let options: Record<string, boolean> = {};
  if (optionsRaw) {
    try { options = JSON.parse(optionsRaw); } catch { /* ignore */ }
  }

  const scan = await prisma.scan.create({
    data: {
      userId,
      repo: file.name.replace(/\.zip$/, ''),
      branch: '-',
      method: 'upload',
      status: 'running',
      options,
    },
  });

  // Read file buffer and run scan in background
  const buffer = Buffer.from(await file.arrayBuffer());
  runUploadScan(scan.id, buffer, file.name, options).catch(console.error);

  return NextResponse.json({ id: scan.id, status: 'running' });
}

async function runUploadScan(
  scanId: string,
  buffer: Buffer,
  filename: string,
  options: Record<string, boolean>,
) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-upload-'));
  const startTime = Date.now();

  try {
    // Write ZIP to temp dir — use basename to prevent path traversal
    const zipPath = join(tmpDir, basename(filename));
    await writeFile(zipPath, buffer);

    // Extract ZIP
    const extractDir = join(tmpDir, 'repo');
    await execAsync(`unzip -q -o "${zipPath}" -d "${extractDir}"`, { timeout: 30_000 });

    // Build CLI command
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    if (options.noAi) flags.push('--no-ai');

    const { stdout } = await execAsync(
      `npx ship-safe audit "${extractDir}" ${flags.join(' ')}`,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
    );

    const duration = (Date.now() - startTime) / 1000;
    let report: Record<string, unknown> = {};
    try { report = JSON.parse(stdout); } catch { report = { raw: stdout }; }

    const score = typeof report.score === 'number' ? report.score : null;
    const grade = typeof report.grade === 'string' ? report.grade : null;
    const findings = typeof report.totalFindings === 'number' ? report.totalFindings : 0;
    const secrets = typeof report.secrets === 'number' ? report.secrets : 0;
    const vulns = typeof report.vulns === 'number' ? report.vulns : 0;
    const cves = typeof report.cves === 'number' ? report.cves : 0;

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'done', score, grade, findings, secrets, vulns, cves, duration, report: report as Prisma.InputJsonValue },
    });
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000;
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'failed',
        duration,
        report: { error: err instanceof Error ? err.message : String(err) },
      },
    });
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
