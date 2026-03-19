import { prisma } from '@/lib/prisma';
import { appendTimeline, advanceRun } from './pipeline';

type Run = NonNullable<Awaited<ReturnType<typeof prisma.pRGuardianRun.findUnique>>>;

interface Finding {
  file?: string;
  line?: number;
  severity?: string;
  category?: string;
  rule?: string;
  title?: string;
  description?: string;
  confidence?: string;
}

interface Diagnosis {
  findings: Finding[];
  falsePositives: Array<Finding & { reason: string }>;
  realIssues: Finding[];
}

/**
 * Step 2: Diagnose the failure — classify findings as false positives vs real issues.
 * Transitions: diagnosing → fixing | blocked
 */
export async function diagnoseFailure(run: Run) {
  await appendTimeline(run.id, 'Diagnosing', 'Analyzing findings...');

  let findings: Finding[] = [];

  // Get findings from the linked scan report
  if (run.scanId) {
    const scan = await prisma.scan.findUnique({ where: { id: run.scanId }, select: { report: true } });
    if (scan?.report) {
      const report = scan.report as Record<string, unknown>;
      findings = ((report.findings || []) as Finding[]);
    }
  }

  // Also try to parse findings from CI logs if no scan report
  if (findings.length === 0 && run.failureLogs) {
    findings = parseFindingsFromLogs(run.failureLogs);
  }

  // Classify each finding
  const falsePositives: Array<Finding & { reason: string }> = [];
  const realIssues: Finding[] = [];

  for (const finding of findings) {
    const fpReason = detectFalsePositive(finding);
    if (fpReason) {
      falsePositives.push({ ...finding, reason: fpReason });
    } else {
      realIssues.push(finding);
    }
  }

  const diagnosis: Diagnosis = { findings, falsePositives, realIssues };

  // Load guardian config to decide what to do
  const config = await prisma.guardianConfig.findFirst({
    where: { userId: run.userId, repo: { in: [run.repo, '*'] } },
    orderBy: { repo: 'desc' }, // prefer specific repo config over wildcard
  });

  const canFixFP = config?.autoFixFalsePositives !== false;
  const canFixReal = config?.autoFixRealIssues === true;
  const maxAttempts = config?.maxAttempts ?? 3;

  let nextStatus: string;
  let detail: string;

  if (run.failureType !== 'shipsafe') {
    // Non-shipsafe failures — block for human review
    nextStatus = 'blocked';
    detail = `${run.failureType} failure requires manual intervention`;
  } else if (falsePositives.length > 0 && canFixFP) {
    nextStatus = 'fixing';
    detail = `${falsePositives.length} false positive(s) to suppress, ${realIssues.length} real issue(s)`;
  } else if (realIssues.length > 0 && canFixReal) {
    nextStatus = 'fixing';
    detail = `${realIssues.length} real issue(s) to auto-fix`;
  } else if (realIssues.length > 0) {
    nextStatus = 'blocked';
    detail = `${realIssues.length} real issue(s) require manual review`;
  } else if (run.attempts >= maxAttempts) {
    nextStatus = 'failed';
    detail = `Max attempts (${maxAttempts}) reached`;
  } else {
    // No findings but CI still failing — might be flaky
    nextStatus = 'blocked';
    detail = 'CI failing but no actionable findings found';
  }

  await appendTimeline(run.id, 'Diagnosis complete', detail);

  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: { status: nextStatus, diagnosis },
  });

  if (nextStatus === 'fixing') {
    advanceRun(run.id).catch(console.error);
  }
}

// ── False Positive Detection ────────────────────────────────

const EXAMPLE_FILE_PATTERNS = [
  /\.env\.example$/i,
  /\.env\.sample$/i,
  /\.env\.template$/i,
  /\.env\.test$/i,
];

const EXAMPLE_DIR_PATTERNS = [
  /^test\//i,
  /__tests__\//i,
  /^spec\//i,
  /fixtures\//i,
  /__mocks__\//i,
  /examples?\//i,
  /docs?\//i,
];

const PLACEHOLDER_VALUES = [
  'your-', 'xxx', 'placeholder', 'changeme', 'example.com',
  'todo', 'fixme', 'replace-', 'sk_test_', 'pk_test_',
  'user:password@localhost', 'password@localhost',
];

function detectFalsePositive(finding: Finding): string | null {
  const file = finding.file || '';
  const title = (finding.title || '').toLowerCase();
  const desc = (finding.description || '').toLowerCase();
  const combined = `${title} ${desc} ${finding.rule || ''}`.toLowerCase();

  // 1. Example/template files
  for (const pattern of EXAMPLE_FILE_PATTERNS) {
    if (pattern.test(file)) {
      return `File is a template/example (${file})`;
    }
  }

  // 2. Test/fixture directories
  for (const pattern of EXAMPLE_DIR_PATTERNS) {
    if (pattern.test(file)) {
      return `File is in a test/example directory`;
    }
  }

  // 3. Placeholder values in the finding
  for (const placeholder of PLACEHOLDER_VALUES) {
    if (combined.includes(placeholder)) {
      return `Contains placeholder value "${placeholder}"`;
    }
  }

  // 4. Low confidence findings
  if (finding.confidence === 'low') {
    return 'Low confidence finding';
  }

  // 5. Finding is in a string that looks like documentation/example code
  if (file.endsWith('.md') || file.endsWith('.txt') || file.endsWith('.rst')) {
    return 'Finding is in documentation';
  }

  return null;
}

// ── Parse findings from CI logs ─────────────────────────────

function parseFindingsFromLogs(logs: string): Finding[] {
  const findings: Finding[] = [];
  const lines = logs.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match ship-safe output format: "file.ts:123"
    const fileMatch = line.match(/^(\S+\.\w+):(\d+)$/);
    if (fileMatch) {
      // Next line usually has severity and title
      const nextLine = lines[i + 1] || '';
      const severityMatch = nextLine.match(/\[(CRITICAL|HIGH|MEDIUM|LOW)]\s*(.+)/i);
      if (severityMatch) {
        findings.push({
          file: fileMatch[1],
          line: parseInt(fileMatch[2], 10),
          severity: severityMatch[1].toLowerCase(),
          title: severityMatch[2].trim(),
        });
      }
    }
  }

  return findings;
}
