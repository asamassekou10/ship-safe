import { createHash } from 'node:crypto';

export interface ScanReportFinding {
  severity?: unknown;
  title?: unknown;
  file?: unknown;
  line?: unknown;
  fix?: unknown;
  description?: unknown;
  cve?: unknown;
  cwe?: unknown;
  rule?: unknown;
  category?: unknown;
}

export function scanReportFindings(report: unknown): ScanReportFinding[] {
  if (!report || typeof report !== 'object' || !('findings' in report)) return [];
  const findings = (report as { findings?: unknown }).findings;
  return Array.isArray(findings) ? findings as ScanReportFinding[] : [];
}

export function scanFindingKey(finding: ScanReportFinding): string {
  return createHash('sha256')
    .update(JSON.stringify([
      finding.severity ?? '',
      finding.title ?? '',
      finding.file ?? '',
      finding.line ?? '',
      finding.rule ?? '',
      finding.category ?? '',
    ]))
    .digest('hex')
    .slice(0, 24);
}
