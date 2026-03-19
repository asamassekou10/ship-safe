import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

// GET /api/reports?scanId=xxx&format=pdf|json|csv|markdown
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const scanId = url.searchParams.get('scanId');
  const format = url.searchParams.get('format') || 'json';

  if (!scanId) return NextResponse.json({ error: 'scanId required' }, { status: 400 });

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId: session.user.id },
  });

  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  if (scan.status !== 'done' || !scan.report) {
    return NextResponse.json({ error: 'Scan not complete' }, { status: 400 });
  }

  const report = scan.report as Record<string, unknown>;

  if (format === 'json') {
    return NextResponse.json(report);
  }

  if (format === 'csv') {
    const findings = (report.findings || []) as Array<Record<string, unknown>>;
    const headers = ['severity', 'category', 'title', 'file', 'line', 'rule', 'description', 'fix'];
    const rows = findings.map(f => headers.map(h => `"${String(f[h] || '').replace(/"/g, '""')}"`).join(','));
    const csv = [headers.join(','), ...rows].join('\n');

    return new NextResponse(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="ship-safe-${scan.repo.replace(/\//g, '-')}-${scan.id.slice(0, 8)}.csv"`,
      },
    });
  }

  if (format === 'markdown') {
    const findings = (report.findings || []) as Array<Record<string, unknown>>;
    let md = `# Ship Safe Security Report\n\n`;
    md += `**Repository:** ${scan.repo} (${scan.branch})\n`;
    md += `**Score:** ${scan.score}/100 (${scan.grade})\n`;
    md += `**Date:** ${scan.createdAt.toISOString()}\n\n`;
    md += `## Summary\n\n`;
    md += `| Metric | Count |\n|--------|-------|\n`;
    md += `| Findings | ${scan.findings} |\n`;
    md += `| Secrets | ${scan.secrets} |\n`;
    md += `| Code Vulns | ${scan.vulns} |\n`;
    md += `| CVEs | ${scan.cves} |\n\n`;

    if (findings.length > 0) {
      md += `## Findings\n\n`;
      md += `| Severity | Title | File | Category |\n|----------|-------|------|----------|\n`;
      for (const f of findings) {
        md += `| ${f.severity} | ${f.title} | ${f.file}${f.line ? ':' + f.line : ''} | ${f.category} |\n`;
      }
    }

    const remediation = (report.remediationPlan || []) as Array<Record<string, unknown>>;
    if (remediation.length > 0) {
      md += `\n## Remediation Plan\n\n`;
      for (const r of remediation) {
        md += `${r.priority}. **${r.title}** (${r.severity}, ${r.effort} effort)\n   ${r.action}\n\n`;
      }
    }

    return new NextResponse(md, {
      headers: {
        'Content-Type': 'text/markdown',
        'Content-Disposition': `attachment; filename="ship-safe-${scan.repo.replace(/\//g, '-')}.md"`,
      },
    });
  }

  if (format === 'pdf') {
    // Generate HTML report, then return as downloadable HTML
    // Full PDF requires Puppeteer/Playwright (server-side Chrome)
    // For now, generate a self-contained HTML report that can be printed to PDF
    const html = generateHtmlReport(scan, report);
    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html',
        'Content-Disposition': `attachment; filename="ship-safe-${scan.repo.replace(/\//g, '-')}.html"`,
      },
    });
  }

  return NextResponse.json({ error: 'Unsupported format. Use: json, csv, markdown, pdf' }, { status: 400 });
}

function generateHtmlReport(
  scan: { repo: string; branch: string; score: number | null; grade: string | null; findings: number; secrets: number; vulns: number; cves: number; duration: number | null; createdAt: Date },
  report: Record<string, unknown>,
): string {
  const gradeColor = (scan.score ?? 0) >= 80 ? '#4ade80' : (scan.score ?? 0) >= 60 ? '#fbbf24' : '#f87171';
  const findings = (report.findings || []) as Array<Record<string, unknown>>;
  const remediation = (report.remediationPlan || []) as Array<Record<string, unknown>>;

  const sevColor: Record<string, string> = {
    critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#4ade80',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Ship Safe Report — ${scan.repo}</title>
  <style>
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #09090b; color: #fafafa; padding: 40px; max-width: 900px; margin: 0 auto; }
    h1 { font-size: 24px; margin-bottom: 4px; }
    h2 { font-size: 18px; margin: 32px 0 12px; border-bottom: 1px solid #27272a; padding-bottom: 8px; }
    .meta { color: #71717a; font-size: 14px; margin-bottom: 24px; }
    .score-box { display: flex; align-items: center; gap: 16px; padding: 20px; background: #18181b; border: 1px solid #27272a; border-radius: 12px; margin-bottom: 24px; }
    .grade { font-size: 48px; font-weight: 800; font-family: monospace; color: ${gradeColor}; }
    .score-num { font-size: 24px; font-weight: 700; font-family: monospace; color: ${gradeColor}; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat { background: #18181b; border: 1px solid #27272a; border-radius: 10px; padding: 16px; text-align: center; }
    .stat-val { font-size: 28px; font-weight: 800; font-family: monospace; }
    .stat-label { font-size: 12px; color: #71717a; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 10px; background: #18181b; border-bottom: 1px solid #27272a; font-weight: 600; color: #a1a1aa; }
    td { padding: 10px; border-bottom: 1px solid #18181b; }
    .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #27272a; font-size: 12px; color: #71717a; }
  </style>
</head>
<body>
  <h1>🛡️ Ship Safe Security Report</h1>
  <p class="meta">${scan.repo} · ${scan.branch} · ${scan.createdAt.toISOString().split('T')[0]}${scan.duration ? ` · ${scan.duration.toFixed(1)}s` : ''}</p>

  <div class="score-box">
    <span class="grade">${scan.grade ?? '-'}</span>
    <span class="score-num">${scan.score ?? 0}/100</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-val" style="color:${scan.findings > 0 ? '#f87171' : '#4ade80'}">${scan.findings}</div><div class="stat-label">Findings</div></div>
    <div class="stat"><div class="stat-val" style="color:${scan.secrets > 0 ? '#f87171' : '#4ade80'}">${scan.secrets}</div><div class="stat-label">Secrets</div></div>
    <div class="stat"><div class="stat-val" style="color:${scan.vulns > 0 ? '#fbbf24' : '#4ade80'}">${scan.vulns}</div><div class="stat-label">Code Vulns</div></div>
    <div class="stat"><div class="stat-val" style="color:${scan.cves > 0 ? '#fbbf24' : '#4ade80'}">${scan.cves}</div><div class="stat-label">CVEs</div></div>
  </div>

  ${findings.length > 0 ? `
  <h2>Findings (${findings.length})</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>File</th><th>Category</th><th>Rule</th></tr>
    ${findings.map(f => `<tr>
      <td><span class="sev" style="background:${sevColor[String(f.severity)] || '#71717a'}20;color:${sevColor[String(f.severity)] || '#71717a'}">${f.severity}</span></td>
      <td>${f.title}</td>
      <td style="font-family:monospace;font-size:11px;color:#22d3ee">${f.file}${f.line ? ':' + f.line : ''}</td>
      <td>${f.category}</td>
      <td style="font-family:monospace;font-size:11px;color:#71717a">${f.rule}</td>
    </tr>`).join('')}
  </table>` : '<p style="color:#4ade80;margin:20px 0">✅ No security findings detected.</p>'}

  ${remediation.length > 0 ? `
  <h2>Remediation Plan</h2>
  <table>
    <tr><th>#</th><th>Severity</th><th>Title</th><th>Action</th><th>Effort</th></tr>
    ${remediation.map(r => `<tr>
      <td>${r.priority}</td>
      <td><span class="sev" style="background:${sevColor[String(r.severity)] || '#71717a'}20;color:${sevColor[String(r.severity)] || '#71717a'}">${r.severity}</span></td>
      <td>${r.title}</td>
      <td style="font-size:12px;color:#a1a1aa">${r.action}</td>
      <td>${r.effort}</td>
    </tr>`).join('')}
  </table>` : ''}

  <div class="footer">
    Generated by Ship Safe · shipsafe.dev · ${new Date().toISOString()}
  </div>
</body>
</html>`;
}
