/**
 * HTML Report Generator
 * ======================
 *
 * Generates a standalone HTML security report.
 * No external dependencies — everything inline.
 */

import fs from 'fs';
import path from 'path';

export class HTMLReporter {
  /**
   * Generate an HTML report from scan results.
   *
   * @param {object} scoreResult — From ScoringEngine.compute()
   * @param {object[]} findings  — Array of finding objects
   * @param {object} recon       — ReconAgent output
   * @param {string} rootPath    — Project root
   * @returns {string}           — HTML string
   */
  generate(scoreResult, findings, recon, rootPath) {
    const projectName = path.basename(rootPath);
    const date = new Date().toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });

    const gradeColors = { A: '#22c55e', B: '#06b6d4', C: '#eab308', D: '#ef4444', F: '#dc2626' };
    const sevColors = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

    const categoryRows = Object.entries(scoreResult.categories)
      .map(([key, cat]) => {
        const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
        return `<tr>
          <td>${cat.label}</td>
          <td>${count}</td>
          <td style="color:${cat.deduction > 0 ? '#ef4444' : '#22c55e'}">${cat.deduction > 0 ? '-' + cat.deduction : '0'}</td>
        </tr>`;
      }).join('\n');

    const findingRows = findings.slice(0, 200).map(f => {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      return `<tr>
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><code>${relFile}:${f.line}</code></td>
        <td><strong>${f.title || f.rule}</strong><br><small>${f.description?.slice(0, 120) || ''}</small></td>
        <td><code>${(f.matched || '').slice(0, 60)}</code></td>
        <td>${f.fix ? `<small>${f.fix.slice(0, 100)}</small>` : ''}</td>
      </tr>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ship Safe Security Report — ${projectName}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{font-size:2rem;margin-bottom:0.5rem;color:#38bdf8}
h2{font-size:1.3rem;margin:2rem 0 1rem;color:#94a3b8;border-bottom:1px solid #1e293b;padding-bottom:0.5rem}
.meta{color:#64748b;margin-bottom:2rem}
.score-card{display:flex;align-items:center;gap:2rem;background:#1e293b;padding:2rem;border-radius:12px;margin-bottom:2rem}
.score-number{font-size:4rem;font-weight:bold}
.grade{font-size:3rem;font-weight:bold;width:80px;height:80px;display:flex;align-items:center;justify-content:center;border-radius:12px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.stat{background:#1e293b;padding:1.5rem;border-radius:8px;text-align:center}
.stat-number{font-size:2rem;font-weight:bold}
.stat-label{color:#64748b;font-size:0.85rem}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}
td{padding:0.75rem 1rem;border-top:1px solid #1e293b;font-size:0.85rem;vertical-align:top}
tr:hover{background:#334155}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8}
small{color:#64748b}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:bold;text-transform:uppercase}
.sev-critical{background:#dc262633;color:#fca5a5}
.sev-high{background:#f9731633;color:#fdba74}
.sev-medium{background:#eab30833;color:#fde047}
.sev-low{background:#3b82f633;color:#93c5fd}
.footer{text-align:center;color:#475569;margin-top:3rem;padding:2rem;border-top:1px solid #1e293b}
</style>
</head>
<body>
<div class="container">
  <h1>Ship Safe Security Report</h1>
  <p class="meta">${projectName} — ${date}</p>

  <div class="score-card">
    <div class="grade" style="background:${gradeColors[scoreResult.grade.letter]}22;color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.grade.letter}</div>
    <div>
      <div class="score-number" style="color:${gradeColors[scoreResult.grade.letter]}">${scoreResult.score}/100</div>
      <div style="color:#94a3b8">${scoreResult.grade.label}</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-number" style="color:${sevColors.critical}">${bySeverity.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.high}">${bySeverity.high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.medium}">${bySeverity.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-number" style="color:${sevColors.low}">${bySeverity.low}</div><div class="stat-label">Low</div></div>
  </div>

  <h2>Category Breakdown</h2>
  <table>
    <thead><tr><th>Category</th><th>Findings</th><th>Deduction</th></tr></thead>
    <tbody>${categoryRows}</tbody>
  </table>

  <h2>Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Code</th><th>Fix</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="5" style="text-align:center;color:#22c55e">No findings — clean!</td></tr>'}</tbody>
  </table>

  ${recon ? `<h2>Attack Surface</h2>
  <table>
    <tbody>
      <tr><td>Frameworks</td><td>${(recon.frameworks || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Languages</td><td>${(recon.languages || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Databases</td><td>${(recon.databases || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Cloud Providers</td><td>${(recon.cloudProviders || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>Auth Patterns</td><td>${(recon.authPatterns || []).join(', ') || 'None detected'}</td></tr>
      <tr><td>CI/CD</td><td>${(recon.cicd || []).map(c => c.platform).join(', ') || 'None detected'}</td></tr>
      <tr><td>API Routes</td><td>${(recon.apiRoutes || []).length} discovered</td></tr>
    </tbody>
  </table>` : ''}

  <div class="footer">
    Generated by <strong>Ship Safe v4.0</strong> — Security toolkit for developers<br>
    <a href="https://github.com/asamassekou10/ship-safe" style="color:#38bdf8">github.com/asamassekou10/ship-safe</a>
  </div>
</div>
</body>
</html>`;
  }

  /**
   * Generate and write HTML report to file.
   */
  generateToFile(scoreResult, findings, recon, rootPath, outputPath) {
    const html = this.generate(scoreResult, findings, recon, rootPath);
    fs.writeFileSync(outputPath, html);
    return outputPath;
  }
}

export default HTMLReporter;
