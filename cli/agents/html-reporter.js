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
    Generated by <strong>Ship Safe v4.3</strong> — Security toolkit for developers<br>
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

  /**
   * Generate a full audit report including deps and remediation plan.
   */
  generateFullReport(scoreResult, findings, depVulns, recon, remediationPlan, rootPath, outputPath) {
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
      let codeBlock = '';
      if (f.codeContext && f.codeContext.length > 0) {
        const codeLines = f.codeContext.map(c =>
          `<span style="${c.highlight ? 'background:#dc262633;display:block;' : ''}">${String(c.line).padStart(4)} ${this.esc(c.text)}</span>`
        ).join('');
        codeBlock = `<pre style="background:#0f172a;padding:0.5rem;border-radius:4px;font-size:0.75rem;margin-top:0.5rem;overflow-x:auto;line-height:1.4"><code>${codeLines}</code></pre>`;
      }
      return `<tr>
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><code>${relFile}:${f.line}</code></td>
        <td><strong>${this.esc(f.title || f.rule)}</strong><br><small>${this.esc((f.description || '').slice(0, 120))}</small>${codeBlock}</td>
        <td><code>${this.esc((f.matched || '').slice(0, 60))}</code></td>
        <td>${f.fix ? `<small>${this.esc(f.fix.slice(0, 100))}</small>` : ''}</td>
      </tr>`;
    }).join('\n');

    // Dep vuln rows
    const depRows = (depVulns || []).slice(0, 100).map(d => {
      const sev = d.severity === 'moderate' ? 'medium' : d.severity;
      return `<tr>
        <td><span class="sev sev-${sev}">${(d.severity || 'unknown').toUpperCase()}</span></td>
        <td><code>${this.esc(d.package || d.id || 'unknown')}</code></td>
        <td>${this.esc((d.description || '').slice(0, 150))}</td>
      </tr>`;
    }).join('\n');

    // Remediation plan rows
    const sevIcons = { critical: '&#x1F534;', high: '&#x1F7E0;', medium: '&#x1F7E1;', low: '&#x1F535;' };
    let currentSev = null;
    let planHTML = '';
    for (const item of (remediationPlan || []).slice(0, 100)) {
      if (item.severity !== currentSev) {
        currentSev = item.severity;
        const label = { critical: 'CRITICAL — fix immediately', high: 'HIGH — fix before deploy', medium: 'MEDIUM — fix soon', low: 'LOW — review when possible' };
        planHTML += `<tr class="sev-header"><td colspan="5" style="background:#1e293b;padding:1rem;font-weight:bold;color:${sevColors[currentSev] || '#94a3b8'}">${sevIcons[currentSev] || ''} ${label[currentSev] || currentSev.toUpperCase()}</td></tr>\n`;
      }
      planHTML += `<tr>
        <td>${item.priority}</td>
        <td><span class="sev sev-${item.severity}">${item.categoryLabel}</span></td>
        <td><strong>${this.esc(item.title)}</strong></td>
        <td><code>${this.esc(item.file)}</code></td>
        <td><small>${this.esc((item.action || '').slice(0, 120))}</small></td>
      </tr>\n`;
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ship Safe Full Audit Report — ${this.esc(projectName)}</title>
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
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
.summary-card{background:#1e293b;padding:1.5rem;border-radius:8px}
.summary-card h3{color:#38bdf8;font-size:1rem;margin-bottom:0.5rem}
.summary-card .big{font-size:2.5rem;font-weight:bold}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}
td{padding:0.75rem 1rem;border-top:1px solid #0f172a;font-size:0.85rem;vertical-align:top}
tr:hover{background:#334155}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8}
small{color:#94a3b8}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:bold;text-transform:uppercase}
.sev-critical{background:#dc262633;color:#fca5a5}
.sev-high{background:#f9731633;color:#fdba74}
.sev-medium,.sev-moderate{background:#eab30833;color:#fde047}
.sev-low{background:#3b82f633;color:#93c5fd}
.toc{background:#1e293b;padding:1.5rem 2rem;border-radius:8px;margin-bottom:2rem}
.toc a{color:#38bdf8;text-decoration:none;display:block;padding:0.3rem 0}
.toc a:hover{text-decoration:underline}
.footer{text-align:center;color:#475569;margin-top:3rem;padding:2rem;border-top:1px solid #1e293b}
.footer a{color:#38bdf8}
@media print{body{background:#fff;color:#1e293b}table,th,td{border:1px solid #e2e8f0}.score-card,.stat,.summary-card,.toc{background:#f8fafc}}
</style>
</head>
<body>
<div class="container">
  <h1>Ship Safe — Full Security Audit Report</h1>
  <p class="meta">${this.esc(projectName)} — ${date}</p>

  <div class="toc">
    <strong>Contents</strong>
    <a href="#score">1. Security Score</a>
    <a href="#summary">2. Executive Summary</a>
    <a href="#categories">3. Category Breakdown</a>
    <a href="#plan">4. Remediation Plan (${(remediationPlan || []).length} items)</a>
    <a href="#findings">5. All Findings (${findings.length})</a>
    <a href="#deps">6. Dependency Vulnerabilities (${(depVulns || []).length})</a>
    <a href="#surface">7. Attack Surface</a>
  </div>

  <h2 id="score">1. Security Score</h2>
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

  <h2 id="summary">2. Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <h3>Code Findings</h3>
      <div class="big" style="color:${findings.length > 0 ? '#ef4444' : '#22c55e'}">${findings.length}</div>
      <small>Across ${Object.keys(scoreResult.categories).length} categories</small>
    </div>
    <div class="summary-card">
      <h3>Dependency CVEs</h3>
      <div class="big" style="color:${(depVulns || []).length > 0 ? '#ef4444' : '#22c55e'}">${(depVulns || []).length}</div>
      <small>From npm/pip/bundler audit</small>
    </div>
  </div>

  <h2 id="categories">3. Category Breakdown</h2>
  <table>
    <thead><tr><th>Category</th><th>Findings</th><th>Score Deduction</th></tr></thead>
    <tbody>${categoryRows}</tbody>
  </table>

  <h2 id="plan">4. Remediation Plan</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Prioritized list of fixes. Address critical items first.</p>
  ${(remediationPlan || []).length > 0 ? `<table>
    <thead><tr><th>#</th><th>Category</th><th>Issue</th><th>Location</th><th>Fix</th></tr></thead>
    <tbody>${planHTML}</tbody>
  </table>` : '<p style="color:#22c55e;font-weight:bold">No issues found — all clear!</p>'}

  <h2 id="findings">5. All Findings (${findings.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Code</th><th>Fix</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="5" style="text-align:center;color:#22c55e">No findings — clean!</td></tr>'}</tbody>
  </table>

  <h2 id="deps">6. Dependency Vulnerabilities (${(depVulns || []).length})</h2>
  ${(depVulns || []).length > 0 ? `<table>
    <thead><tr><th>Severity</th><th>Package</th><th>Description</th></tr></thead>
    <tbody>${depRows}</tbody>
  </table>` : '<p style="color:#22c55e;font-weight:bold">No vulnerable dependencies found.</p>'}

  ${recon ? `<h2 id="surface">7. Attack Surface</h2>
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
    Generated by <strong>Ship Safe v4.3</strong> — Full Security Audit<br>
    <a href="https://github.com/asamassekou10/ship-safe">github.com/asamassekou10/ship-safe</a>
  </div>
</div>
</body>
</html>`;

    fs.writeFileSync(outputPath, html);
    return outputPath;
  }

  /** Escape HTML entities */
  esc(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

export default HTMLReporter;
