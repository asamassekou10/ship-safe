/**
 * HTML Report Generator
 * ======================
 *
 * Generates a standalone interactive HTML security report.
 * No external dependencies — everything inline.
 *
 * Features:
 *   - Severity filter toolbar (toggle critical/high/medium/low)
 *   - Category bar chart (deductions visualization)
 *   - Collapsible finding rows with code context
 *   - Click-to-copy ship-safe-ignore annotations
 *   - Text search across findings
 *   - Print-friendly styles
 */

import fs from 'fs';
import path from 'path';
import { getComplianceSummary } from '../utils/compliance-map.js';

export class HTMLReporter {
  /**
   * Generate an HTML report from scan results.
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

  <h2>Compliance Mapping</h2>
  ${(() => {
    const compliance = getComplianceSummary(findings);
    const s = compliance.summary;
    return `<div class="stats">
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.soc2Controls}</div><div class="stat-label">SOC 2 Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.iso27001Controls}</div><div class="stat-label">ISO 27001 Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#38bdf8">${s.nistAiRmfControls}</div><div class="stat-label">NIST AI RMF Controls</div></div>
      <div class="stat"><div class="stat-number" style="color:#94a3b8">${s.totalFindings}</div><div class="stat-label">Mapped Findings</div></div>
    </div>
    <table>
      <thead><tr><th>Framework</th><th>Controls Impacted</th><th>Details</th></tr></thead>
      <tbody>
        <tr><td>SOC 2 Type II</td><td>${s.soc2Controls}</td><td>${Object.entries(compliance.soc2).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
        <tr><td>ISO 27001:2022</td><td>${s.iso27001Controls}</td><td>${Object.entries(compliance.iso27001).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
        <tr><td>NIST AI RMF</td><td>${s.nistAiRmfControls}</td><td>${Object.entries(compliance.nistAiRmf).map(([k,v]) => k + ' (' + v + ')').join(', ') || 'None'}</td></tr>
      </tbody>
    </table>`;
  })()}

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

  <div style="text-align:center;margin:1.5rem 0">
    <a href="https://twitter.com/intent/tweet?text=${encodeURIComponent(`My project scored ${scoreResult.score}/100 (Grade ${scoreResult.grade.letter}) on Ship Safe! Scan yours: npx ship-safe audit . https://shipsafecli.com`)}" target="_blank" rel="noopener" style="display:inline-block;padding:8px 18px;background:#000;color:#fff;border-radius:6px;font-size:0.85rem;font-weight:600;text-decoration:none;margin:0 4px">Share on X</a>
    <a href="https://www.linkedin.com/sharing/share-offsite/?url=https://shipsafecli.com" target="_blank" rel="noopener" style="display:inline-block;padding:8px 18px;background:#0a66c2;color:#fff;border-radius:6px;font-size:0.85rem;font-weight:600;text-decoration:none;margin:0 4px">Share on LinkedIn</a>
  </div>

  <div class="footer">
    Generated by <strong>Ship Safe v6.1</strong> — Security toolkit for developers<br>
    <a href="https://shipsafecli.com" style="color:#38bdf8">shipsafecli.com</a> &middot; <a href="https://shipsafecli.com/pricing" style="color:#38bdf8">Cloud Dashboard</a>
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
   * Generate a full interactive audit report including deps and remediation plan.
   *
   * Interactive features:
   *   - Severity filter toolbar
   *   - Category deduction bar chart
   *   - Collapsible finding rows with code context
   *   - Click-to-copy ship-safe-ignore annotations
   *   - Text search across findings
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

    // Category chart data
    const catEntries = Object.entries(scoreResult.categories);
    const maxDeduction = Math.max(...catEntries.map(([, c]) => c.deduction), 1);
    const categoryBars = catEntries.map(([key, cat]) => {
      const count = Object.values(cat.counts).reduce((a, b) => a + b, 0);
      const pct = Math.round((cat.deduction / maxDeduction) * 100);
      const color = cat.deduction > 5 ? '#ef4444' : cat.deduction > 0 ? '#f97316' : '#22c55e';
      return `<div class="bar-row">
        <span class="bar-label">${this.esc(cat.label)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="bar-value" style="color:${color}">${cat.deduction > 0 ? '-' + Math.round(cat.deduction * 10) / 10 : '0'} pts</span>
        <span class="bar-count">${count} findings</span>
      </div>`;
    }).join('\n');

    // Finding rows with collapsible detail
    const findingRows = findings.slice(0, 500).map((f, i) => {
      const relFile = path.relative(rootPath, f.file).replace(/\\/g, '/');
      let codeBlock = '';
      if (f.codeContext && f.codeContext.length > 0) {
        const codeLines = f.codeContext.map(c =>
          `<span style="${c.highlight ? 'background:#dc262633;display:block;' : ''}">${String(c.line).padStart(4)} ${this.esc(c.text)}</span>`
        ).join('');
        codeBlock = `<pre class="code-block"><code>${codeLines}</code></pre>`;
      }
      const ignoreAnnotation = `ship-safe-ignore ${f.rule || ''}`.trim();
      return `<tr class="finding-row" data-sev="${f.severity}" data-rule="${this.esc(f.rule || '')}" data-text="${this.esc((f.title || '') + ' ' + (f.description || '') + ' ' + relFile).toLowerCase()}">
        <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><code>${this.esc(relFile)}:${f.line}</code></td>
        <td>
          <strong class="finding-title" onclick="toggleDetail(${i})">${this.esc(f.title || f.rule)}</strong>
          <div id="detail-${i}" class="finding-detail" style="display:none">
            <p>${this.esc((f.description || '').slice(0, 300))}</p>
            ${f.cwe ? `<p class="finding-meta">CWE: ${this.esc(f.cwe)}${f.owasp ? ` | OWASP: ${this.esc(f.owasp)}` : ''}</p>` : ''}
            ${codeBlock}
            ${f.fix ? `<p class="finding-fix">Fix: ${this.esc(f.fix.slice(0, 200))}</p>` : ''}
            <button class="copy-btn" onclick="copyIgnore('${this.esc(ignoreAnnotation)}',this);event.stopPropagation()">Copy ignore annotation</button>
          </div>
        </td>
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
        <td><span class="sev sev-${item.severity}">${this.esc(item.categoryLabel)}</span></td>
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
.stat{background:#1e293b;padding:1.5rem;border-radius:8px;text-align:center;cursor:pointer;transition:transform .15s,box-shadow .15s}
.stat:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.3)}
.stat.active{outline:2px solid #38bdf8}
.stat-number{font-size:2rem;font-weight:bold}
.stat-label{color:#64748b;font-size:0.85rem}
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
.summary-card{background:#1e293b;padding:1.5rem;border-radius:8px}
.summary-card h3{color:#38bdf8;font-size:1rem;margin-bottom:0.5rem}
.summary-card .big{font-size:2.5rem;font-weight:bold}
/* Bar chart */
.chart{background:#1e293b;border-radius:8px;padding:1.5rem;margin-bottom:2rem}
.bar-row{display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0}
.bar-label{width:160px;font-size:0.8rem;color:#94a3b8;text-align:right;flex-shrink:0}
.bar-track{flex:1;height:20px;background:#0f172a;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .4s ease}
.bar-value{width:70px;font-size:0.8rem;font-weight:bold;flex-shrink:0}
.bar-count{width:80px;font-size:0.75rem;color:#64748b;flex-shrink:0}
/* Filter bar */
.filter-bar{display:flex;align-items:center;gap:1rem;background:#1e293b;padding:1rem 1.5rem;border-radius:8px;margin-bottom:1rem;flex-wrap:wrap}
.filter-bar label{font-size:0.8rem;color:#94a3b8}
.filter-btn{padding:4px 12px;border-radius:4px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;cursor:pointer;font-size:0.8rem;transition:background .15s}
.filter-btn.active{border-color:#38bdf8;background:#38bdf822}
.filter-btn:hover{background:#334155}
.search-input{background:#0f172a;border:1px solid #334155;border-radius:4px;padding:6px 12px;color:#e2e8f0;font-size:0.8rem;width:200px}
.search-input:focus{outline:none;border-color:#38bdf8}
.filter-bar .count-label{margin-left:auto;font-size:0.8rem;color:#64748b}
/* Table */
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.8rem;text-transform:uppercase;color:#94a3b8;cursor:pointer;user-select:none}
th:hover{color:#e2e8f0}
td{padding:0.75rem 1rem;border-top:1px solid #0f172a;font-size:0.85rem;vertical-align:top}
tr:hover{background:#334155}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8;word-break:break-all}
small{color:#94a3b8}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:bold;text-transform:uppercase;white-space:nowrap}
.sev-critical{background:#dc262633;color:#fca5a5}
.sev-high{background:#f9731633;color:#fdba74}
.sev-medium,.sev-moderate{background:#eab30833;color:#fde047}
.sev-low{background:#3b82f633;color:#93c5fd}
/* Collapsible findings */
.finding-title{cursor:pointer;border-bottom:1px dashed #475569}
.finding-title:hover{color:#38bdf8}
.finding-detail{margin-top:0.5rem;padding:0.75rem;background:#0f172a;border-radius:6px;border-left:3px solid #38bdf8}
.finding-detail p{font-size:0.8rem;color:#94a3b8;margin-bottom:0.4rem}
.finding-meta{font-size:0.75rem;color:#64748b}
.finding-fix{color:#22c55e;font-size:0.8rem}
.code-block{background:#020617;padding:0.5rem;border-radius:4px;font-size:0.75rem;margin:0.5rem 0;overflow-x:auto;line-height:1.4}
.copy-btn{background:#334155;color:#38bdf8;border:1px solid #475569;border-radius:4px;padding:3px 10px;font-size:0.7rem;cursor:pointer;margin-top:0.4rem}
.copy-btn:hover{background:#475569}
.copy-btn.copied{background:#22c55e33;color:#22c55e;border-color:#22c55e}
/* TOC */
.toc{background:#1e293b;padding:1.5rem 2rem;border-radius:8px;margin-bottom:2rem}
.toc a{color:#38bdf8;text-decoration:none;display:block;padding:0.3rem 0}
.toc a:hover{text-decoration:underline}
.footer{text-align:center;color:#475569;margin-top:3rem;padding:2rem;border-top:1px solid #1e293b}
.footer a{color:#38bdf8}
.share-bar{display:flex;justify-content:center;gap:0.75rem;margin:1.5rem 0}
.share-btn{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;border-radius:6px;font-size:0.85rem;font-weight:600;text-decoration:none;cursor:pointer;border:none;transition:opacity .15s}
.share-btn:hover{opacity:0.85}
.share-btn-x{background:#000;color:#fff}
.share-btn-li{background:#0a66c2;color:#fff}
.share-btn-copy{background:#334155;color:#38bdf8;border:1px solid #475569}
.share-btn-copy.copied{background:#22c55e33;color:#22c55e;border-color:#22c55e}
.badge-section{background:#1e293b;border-radius:8px;padding:1.5rem;margin-top:1.5rem;text-align:center}
.badge-section img{margin-bottom:0.75rem}
.badge-section code{display:block;background:#0f172a;padding:8px 12px;border-radius:4px;font-size:0.75rem;margin-top:0.5rem;word-break:break-all;user-select:all}
/* Hidden row */
.hidden-row{display:none}
/* Print */
@media print{
  body{background:#fff;color:#1e293b}
  table,th,td{border:1px solid #e2e8f0}
  .score-card,.stat,.summary-card,.toc,.chart,.filter-bar{background:#f8fafc}
  .copy-btn,.search-input{display:none}
  .finding-detail{display:block!important}
}
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

  <div class="stats" id="severity-stats">
    <div class="stat" onclick="toggleSevFilter('critical')" id="stat-critical"><div class="stat-number" style="color:${sevColors.critical}">${bySeverity.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat" onclick="toggleSevFilter('high')" id="stat-high"><div class="stat-number" style="color:${sevColors.high}">${bySeverity.high}</div><div class="stat-label">High</div></div>
    <div class="stat" onclick="toggleSevFilter('medium')" id="stat-medium"><div class="stat-number" style="color:${sevColors.medium}">${bySeverity.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat" onclick="toggleSevFilter('low')" id="stat-low"><div class="stat-number" style="color:${sevColors.low}">${bySeverity.low}</div><div class="stat-label">Low</div></div>
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
  <div class="chart">
    ${categoryBars}
  </div>

  <h2 id="plan">4. Remediation Plan</h2>
  <p style="color:#94a3b8;margin-bottom:1rem">Prioritized list of fixes. Address critical items first.</p>
  ${(remediationPlan || []).length > 0 ? `<table>
    <thead><tr><th>#</th><th>Category</th><th>Issue</th><th>Location</th><th>Fix</th></tr></thead>
    <tbody>${planHTML}</tbody>
  </table>` : '<p style="color:#22c55e;font-weight:bold">No issues found — all clear!</p>'}

  <h2 id="findings">5. All Findings (${findings.length})</h2>
  <div class="filter-bar">
    <label>Filter:</label>
    <button class="filter-btn active" data-sev="all" onclick="filterSev('all',this)">All</button>
    <button class="filter-btn" data-sev="critical" onclick="filterSev('critical',this)">Critical (${bySeverity.critical})</button>
    <button class="filter-btn" data-sev="high" onclick="filterSev('high',this)">High (${bySeverity.high})</button>
    <button class="filter-btn" data-sev="medium" onclick="filterSev('medium',this)">Medium (${bySeverity.medium})</button>
    <button class="filter-btn" data-sev="low" onclick="filterSev('low',this)">Low (${bySeverity.low})</button>
    <input class="search-input" type="text" placeholder="Search findings..." oninput="searchFindings(this.value)">
    <span class="count-label" id="visible-count">${findings.length} shown</span>
  </div>
  <table id="findings-table">
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

  <div class="share-bar">
    <a class="share-btn share-btn-x" href="https://twitter.com/intent/tweet?text=${encodeURIComponent(`My project scored ${scoreResult.score}/100 (Grade ${scoreResult.grade.letter}) on Ship Safe security audit! 18 AI agents, 80+ attack classes.\n\nScan yours: npx ship-safe audit .\n\nhttps://shipsafecli.com`)}" target="_blank" rel="noopener">Share on X</a>
    <a class="share-btn share-btn-li" href="https://www.linkedin.com/sharing/share-offsite/?url=https://shipsafecli.com" target="_blank" rel="noopener">Share on LinkedIn</a>
    <button class="share-btn share-btn-copy" onclick="copyShareText(this)">Copy Score Summary</button>
  </div>

  <div class="badge-section">
    <p style="color:#94a3b8;margin-bottom:0.75rem"><strong>Add a security badge to your README:</strong></p>
    <img src="https://img.shields.io/badge/Ship_Safe-${scoreResult.grade.letter}-${gradeColors[scoreResult.grade.letter].replace('#','')}" alt="Ship Safe Grade ${scoreResult.grade.letter}" />
    <code>[![Ship Safe](https://img.shields.io/badge/Ship_Safe-${scoreResult.grade.letter}-${gradeColors[scoreResult.grade.letter].replace('#','')})](https://shipsafecli.com)</code>
  </div>

  <div class="footer">
    Generated by <strong>Ship Safe v6.1</strong> — Full Security Audit<br>
    <a href="https://shipsafecli.com">shipsafecli.com</a> &middot; <a href="https://shipsafecli.com/pricing">Cloud Dashboard</a>
  </div>
</div>

<script>
function copyShareText(btn) {
  const text = 'My project scored ${scoreResult.score}/100 (Grade ${scoreResult.grade.letter}) on Ship Safe security audit!\\nScan yours: npx ship-safe audit .\\nhttps://shipsafecli.com';
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy Score Summary'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── Severity filter ────────────────────────────────────────────────────────
let activeSev = 'all';
let searchTerm = '';

function filterSev(sev, btn) {
  activeSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

function toggleSevFilter(sev) {
  const btn = document.querySelector('.filter-btn[data-sev="' + sev + '"]');
  if (activeSev === sev) {
    filterSev('all', document.querySelector('.filter-btn[data-sev="all"]'));
  } else if (btn) {
    filterSev(sev, btn);
  }
}

function searchFindings(term) {
  searchTerm = term.toLowerCase();
  applyFilters();
}

function applyFilters() {
  const rows = document.querySelectorAll('.finding-row');
  let visible = 0;
  rows.forEach(row => {
    const matchSev = activeSev === 'all' || row.dataset.sev === activeSev;
    const matchSearch = !searchTerm || row.dataset.text.includes(searchTerm);
    if (matchSev && matchSearch) {
      row.classList.remove('hidden-row');
      visible++;
    } else {
      row.classList.add('hidden-row');
    }
  });
  document.getElementById('visible-count').textContent = visible + ' shown';

  // Highlight active stat card
  document.querySelectorAll('.stat').forEach(s => s.classList.remove('active'));
  if (activeSev !== 'all') {
    const el = document.getElementById('stat-' + activeSev);
    if (el) el.classList.add('active');
  }
}

// ── Collapsible detail ─────────────────────────────────────────────────────
function toggleDetail(idx) {
  const el = document.getElementById('detail-' + idx);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

// ── Copy ignore annotation ─────────────────────────────────────────────────
function copyIgnore(text, btn) {
  navigator.clipboard.writeText('// ' + text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy ignore annotation'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
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
