/**
 * Team Report Command
 * ====================
 *
 * Converts raw Hermes Agent team output into a professional Ship Safe report.
 * Strips ANSI codes and terminal chrome, parses structured FINDING: lines,
 * and renders everything through Ship Safe's HTML reporter.
 *
 * USAGE:
 *   ship-safe team-report                     Read from stdin (pipe Hermes output)
 *   ship-safe team-report output.txt          Read from file
 *   ship-safe team-report output.txt --html   Save as HTML
 *   ship-safe team-report output.txt --json   JSON output
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import * as output from '../utils/output.js';
import { printBanner } from '../utils/output.js';

// =============================================================================
// ANSI + TERMINAL NOISE STRIPPING
// =============================================================================

function stripAnsi(str) {
  // Remove all ANSI escape sequences (colors, cursor moves, clears, etc.)
  return str
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][AB012]/g, '')
    .replace(/\x9b[0-9;]*[A-Za-z]/g, '');
}

function stripHermesChrome(text) {
  const lines = text.split('\n');
  const cleaned = [];
  let inSplash = false;

  for (const line of lines) {
    const t = line.trim();

    // Skip the Hermes splash box (╭─ ... ─╮ ... ╰─ ... ─╯)
    if (t.startsWith('╭─') || t.startsWith('╰─')) { inSplash = !inSplash; continue; }
    if (inSplash) continue;

    // Skip raw system prompt instructions leaked into output
    if (t.startsWith('EXACTLY this format') || t.startsWith('FINDING: {"severity"')) continue;
    if (t.match(/^─{10,}$/)) continue;

    // Skip Hermes warning lines
    if (t.startsWith('⚠') && t.includes('hermes')) continue;
    if (t.startsWith('⚠') && t.includes('OPENROUTER')) continue;
    if (t.startsWith('⚠') && (t.includes('API call failed') || t.includes('credits'))) continue;
    if (t.startsWith('⏱') || t.startsWith('❌')) continue;

    // Skip terminal screen-clear sequences
    if (t === '[2J' || t === '[H' || t === '[2J[H') continue;

    cleaned.push(line);
  }

  return cleaned.join('\n');
}

// =============================================================================
// FINDING PARSER
// =============================================================================

function parseFindings(text) {
  const findings = [];
  const findingRegex = /^FINDING:\s*(\{.+\})\s*$/gm;
  let match;

  while ((match = findingRegex.exec(text)) !== null) {
    try {
      const f = JSON.parse(match[1]);
      if (f.severity && f.title) findings.push(f);
    } catch { /* skip malformed */ }
  }

  return findings;
}

// =============================================================================
// AGENT SECTION PARSER
// =============================================================================

function parseAgentSections(text) {
  const sections = [];
  // Matches: ### Agent Name (Role) — N finding(s)
  const sectionRegex = /###\s+(.+?)\s*(?:\(([^)]+)\))?\s*[—–-]+\s*(\d+)\s*finding/gi;
  let match;

  while ((match = sectionRegex.exec(text)) !== null) {
    sections.push({
      name: match[1].trim(),
      role: match[2]?.trim() || '',
      count: parseInt(match[3], 10),
    });
  }

  // Also collect bullet findings under each section
  const bulletRegex = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?)\s*[—–-]+\s*(.+)/gi;
  const bullets = [];
  while ((match = bulletRegex.exec(text)) !== null) {
    bullets.push({
      severity: match[1].toLowerCase(),
      title: match[2].trim(),
      location: match[3].trim(),
    });
  }

  return { sections, bullets };
}

// =============================================================================
// SYNTHESIS PARSER
// =============================================================================

function parseSynthesis(text) {
  // Extract the Hermes synthesis block (inside ╭─ ⚕ Hermes ─╮ ... ╰─╯)
  // After stripping chrome, look for the summary block
  const lines = text.split('\n');
  const synthesisLines = [];
  let capturing = false;

  for (const line of lines) {
    const t = line.trim();

    // The synthesis is the content after the agent section summary and before errors
    if (t.match(/^Overall risk posture:/i)) { capturing = true; }
    if (capturing) {
      if (t.startsWith('⚠') || t.startsWith('❌') || t.startsWith('⏱')) break;
      synthesisLines.push(line);
    }
  }

  // Also look for risk posture statement
  const riskMatch = text.match(/Overall risk posture:\s*(.+)/i);
  const riskPosture = riskMatch ? riskMatch[1].trim() : null;

  // Parse roadmap sections
  const immediateMatch = text.match(/\*\*Immediate[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const shortTermMatch = text.match(/\*\*Short-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);
  const longTermMatch  = text.match(/\*\*Long-term[^*]*\*\*:?\s*([^\n]+(?:\n(?!\*\*)[^\n]+)*)/i);

  return {
    riskPosture,
    synthesis: synthesisLines.join('\n').trim(),
    roadmap: {
      immediate: immediateMatch?.[1]?.trim() || null,
      shortTerm: shortTermMatch?.[1]?.trim() || null,
      longTerm:  longTermMatch?.[1]?.trim()  || null,
    },
  };
}

// =============================================================================
// TARGET PARSER
// =============================================================================

function parseTarget(text) {
  const match = text.match(/assessments?\s+of\s+\*\*([^*]+)\*\*/i);
  return match ? match[1].trim() : 'Unknown Target';
}

// =============================================================================
// HTML RENDERER
// =============================================================================

function generateHTML(target, findings, agentSections, synthesis, bullets) {
  const date = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  // Merge FINDING: JSON lines with bullet-parsed findings (bullets are fallback)
  const allFindings = findings.length > 0 ? findings : bullets.map(b => ({
    severity: b.severity,
    title: b.title,
    location: b.location,
    remediation: '',
  }));

  // Recalculate counts from allFindings
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;

  const riskColor = (rp) => {
    if (!rp) return '#94a3b8';
    const lc = rp.toLowerCase();
    if (lc.includes('critical')) return '#dc2626';
    if (lc.includes('high')) return '#f97316';
    if (lc.includes('medium')) return '#eab308';
    return '#22c55e';
  };

  const sevColors = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#94a3b8' };

  const findingRows = allFindings.map(f => `
    <tr>
      <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
      <td><code>${f.location || '—'}</code></td>
      <td><strong>${f.title}</strong>${f.cve ? `<br><small>CVE: ${f.cve}</small>` : ''}</td>
      <td><small>${f.remediation || '—'}</small></td>
    </tr>`).join('');

  const agentRows = agentSections.sections.map(s => `
    <tr>
      <td>${s.name}</td>
      <td><code>${s.role || '—'}</code></td>
      <td style="color:${s.count > 0 ? '#f97316' : '#22c55e'}">${s.count}</td>
    </tr>`).join('');

  const roadmap = synthesis.roadmap;
  const roadmapHTML = (roadmap.immediate || roadmap.shortTerm || roadmap.longTerm) ? `
    <h2>Remediation Roadmap</h2>
    <table>
      <tbody>
        ${roadmap.immediate ? `<tr><td style="color:#dc2626;white-space:nowrap;font-weight:600">⚡ Immediate (24–48h)</td><td>${roadmap.immediate}</td></tr>` : ''}
        ${roadmap.shortTerm ? `<tr><td style="color:#f97316;white-space:nowrap;font-weight:600">📅 Short-term (1–2 weeks)</td><td>${roadmap.shortTerm}</td></tr>` : ''}
        ${roadmap.longTerm  ? `<tr><td style="color:#eab308;white-space:nowrap;font-weight:600">🏗 Long-term (1–3 months)</td><td>${roadmap.longTerm}</td></tr>` : ''}
      </tbody>
    </table>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ship Safe Team Report — ${target}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
.container{max-width:1100px;margin:0 auto}
.header{display:flex;align-items:center;gap:1rem;margin-bottom:2rem}
.logo{font-size:1.5rem;font-weight:800;color:#38bdf8;letter-spacing:-1px}
.badge{background:#1e293b;padding:3px 10px;border-radius:20px;font-size:0.75rem;color:#94a3b8;border:1px solid #334155}
h1{font-size:1.8rem;font-weight:700;color:#f1f5f9;margin-bottom:0.25rem}
h2{font-size:1.1rem;font-weight:600;margin:2rem 0 1rem;color:#94a3b8;border-bottom:1px solid #1e293b;padding-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em}
.meta{color:#64748b;font-size:0.85rem;margin-bottom:2rem}
.risk-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.5rem 2rem;margin-bottom:2rem;display:flex;align-items:center;gap:1.5rem}
.risk-label{font-size:0.75rem;text-transform:uppercase;color:#64748b;margin-bottom:0.25rem}
.risk-value{font-size:1.5rem;font-weight:700}
.risk-desc{color:#94a3b8;font-size:0.9rem;flex:1}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:0.75rem;margin-bottom:2rem}
.stat{background:#1e293b;padding:1.25rem;border-radius:8px;text-align:center;border:1px solid #334155}
.stat-number{font-size:2rem;font-weight:bold}
.stat-label{color:#64748b;font-size:0.75rem;margin-top:0.25rem;text-transform:uppercase}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin-bottom:2rem;border:1px solid #334155}
th{background:#334155;text-align:left;padding:0.75rem 1rem;font-size:0.75rem;text-transform:uppercase;color:#94a3b8;font-weight:600;letter-spacing:0.05em}
td{padding:0.75rem 1rem;border-top:1px solid #0f172a;font-size:0.85rem;vertical-align:top}
tr:hover{background:#263248}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem;color:#38bdf8;word-break:break-all}
small{color:#64748b}
.sev{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em}
.sev-critical{background:#dc262622;color:#fca5a5;border:1px solid #dc262644}
.sev-high{background:#f9731622;color:#fdba74;border:1px solid #f9731644}
.sev-medium{background:#eab30822;color:#fde047;border:1px solid #eab30844}
.sev-low{background:#3b82f622;color:#93c5fd;border:1px solid #3b82f644}
.sev-info{background:#94a3b822;color:#cbd5e1;border:1px solid #94a3b844}
.empty{text-align:center;color:#22c55e;padding:2rem}
.footer{text-align:center;color:#334155;margin-top:3rem;padding-top:1.5rem;border-top:1px solid #1e293b;font-size:0.8rem}
.powered{color:#38bdf8}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <span class="logo">Ship Safe</span>
    <span class="badge">Team Security Report</span>
    <span class="badge">Powered by Hermes Agent</span>
  </div>

  <h1>${target}</h1>
  <p class="meta">Generated ${date} · ${allFindings.length} finding${allFindings.length !== 1 ? 's' : ''} · ${agentSections.sections.length} agent${agentSections.sections.length !== 1 ? 's' : ''}</p>

  ${synthesis.riskPosture ? `
  <div class="risk-card">
    <div>
      <div class="risk-label">Overall Risk Posture</div>
      <div class="risk-value" style="color:${riskColor(synthesis.riskPosture)}">${synthesis.riskPosture.split('—')[0].trim()}</div>
    </div>
    <div class="risk-desc">${synthesis.riskPosture.includes('—') ? synthesis.riskPosture.split('—').slice(1).join('—').trim() : ''}</div>
  </div>` : ''}

  <div class="stats">
    <div class="stat"><div class="stat-number" style="color:#dc2626">${sevCounts.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-number" style="color:#f97316">${sevCounts.high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-number" style="color:#eab308">${sevCounts.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-number" style="color:#3b82f6">${sevCounts.low}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-number" style="color:#94a3b8">${sevCounts.info}</div><div class="stat-label">Info</div></div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Remediation</th></tr></thead>
    <tbody>${findingRows || '<tr><td colspan="4" class="empty">No findings — clean!</td></tr>'}</tbody>
  </table>

  ${agentSections.sections.length > 0 ? `
  <h2>Agent Team Summary</h2>
  <table>
    <thead><tr><th>Agent</th><th>Role</th><th>Findings</th></tr></thead>
    <tbody>${agentRows}</tbody>
  </table>` : ''}

  ${roadmapHTML}

  <div class="footer">
    Secured by <span class="powered">Ship Safe</span> · shipsafecli.com · <code>npx ship-safe red-team .</code>
  </div>
</div>
</body>
</html>`;
}

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function teamReportCommand(inputFile, options = {}) {
  let raw;

  if (inputFile) {
    if (!fs.existsSync(inputFile)) {
      output.error(`File not found: ${inputFile}`);
      process.exit(1);
    }
    raw = fs.readFileSync(inputFile, 'utf-8');
  } else {
    // Read from stdin
    raw = fs.readFileSync('/dev/stdin', 'utf-8');
  }

  // Clean the input
  const stripped = stripAnsi(raw);
  const cleaned  = stripHermesChrome(stripped);

  // Parse
  const target       = parseTarget(stripped);
  const findings     = parseFindings(cleaned);
  const agentSections = parseAgentSections(cleaned);
  const synthesis    = parseSynthesis(cleaned);

  const allFindings = findings.length > 0 ? findings : agentSections.bullets.map(b => ({
    severity: b.severity,
    title: b.title,
    location: b.location,
    remediation: '',
  }));

  if (options.json) {
    console.log(JSON.stringify({ target, findings: allFindings, agentSections: agentSections.sections, synthesis }, null, 2));
    return;
  }

  if (options.html !== undefined) {
    const htmlPath = typeof options.html === 'string' ? options.html : 'team-report.html';
    const html = generateHTML(target, findings, agentSections, synthesis, agentSections.bullets);
    fs.writeFileSync(htmlPath, html, 'utf-8');
    output.success(`Team report saved to ${htmlPath}`);
    return;
  }

  // Terminal output
  printBanner();
  console.log(chalk.cyan.bold('  Team Security Report'));
  console.log(chalk.gray(`  Target: ${target}`));
  console.log();

  if (synthesis.riskPosture) {
    const rp = synthesis.riskPosture;
    const color = rp.toLowerCase().includes('critical') ? chalk.red.bold
      : rp.toLowerCase().includes('high') ? chalk.yellow.bold
      : rp.toLowerCase().includes('medium') ? chalk.yellow
      : chalk.green;
    console.log(`  ${chalk.white.bold('Risk Posture:')} ${color(rp)}`);
    console.log();
  }

  const sevColor = { critical: chalk.red.bold, high: chalk.yellow, medium: chalk.blue, low: chalk.gray, info: chalk.gray };
  for (const f of allFindings) {
    const col = sevColor[f.severity] || chalk.white;
    console.log(`  ${col(`[${f.severity.toUpperCase()}]`.padEnd(11))} ${chalk.white(f.title)}`);
    if (f.location) console.log(`  ${' '.repeat(11)} ${chalk.gray(f.location)}`);
    if (f.remediation) console.log(`  ${' '.repeat(11)} ${chalk.green('Fix:')} ${f.remediation.slice(0, 90)}`);
  }

  if (allFindings.length === 0) {
    console.log(chalk.green('  No findings — clean!'));
  }

  console.log();
  if (synthesis.roadmap.immediate) {
    console.log(chalk.red.bold('  ⚡ Immediate (24–48h):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.immediate}`));
  }
  if (synthesis.roadmap.shortTerm) {
    console.log(chalk.yellow.bold('  📅 Short-term (1–2 weeks):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.shortTerm}`));
  }
  if (synthesis.roadmap.longTerm) {
    console.log(chalk.white.bold('  🏗  Long-term (1–3 months):'));
    console.log(chalk.gray(`     ${synthesis.roadmap.longTerm}`));
  }

  console.log();
  console.log(chalk.gray('  Generate HTML report: ') + chalk.cyan(`ship-safe team-report ${inputFile || '<file>'} --html report.html`));
  console.log();
}
