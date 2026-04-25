/**
 * Ship Safe Security Agent — Interactive Fix Loop
 * ================================================
 *
 * Scans your codebase, then for each finding:
 *   1. Generates a precise fix plan via LLM
 *   2. Shows you exactly what it will change (unified diff)
 *   3. Asks you to accept, skip, or quit
 *   4. Applies the change atomically
 *   5. Re-scans the file to verify the finding is resolved
 *   6. Logs the change to .ship-safe/fixes.jsonl
 *
 * USAGE:
 *   ship-safe agent [path]              Interactive fix loop
 *   ship-safe agent . --plan-only       Generate plans, never write
 *   ship-safe agent . --severity high   Only fix high+ severity
 *   ship-safe agent . --provider deepseek-flash
 *
 * SAFETY:
 *   - Refuses to operate on a dirty git tree (use --allow-dirty to override)
 *   - Always shows a diff before any write
 *   - Re-scans after each edit to verify the fix
 *   - Every applied change is logged for audit & undo
 */

import fs from 'fs';
import path from 'path';
import { createInterface } from 'readline';
import { execFileSync } from 'child_process';
import chalk from 'chalk';
import ora from 'ora';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { auditCommand } from './audit.js';
import * as output from '../utils/output.js';

const SEV_RANK   = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const NEVER_EDIT = [
  /(^|\/)\.env(\.|$)/i,
  /\.pem$|\.key$|\.p12$|\.pfx$/i,
  /package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/i,
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /\.min\.(js|css)$/,
];

const FIX_LOG_DIR  = '.ship-safe';
const FIX_LOG_FILE = 'fixes.jsonl';

// =============================================================================
// MAIN
// =============================================================================

export async function agentFixCommand(targetPath = '.', options = {}) {
  const root = path.resolve(targetPath);

  if (!fs.existsSync(root)) {
    output.error(`Path does not exist: ${root}`);
    process.exit(1);
  }

  console.log();
  output.header('Ship Safe — Security Agent');
  console.log(chalk.gray('  I will scan, plan each fix, ask before changing anything,'));
  console.log(chalk.gray('  and verify the fix worked. You stay in control.'));
  console.log();

  // ── Git safety check ─────────────────────────────────────────────────────
  if (!options.allowDirty) {
    const state = checkGitState(root);
    if (state === 'not-a-repo') {
      console.log(chalk.yellow('  Note: this is not a git repository.'));
      console.log(chalk.gray('  Changes cannot be reverted automatically.'));
      const ok = await confirm('  Continue anyway?');
      if (!ok) { console.log(chalk.gray('  Aborted.\n')); return; }
    } else if (state === 'dirty') {
      output.error('Working tree has uncommitted changes.');
      console.log(chalk.gray('  Commit or stash first, or pass --allow-dirty.'));
      process.exit(1);
    }
  }

  // ── Load LLM provider ────────────────────────────────────────────────────
  const provider = autoDetectProvider(root, {
    provider:   options.provider,
    model:      options.model,
    think:      options.think || false,
  });
  if (!provider) {
    output.error('No LLM provider available.');
    console.log(chalk.gray('  Set one of: DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, MOONSHOT_API_KEY, XAI_API_KEY'));
    process.exit(1);
  }
  console.log(chalk.gray(`  Provider: ${chalk.cyan(provider.name)}`));

  // ── Run the scan ─────────────────────────────────────────────────────────
  const scanSpinner = ora({ text: 'Scanning for issues...', color: 'cyan' }).start();
  let scanResult;
  try {
    scanResult = await auditCommand(root, { _agenticInner: true, deep: false, deps: false, noAi: true });
  } catch (err) {
    scanSpinner.fail('Scan failed');
    output.error(err.message);
    process.exit(1);
  }
  scanSpinner.stop();

  // ── Filter findings ──────────────────────────────────────────────────────
  const minSev  = options.severity || 'low';
  const minRank = SEV_RANK[minSev] ?? 1;

  const findings = (scanResult.findings ?? []).filter(f => {
    if (!f.file) return false;
    if ((SEV_RANK[f.severity] ?? 0) < minRank) return false;
    const rel = f.file.replace(/\\/g, '/');
    if (NEVER_EDIT.some(p => p.test(rel))) return false;
    const abs = path.resolve(root, f.file);
    return fs.existsSync(abs);
  });

  if (findings.length === 0) {
    output.success('No fixable findings at the requested severity.');
    console.log();
    return;
  }

  console.log(chalk.cyan(`  Found ${findings.length} fixable finding(s)`));
  console.log();

  // ── Fix loop ─────────────────────────────────────────────────────────────
  const applied = [];
  const skipped = [];

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    const idx     = `[${i + 1}/${findings.length}]`;

    console.log();
    console.log(chalk.bold(`  ${idx} ${severityLabel(finding.severity)} ${finding.title}`));
    console.log(chalk.gray(`      ${finding.file}${finding.line ? `:${finding.line}` : ''}`));
    if (finding.description) {
      console.log(chalk.gray(`      ${finding.description}`));
    }

    // Generate plan
    const planSpinner = ora({ text: 'Generating fix plan...', color: 'cyan', indent: 6 }).start();
    let plan;
    try {
      plan = await generateFixPlan(provider, root, finding);
      planSpinner.stop();
    } catch (err) {
      planSpinner.fail(chalk.red(`Plan generation failed: ${err.message}`));
      skipped.push({ finding, reason: 'plan-generation-failed' });
      continue;
    }

    if (!plan || !plan.files || plan.files.length === 0) {
      console.log(chalk.yellow('      No precise fix available — needs manual review.'));
      skipped.push({ finding, reason: 'no-precise-fix' });
      continue;
    }

    // Validate the plan's `find` strings actually exist in the files
    const validation = validatePlan(root, plan);
    if (!validation.ok) {
      console.log(chalk.yellow(`      Plan invalid: ${validation.reason}`));
      skipped.push({ finding, reason: `plan-invalid: ${validation.reason}` });
      continue;
    }

    // Show plan
    printPlan(plan, root);

    if (options.planOnly) {
      console.log(chalk.gray('      (plan-only mode — not applying)'));
      continue;
    }

    // Confirm
    const decision = (await prompt(chalk.cyan('      [a]ccept  [s]kip  [q]uit > '))).trim().toLowerCase();
    if (decision === 'q' || decision === 'quit') {
      console.log(chalk.gray('      Stopping.'));
      break;
    }
    if (decision !== 'a' && decision !== 'accept' && decision !== 'y' && decision !== 'yes') {
      skipped.push({ finding, reason: 'user-skipped' });
      continue;
    }

    // Apply
    try {
      for (const fileChange of plan.files) {
        applyEdit(root, fileChange);
      }
    } catch (err) {
      console.log(chalk.red(`      Apply failed: ${err.message}`));
      skipped.push({ finding, reason: `apply-failed: ${err.message}` });
      continue;
    }

    // Verify by re-scanning the file
    const verifySpinner = ora({ text: 'Verifying...', color: 'cyan', indent: 6 }).start();
    const verified = await verifyFinding(root, finding);
    if (verified) {
      verifySpinner.succeed(chalk.green('Fix verified — finding resolved'));
    } else {
      verifySpinner.warn(chalk.yellow('Fix applied, but a related finding still appears'));
    }

    // Log
    logFix(root, {
      timestamp: new Date().toISOString(),
      finding:   { title: finding.title, file: finding.file, line: finding.line, severity: finding.severity, rule: finding.rule },
      plan,
      verified,
    });

    applied.push({ finding, plan, verified });
  }

  // ── Final report ─────────────────────────────────────────────────────────
  console.log();
  console.log();
  output.header('Summary');
  console.log();
  console.log(`  ${chalk.green('Applied:')} ${applied.length}`);
  console.log(`  ${chalk.gray('Skipped:')} ${skipped.length}`);

  if (applied.length > 0) {
    console.log();
    console.log(chalk.gray('  Applied fixes:'));
    for (const a of applied) {
      const mark = a.verified ? chalk.green('✓') : chalk.yellow('?');
      console.log(`    ${mark} ${a.finding.title} ${chalk.gray(`(${a.finding.file})`)}`);
    }
    console.log();
    console.log(chalk.gray(`  Audit log: ${path.join(FIX_LOG_DIR, FIX_LOG_FILE)}`));
    console.log(chalk.gray('  Review changes:  git diff'));
    console.log(chalk.gray('  Undo all:        git checkout .'));
  }

  if (skipped.length > 0 && applied.length === 0) {
    console.log();
    console.log(chalk.gray('  Tip: try a different provider with --provider, or run with --plan-only to inspect'));
    console.log(chalk.gray('  what would change before committing.'));
  }

  console.log();
}

// =============================================================================
// PLAN GENERATION
// =============================================================================

async function generateFixPlan(provider, root, finding) {
  const filePath = path.resolve(root, finding.file);
  let fileContent;
  try {
    fileContent = fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }

  // Window to a region around the finding for big files
  const fileForPrompt = windowFileContent(fileContent, finding.line);

  const systemPrompt = 'You are a security engineer. Produce precise code edits as structured JSON only. Never include prose, markdown, or code fences. Output a single JSON object.';

  const userPrompt = `Fix this security finding by producing a precise code edit.

FINDING:
- Severity: ${finding.severity}
- Title: ${finding.title}
- File: ${finding.file}${finding.line ? ` (line ${finding.line})` : ''}
- Description: ${finding.description ?? 'N/A'}
- Rule: ${finding.rule ?? 'N/A'}
${finding.fix ? `- Suggested fix: ${finding.fix}\n` : ''}
FILE CONTENT:
\`\`\`
${fileForPrompt}
\`\`\`

OUTPUT this exact JSON shape:
{
  "summary": "one short sentence describing what you'll do",
  "files": [
    {
      "path": "${finding.file}",
      "edits": [
        { "find": "EXACT verbatim substring to find", "replace": "new string", "reason": "why this fix" }
      ]
    }
  ],
  "risk": "low"
}

RULES:
- "find" must appear EXACTLY in the file content. Include enough context (3+ lines if needed) to be unique.
- "replace" is the corrected code. For secrets, use process.env.NAME or the language equivalent.
- Risk levels: "low" = mechanical change with no logic shift, "medium" = behavior change, "high" = architectural.
- If you cannot produce a precise mechanical edit, return: {"summary":"requires manual review","files":[],"risk":"high"}
- JSON only. No prose. No code fences.`;

  const response = await provider.complete(systemPrompt, userPrompt, {
    maxTokens: 2000,
    jsonMode:  true,
  });

  // Parse — be lenient since some providers wrap in code fences despite instructions
  const cleaned = response.trim()
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      try { return JSON.parse(m[0]); } catch { return null; }
    }
    return null;
  }
}

function windowFileContent(content, line) {
  if (content.length <= 8000) return content;
  if (!line) return content.slice(0, 8000);
  const lines = content.split('\n');
  const start = Math.max(0, line - 40);
  const end   = Math.min(lines.length, line + 40);
  return lines.slice(start, end).join('\n');
}

// =============================================================================
// PLAN VALIDATION
// =============================================================================

function validatePlan(root, plan) {
  if (!Array.isArray(plan.files)) return { ok: false, reason: 'no files array' };

  for (const f of plan.files) {
    if (!f.path || !Array.isArray(f.edits) || f.edits.length === 0) {
      return { ok: false, reason: 'malformed file entry' };
    }
    const abs = path.resolve(root, f.path);
    if (!fs.existsSync(abs)) {
      return { ok: false, reason: `file not found: ${f.path}` };
    }
    if (NEVER_EDIT.some(p => p.test(f.path.replace(/\\/g, '/')))) {
      return { ok: false, reason: `protected path: ${f.path}` };
    }
    const content = fs.readFileSync(abs, 'utf8');
    for (const e of f.edits) {
      if (typeof e.find !== 'string' || typeof e.replace !== 'string') {
        return { ok: false, reason: 'edit missing find/replace' };
      }
      if (e.find === e.replace) {
        return { ok: false, reason: 'edit is a no-op' };
      }
      const occurrences = countOccurrences(content, e.find);
      if (occurrences === 0) {
        return { ok: false, reason: `find string not present in ${f.path}` };
      }
      if (occurrences > 1) {
        return { ok: false, reason: `find string is ambiguous (${occurrences} matches) in ${f.path}` };
      }
    }
  }
  return { ok: true };
}

function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let count = 0, idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) { count++; idx += needle.length; }
  return count;
}

// =============================================================================
// PRINTING
// =============================================================================

function printPlan(plan, root) {
  console.log();
  console.log(chalk.bold('      Plan:'));
  console.log(chalk.white(`        ${plan.summary || '(no summary)'}`));
  if (plan.risk) {
    const riskColor = plan.risk === 'low' ? chalk.green : plan.risk === 'medium' ? chalk.yellow : chalk.red;
    console.log(`        Risk: ${riskColor(plan.risk)}`);
  }
  console.log();

  for (const f of plan.files) {
    console.log(chalk.bold(`      ${f.path}`));
    for (const e of f.edits) {
      console.log(chalk.gray(`        — ${e.reason || 'edit'}`));
      printDiff(e.find, e.replace);
    }
  }
  console.log();
}

function printDiff(oldStr, newStr) {
  const oldLines = oldStr.split('\n');
  const newLines = newStr.split('\n');
  for (const l of oldLines) console.log(chalk.red(`        - ${l}`));
  for (const l of newLines) console.log(chalk.green(`        + ${l}`));
}

function severityLabel(sev) {
  switch (sev) {
    case 'critical': return chalk.red.bold('[CRITICAL]');
    case 'high':     return chalk.red('[HIGH]');
    case 'medium':   return chalk.yellow('[MEDIUM]');
    case 'low':      return chalk.blue('[LOW]');
    default:         return chalk.gray(`[${(sev || 'INFO').toUpperCase()}]`);
  }
}

// =============================================================================
// APPLY
// =============================================================================

function applyEdit(root, fileChange) {
  const abs = path.resolve(root, fileChange.path);
  let content = fs.readFileSync(abs, 'utf8');

  for (const e of fileChange.edits) {
    if (!content.includes(e.find)) {
      throw new Error(`find string no longer present in ${fileChange.path} (file changed during planning)`);
    }
    content = content.replace(e.find, e.replace);
  }

  fs.writeFileSync(abs, content, 'utf8');
}

// =============================================================================
// VERIFY
// =============================================================================

async function verifyFinding(root, originalFinding) {
  // Re-run the scan and check whether a finding with the same rule+file+line still exists.
  try {
    const result = await auditCommand(root, { _agenticInner: true, deep: false, deps: false, noAi: true });
    const stillThere = (result.findings ?? []).some(f =>
      f.file === originalFinding.file &&
      f.rule === originalFinding.rule &&
      Math.abs((f.line ?? 0) - (originalFinding.line ?? 0)) <= 2,
    );
    return !stillThere;
  } catch {
    return false;
  }
}

// =============================================================================
// LOGGING
// =============================================================================

function logFix(root, entry) {
  const dir  = path.join(root, FIX_LOG_DIR);
  const file = path.join(dir, FIX_LOG_FILE);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(file, JSON.stringify(entry) + '\n', 'utf8');
}

// =============================================================================
// GIT
// =============================================================================

function checkGitState(root) {
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: root, stdio: 'pipe' });
  } catch {
    return 'not-a-repo';
  }
  try {
    const out = execFileSync('git', ['status', '--porcelain'], { cwd: root, stdio: 'pipe' }).toString();
    // Ignore Ship Safe's own artifacts when assessing cleanliness
    const meaningful = out.split('\n').filter(line => {
      const path = line.slice(3).trim();
      if (!path) return false;
      if (path.startsWith('.ship-safe/')) return false;
      if (path === 'ship-safe-report.html') return false;
      return true;
    });
    return meaningful.length === 0 ? 'clean' : 'dirty';
  } catch {
    return 'clean';
  }
}

// =============================================================================
// PROMPTS
// =============================================================================

function prompt(question) {
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, answer => { rl.close(); resolve(answer); });
  });
}

async function confirm(question) {
  const a = (await prompt(`${question} [y/N] `)).trim().toLowerCase();
  return a === 'y' || a === 'yes';
}
