/**
 * Ship Safe Security Agent — Interactive Fix Loop
 * ================================================
 *
 * Scans your codebase, then for each affected file:
 *   1. Generates a precise multi-edit fix plan via LLM (one plan per file,
 *      addressing every finding in that file at once)
 *   2. Shows you exactly what it will change (unified diff with line numbers)
 *   3. Asks you to accept, skip, or quit
 *   4. Applies the changes atomically
 *   5. Re-scans to verify the findings are resolved
 *   6. Logs every change to .ship-safe/fixes.jsonl
 *
 * USAGE:
 *   ship-safe agent [path]              Interactive fix loop
 *   ship-safe agent . --plan-only       Generate plans, never write
 *   ship-safe agent . --severity high   Only fix high+ severity
 *   ship-safe agent . --branch fixes    Create a branch, commit per file
 *   ship-safe agent . --pr              After fixing, push and open a PR
 *   ship-safe agent . --provider deepseek-flash
 *
 * SAFETY:
 *   - Refuses to operate on a dirty git tree (use --allow-dirty to override)
 *   - Always shows a diff before any write
 *   - Re-scans after each batch to verify the fix
 *   - Plans may create new files (e.g., .env.example) but cannot edit
 *     .env, secrets, lockfiles, or build artifacts
 *   - Every applied change is logged for audit & undo (`ship-safe undo`)
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
// Files the agent IS allowed to create or update freely (companions to fixes)
const SAFE_NEW_FILES = [
  /(^|\/)\.env\.example$/i,
  /(^|\/)\.env\.sample$/i,
  /(^|\/)\.gitignore$/i,
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
  const initialBranch = getCurrentBranch(root);
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

  // ── Optional branch isolation ────────────────────────────────────────────
  let branchCreated = null;
  if (options.branch) {
    if (!initialBranch) {
      console.log(chalk.yellow('  --branch requires a git repository. Skipping branch creation.'));
    } else {
      const stamp      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 16);
      const branchName = options.branch === true
        ? `ship-safe/fixes-${stamp}`
        : String(options.branch);
      try {
        execFileSync('git', ['checkout', '-b', branchName], { cwd: root, stdio: 'pipe' });
        branchCreated = branchName;
        console.log(chalk.gray(`  Branch: ${chalk.cyan(branchName)}`));
      } catch (err) {
        output.error(`Could not create branch ${branchName}: ${err.message}`);
        process.exit(1);
      }
    }
  }

  // ── Load LLM provider ────────────────────────────────────────────────────
  const provider = autoDetectProvider(root, {
    provider: options.provider,
    model:    options.model,
    think:    options.think || false,
  });
  if (!provider) {
    output.error('No LLM provider available.');
    console.log(chalk.gray('  Set one of: DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, MOONSHOT_API_KEY, XAI_API_KEY'));
    process.exit(1);
  }
  console.log(chalk.gray(`  Provider: ${chalk.cyan(provider.name)}`));

  if (options.sandbox) {
    console.log(chalk.yellow('  --sandbox is not yet implemented — falling back to in-process verification.'));
    console.log(chalk.gray('  Track this in the agent\'s next milestone.'));
  }

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

  // ── Group by file ────────────────────────────────────────────────────────
  const byFile = new Map();
  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  console.log(chalk.cyan(`  Found ${findings.length} fixable finding(s) across ${byFile.size} file(s)`));
  console.log();

  // ── Fix loop ─────────────────────────────────────────────────────────────
  const applied = []; // { file, plan, verified }
  const skipped = []; // { file, findings, reason }
  let stopped   = false;
  let i         = 0;

  for (const [filePath, fileFindings] of byFile) {
    i++;
    if (stopped) break;

    const idx = `[${i}/${byFile.size}]`;
    console.log();
    console.log(chalk.bold(`  ${idx} ${chalk.cyan(filePath)} ${chalk.gray(`— ${fileFindings.length} finding(s)`)}`));
    for (const f of fileFindings) {
      console.log(`      ${severityLabel(f.severity)} ${f.title}${f.line ? chalk.gray(` (line ${f.line})`) : ''}`);
    }

    // Generate plan
    const planSpinner = ora({ text: 'Generating fix plan...', color: 'cyan', indent: 6 }).start();
    const planResult = await generateBatchPlan(provider, root, filePath, fileFindings);
    planSpinner.stop();

    if (!planResult.ok) {
      const detail = describePlanFailure(planResult);
      console.log(chalk.yellow(`      ${detail.message}`));
      logFailure(root, { timestamp: new Date().toISOString(), file: filePath, findings: fileFindings.map(f => ({ title: f.title, line: f.line, rule: f.rule })), ...planResult });
      skipped.push({ file: filePath, findings: fileFindings, reason: detail.reason });
      continue;
    }
    const plan = planResult.plan;

    // Validate (allows new safe files like .env.example)
    const validation = validatePlan(root, plan);
    if (!validation.ok) {
      console.log(chalk.yellow(`      Plan invalid: ${validation.reason}`));
      logFailure(root, { timestamp: new Date().toISOString(), file: filePath, findings: fileFindings.map(f => ({ title: f.title, line: f.line, rule: f.rule })), reason: 'validation-rejected', detail: validation.reason, plan });
      skipped.push({ file: filePath, findings: fileFindings, reason: `plan-invalid: ${validation.reason}` });
      continue;
    }

    // Show plan
    printPlan(plan, root);

    if (options.planOnly) {
      console.log(chalk.gray('      (plan-only mode — not applying)'));
      continue;
    }

    // Decision logic:
    //   --yolo       → auto-accept everything
    //   --auto-low   → auto-accept low-risk plans, prompt on medium/high
    //   default      → prompt every time
    let decision;
    const risk = (plan.risk || 'medium').toLowerCase();
    if (options.yolo) {
      decision = 'a';
      console.log(chalk.gray('      (yolo: auto-accepting)'));
    } else if (options.autoLow && risk === 'low') {
      decision = 'a';
      console.log(chalk.gray('      (auto-low: low-risk, auto-accepting)'));
    } else {
      // Interactive: prompt with [e]dit option
      decision = await promptDecision(plan, root);
    }

    if (decision === 'q' || decision === 'quit') {
      console.log(chalk.gray('      Stopping.'));
      stopped = true;
      break;
    }
    if (!['a', 'accept', 'y', 'yes'].includes(decision)) {
      skipped.push({ file: filePath, findings: fileFindings, reason: 'user-skipped' });
      continue;
    }

    // Apply
    let applyErr = null;
    const written = [];
    try {
      for (const fileChange of plan.files) {
        applyEdit(root, fileChange);
        written.push(path.resolve(root, fileChange.path));
      }
    } catch (err) {
      applyErr = err.message;
    }

    if (applyErr) {
      console.log(chalk.red(`      Apply failed: ${applyErr}`));
      skipped.push({ file: filePath, findings: fileFindings, reason: `apply-failed: ${applyErr}` });
      continue;
    }

    // Verify by re-scanning
    const verifySpinner = ora({ text: 'Verifying...', color: 'cyan', indent: 6 }).start();
    const verified = await verifyFile(root, filePath, fileFindings);
    if (verified.allResolved) {
      verifySpinner.succeed(chalk.green(`Fix verified — ${fileFindings.length} finding(s) resolved`));
    } else if (verified.someResolved) {
      verifySpinner.warn(chalk.yellow(`Partial: ${verified.resolvedCount}/${fileFindings.length} resolved`));
    } else {
      verifySpinner.warn(chalk.yellow('Fix applied, but findings still appear'));
    }

    // Per-fix commit (if branch isolation in use)
    if (branchCreated) {
      try {
        execFileSync('git', ['add', '--', ...written], { cwd: root, stdio: 'pipe' });
        const titles = fileFindings.slice(0, 3).map(f => f.title).join(', ');
        const more   = fileFindings.length > 3 ? ` (+${fileFindings.length - 3} more)` : '';
        const msg    = `fix(security): ${filePath} — ${titles}${more}`;
        execFileSync('git', ['commit', '-m', msg], { cwd: root, stdio: 'pipe' });
      } catch {
        // commit failed — most likely nothing staged because edits were no-ops
      }
    }

    // Log
    logFix(root, {
      timestamp: new Date().toISOString(),
      file:      filePath,
      findings:  fileFindings.map(f => ({ title: f.title, line: f.line, severity: f.severity, rule: f.rule })),
      plan,
      verified:  verified.allResolved,
      branch:    branchCreated,
    });

    applied.push({ file: filePath, plan, verified });
  }

  // ── Final report ─────────────────────────────────────────────────────────
  console.log();
  console.log();
  output.header('Summary');
  console.log();
  console.log(`  ${chalk.green('Applied:')} ${applied.length} file(s)`);
  console.log(`  ${chalk.gray('Skipped:')} ${skipped.length} file(s)`);

  if (applied.length > 0) {
    console.log();
    console.log(chalk.gray('  Applied:'));
    for (const a of applied) {
      const mark = a.verified.allResolved ? chalk.green('✓') : chalk.yellow('?');
      console.log(`    ${mark} ${a.file}`);
    }
    console.log();
    console.log(chalk.gray(`  Audit log: ${path.join(FIX_LOG_DIR, FIX_LOG_FILE)}`));
    if (branchCreated) {
      console.log(chalk.gray(`  Branch:    ${chalk.cyan(branchCreated)}`));
      console.log(chalk.gray(`  Switch back: git checkout ${initialBranch}`));
    } else {
      console.log(chalk.gray('  Review:    git diff'));
      console.log(chalk.gray('  Undo last: ship-safe undo'));
    }
  }

  // ── PR autopilot ─────────────────────────────────────────────────────────
  if (options.pr && applied.length > 0 && branchCreated) {
    console.log();
    await openPullRequest(root, branchCreated, applied);
  } else if (options.pr && !branchCreated) {
    console.log();
    console.log(chalk.yellow('  --pr requires --branch. Skipping PR creation.'));
  }

  if (skipped.length > 0 && applied.length === 0) {
    console.log();
    console.log(chalk.gray('  Tip: try a different provider with --provider, or run with --plan-only'));
    console.log(chalk.gray('  to inspect what would change.'));
  }

  console.log();
}

// =============================================================================
// PLAN GENERATION
// =============================================================================

// Generate a fix plan for a file. Returns either:
//   { ok: true, plan }                       — plan generated successfully
//   { ok: false, reason, raw, error }        — failed; reason is one of:
//       'file-read-failed' | 'provider-error' | 'parse-error' |
//       'llm-declined' | 'empty-response'
// Caller decides what to do with the failure (log, persist, skip).
async function generateBatchPlan(provider, root, filePath, fileFindings) {
  const abs = path.resolve(root, filePath);
  let content;
  try {
    content = fs.readFileSync(abs, 'utf8');
  } catch (err) {
    return { ok: false, reason: 'file-read-failed', error: err.message };
  }

  const fileForPrompt = windowFileContent(content, fileFindings[0]?.line);

  const findingsBlock = fileFindings.map((f, i) => `
${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${f.line ? ` (line ${f.line})` : ''}
   Rule: ${f.rule ?? 'N/A'}
   Description: ${f.description ?? 'N/A'}${f.fix ? `\n   Suggested fix: ${f.fix}` : ''}
`).join('');

  const systemPrompt = 'You are a security engineer. Produce precise code edits as structured JSON only. Never include prose, markdown, or code fences. Output a single JSON object.';

  const userPrompt = `Fix all of these security findings in a single file by producing one coordinated plan.

FILE: ${filePath}

FINDINGS (${fileFindings.length}):
${findingsBlock}

CURRENT FILE CONTENT:
\`\`\`
${fileForPrompt}
\`\`\`

OUTPUT this exact JSON shape:
{
  "summary": "one short sentence describing what you'll do across all findings",
  "files": [
    {
      "path": "${filePath}",
      "edits": [
        { "find": "EXACT verbatim substring", "replace": "new string", "reason": "addresses finding N" }
      ]
    }
  ],
  "risk": "low"
}

You MAY also include companion file changes (only these are allowed):
  - .env.example  — add placeholders for any secrets you moved to env vars
  - .gitignore    — add patterns for files that should not be committed

For companion files, use this shape (no "find" needed):
  { "path": ".env.example", "create": true, "content": "FULL FILE CONTENT" }
or to append:
  { "path": ".gitignore", "append": "PATTERN_TO_ADD\\n" }

RULES:
- Each "find" string must appear EXACTLY ONCE in the file. Include enough context (3+ lines) for uniqueness.
- "replace" must be the corrected code. Preserve indentation and surrounding style.
- Address each finding listed above with at least one edit (or explain in summary why a finding can't be mechanically fixed).
- Risk: "low" = mechanical, "medium" = behavior change, "high" = architectural. Use "high" sparingly.
- If you cannot produce a precise mechanical plan, return {"summary":"requires manual review","files":[],"risk":"high"}
- JSON only. No prose. No code fences.`;

  let response;
  try {
    response = await provider.complete(systemPrompt, userPrompt, {
      maxTokens: 3000,
      jsonMode:  true,
    });
  } catch (err) {
    return { ok: false, reason: 'provider-error', error: err.message };
  }

  if (!response || !response.trim()) {
    return { ok: false, reason: 'empty-response', raw: response ?? '' };
  }

  const plan = parseJsonLoose(response);
  if (!plan) {
    return { ok: false, reason: 'parse-error', raw: response };
  }
  if (!Array.isArray(plan.files) || plan.files.length === 0) {
    // The LLM returned valid JSON but explicitly declined to produce edits
    // (typically with summary like "requires manual review"). This is a
    // legitimate "I don't know" — not a bug.
    return { ok: false, reason: 'llm-declined', raw: response, plan };
  }

  return { ok: true, plan };
}

function parseJsonLoose(response) {
  if (!response) return null;
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
  if (!Array.isArray(plan.files) || plan.files.length === 0) {
    return { ok: false, reason: 'no files in plan' };
  }

  for (const f of plan.files) {
    if (!f.path) return { ok: false, reason: 'file entry missing path' };

    const rel       = f.path.replace(/\\/g, '/');
    const isSafeNew = SAFE_NEW_FILES.some(p => p.test(rel));

    // Block protected paths unless this is a known-safe companion file
    if (!isSafeNew && NEVER_EDIT.some(p => p.test(rel))) {
      return { ok: false, reason: `protected path: ${f.path}` };
    }

    const abs    = path.resolve(root, f.path);
    const exists = fs.existsSync(abs);

    // Companion file forms (create / append)
    if (f.create || f.append !== undefined) {
      if (!exists && !isSafeNew) {
        return { ok: false, reason: `cannot create new file at ${f.path}` };
      }
      if (f.create && typeof f.content !== 'string') {
        return { ok: false, reason: 'create entry missing content' };
      }
      if (f.append && typeof f.append !== 'string') {
        return { ok: false, reason: 'append must be a string' };
      }
      continue;
    }

    // Standard edit form
    if (!exists) return { ok: false, reason: `file not found: ${f.path}` };
    if (!Array.isArray(f.edits) || f.edits.length === 0) {
      return { ok: false, reason: `no edits for ${f.path}` };
    }

    const content = fs.readFileSync(abs, 'utf8');
    for (const e of f.edits) {
      if (typeof e.find !== 'string' || typeof e.replace !== 'string') {
        return { ok: false, reason: 'edit missing find/replace' };
      }
      if (e.find === e.replace) {
        return { ok: false, reason: 'edit is a no-op' };
      }
      const match = locateFindString(content, e.find);
      if (match.kind === 'missing') {
        return { ok: false, reason: `find string not present in ${f.path}` };
      }
      if (match.kind === 'ambiguous') {
        return { ok: false, reason: `find string is ambiguous (${match.count} matches) in ${f.path}` };
      }
      // Annotate the edit with the resolved match for use during apply
      e._resolvedFind = match.matched;
    }
  }
  return { ok: true };
}

// Try exact match first, then whitespace-normalized match if exact misses.
// Returns { kind: 'unique'|'ambiguous'|'missing', matched, count }
function locateFindString(haystack, needle) {
  const exact = countOccurrences(haystack, needle);
  if (exact === 1) return { kind: 'unique', matched: needle, count: 1 };
  if (exact > 1)   return { kind: 'ambiguous', matched: needle, count: exact };

  // Whitespace-tolerant fallback: collapse whitespace runs and try again
  const norm = (s) => s.replace(/[ \t]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();
  const needleNorm = norm(needle);
  if (!needleNorm) return { kind: 'missing', matched: null, count: 0 };

  // Walk the haystack and check if any window normalizes to the same string
  // To keep this cheap, only attempt when needle has at least one newline (likely a code block)
  const lines = haystack.split('\n');
  const needleLines = needleNorm.split('\n').length;
  let foundIdx = -1;
  let foundCount = 0;
  for (let i = 0; i + needleLines <= lines.length; i++) {
    const window = lines.slice(i, i + needleLines).join('\n');
    if (norm(window) === needleNorm) {
      foundIdx = i;
      foundCount++;
      if (foundCount > 1) break;
    }
  }
  if (foundCount === 1) {
    const matched = lines.slice(foundIdx, foundIdx + needleLines).join('\n');
    return { kind: 'unique', matched, count: 1 };
  }
  if (foundCount > 1) return { kind: 'ambiguous', matched: null, count: foundCount };
  return { kind: 'missing', matched: null, count: 0 };
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

function printPlan(plan, _root) {
  console.log();
  console.log(chalk.bold('      Plan:'));
  console.log(chalk.white(`        ${plan.summary || '(no summary)'}`));
  if (plan.risk) {
    const riskColor = plan.risk === 'low' ? chalk.green : plan.risk === 'medium' ? chalk.yellow : chalk.red;
    console.log(`        Risk: ${riskColor(plan.risk)}`);
  }
  console.log();

  for (const f of plan.files) {
    if (f.create) {
      console.log(chalk.bold(`      ${chalk.green('+ ')}${f.path} ${chalk.gray('(new file)')}`));
      printNewFilePreview(f.content);
      continue;
    }
    if (f.append !== undefined) {
      console.log(chalk.bold(`      ${f.path} ${chalk.gray('(append)')}`));
      for (const l of f.append.split('\n')) {
        if (l) console.log(chalk.green(`        + ${l}`));
      }
      continue;
    }
    console.log(chalk.bold(`      ${f.path}`));
    for (const e of f.edits) {
      console.log(chalk.gray(`        — ${e.reason || 'edit'}`));
      printDiff(e._resolvedFind || e.find, e.replace);
    }
  }
  console.log();
}

function printNewFilePreview(content) {
  const lines = content.split('\n');
  const max = 6;
  const shown = lines.slice(0, max);
  for (const l of shown) console.log(chalk.green(`        + ${l}`));
  if (lines.length > max) {
    console.log(chalk.gray(`        … +${lines.length - max} more line(s)`));
  }
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

  if (fileChange.create) {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, fileChange.content, 'utf8');
    return;
  }

  if (fileChange.append !== undefined) {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    const existing = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : '';
    // Avoid duplicate appends
    if (existing.includes(fileChange.append.trim())) return;
    const sep = existing && !existing.endsWith('\n') ? '\n' : '';
    fs.writeFileSync(abs, existing + sep + fileChange.append, 'utf8');
    return;
  }

  let content = fs.readFileSync(abs, 'utf8');
  for (const e of fileChange.edits) {
    const find = e._resolvedFind || e.find;
    if (!content.includes(find)) {
      throw new Error(`find string drifted in ${fileChange.path} (file changed mid-plan)`);
    }
    content = content.replace(find, e.replace);
  }
  fs.writeFileSync(abs, content, 'utf8');
}

// =============================================================================
// VERIFY
// =============================================================================

async function verifyFile(root, filePath, originalFindings) {
  try {
    const result = await auditCommand(root, { _agenticInner: true, deep: false, deps: false, noAi: true });
    const remaining = (result.findings ?? []).filter(f => f.file === filePath);

    let resolvedCount = 0;
    for (const orig of originalFindings) {
      const stillThere = remaining.some(f =>
        f.rule === orig.rule &&
        Math.abs((f.line ?? 0) - (orig.line ?? 0)) <= 2,
      );
      if (!stillThere) resolvedCount++;
    }

    return {
      allResolved:  resolvedCount === originalFindings.length,
      someResolved: resolvedCount > 0,
      resolvedCount,
    };
  } catch {
    return { allResolved: false, someResolved: false, resolvedCount: 0 };
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

// Append a structured record for every plan that didn't produce an apply.
// Useful for debugging regressions (the LLM said X, we rejected because Y).
function logFailure(root, entry) {
  const dir  = path.join(root, FIX_LOG_DIR);
  const file = path.join(dir, 'failures.jsonl');
  fs.mkdirSync(dir, { recursive: true });
  // Truncate raw response to keep the log readable
  const truncated = { ...entry };
  if (typeof truncated.raw === 'string' && truncated.raw.length > 4000) {
    truncated.raw = truncated.raw.slice(0, 4000) + '... [truncated]';
  }
  fs.appendFileSync(file, JSON.stringify(truncated) + '\n', 'utf8');
}

// Turn a structured plan failure into a user-facing one-liner.
function describePlanFailure(failure) {
  switch (failure.reason) {
    case 'file-read-failed':
      return { message: `Could not read source file: ${failure.error}`, reason: 'file-read-failed' };
    case 'provider-error':
      return { message: `LLM provider error — ${failure.error}`, reason: 'provider-error' };
    case 'empty-response':
      return { message: 'LLM returned an empty response (try again, or switch provider).', reason: 'empty-response' };
    case 'parse-error':
      return { message: 'LLM returned unparseable JSON — saved to .ship-safe/failures.jsonl for inspection.', reason: 'parse-error' };
    case 'llm-declined': {
      const summary = failure.plan?.summary;
      return { message: summary
        ? `LLM declined to fix this file — ${summary}`
        : 'LLM declined to fix this file (returned files=[] — needs manual review).',
        reason: 'llm-declined',
      };
    }
    default:
      return { message: `Plan failed: ${failure.reason}`, reason: failure.reason };
  }
}

// =============================================================================
// PR AUTOPILOT
// =============================================================================

async function openPullRequest(root, branch, applied) {
  const ghAvailable = (() => {
    try { execFileSync('gh', ['--version'], { stdio: 'pipe' }); return true; }
    catch { return false; }
  })();
  if (!ghAvailable) {
    console.log(chalk.yellow('  gh CLI not found. Install from https://cli.github.com to enable --pr.'));
    return;
  }

  // Push branch
  console.log(chalk.gray('  Pushing branch...'));
  try {
    execFileSync('git', ['push', '-u', 'origin', branch], { cwd: root, stdio: 'pipe' });
  } catch (err) {
    console.log(chalk.red(`  Push failed: ${err.message}`));
    return;
  }

  // Build PR body
  const totalFindings = applied.reduce((n, a) => n + (a.plan.files?.[0]?.edits?.length ?? 0), 0);
  const body = [
    '## Ship Safe — Security Fixes',
    '',
    `Applied ${applied.length} file(s) of fixes (${totalFindings} edit(s)) generated and verified by the Ship Safe agent.`,
    '',
    '### Files changed',
    ...applied.map(a => {
      const mark = a.verified.allResolved ? '✓' : '⚠';
      return `- ${mark} \`${a.file}\` — ${a.plan.summary || 'security fix'}`;
    }),
    '',
    '### Notes',
    '- Each fix was generated by an LLM and verified by re-scanning the file.',
    '- Files marked ⚠ have residual findings; review carefully before merging.',
    '- Full audit log: `.ship-safe/fixes.jsonl`',
    '',
    'Generated by `ship-safe agent`.',
  ].join('\n');

  const title = `Security fixes: ${applied.length} file(s)`;

  console.log(chalk.gray('  Opening PR...'));
  let prUrl = null;
  try {
    prUrl = execFileSync('gh', ['pr', 'create', '--title', title, '--body', body], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
    console.log(chalk.green(`  PR opened: ${prUrl}`));
  } catch (err) {
    console.log(chalk.red(`  PR creation failed: ${err.message}`));
    return;
  }

  // If we're running inside CI on a PR, leave a comment on the originating PR
  // pointing at our fix PR. Detect from common GitHub Actions env vars.
  const originPr = detectOriginPrNumber();
  if (originPr) {
    const note = [
      `### 🛡️ Ship Safe Agent — fix PR opened`,
      ``,
      `The Ship Safe agent found fixable security issues triggered by this PR and opened **${prUrl}** with proposed fixes.`,
      ``,
      `**Files changed:** ${applied.length}`,
      `**Total edits:** ${totalFindings}`,
      ``,
      `Review the fix PR and merge if it looks good.`,
    ].join('\n');
    try {
      execFileSync('gh', ['pr', 'comment', String(originPr), '--body', note], { cwd: root, stdio: 'pipe' });
      console.log(chalk.green(`  Commented on origin PR #${originPr}`));
    } catch (err) {
      console.log(chalk.yellow(`  Could not comment on origin PR #${originPr}: ${err.message}`));
    }
  }
}

// Detect the PR number that triggered this CI run. Supports GitHub Actions'
// pull_request and pull_request_target events. Returns null when not in CI
// or when the event isn't a PR event.
function detectOriginPrNumber() {
  // Explicit override (handy for testing or non-GHA CI providers)
  if (process.env.SHIP_SAFE_ORIGIN_PR) return process.env.SHIP_SAFE_ORIGIN_PR;

  // GitHub Actions: GITHUB_REF looks like "refs/pull/<n>/merge" or "refs/pull/<n>/head"
  const ref = process.env.GITHUB_REF || '';
  const m = ref.match(/^refs\/pull\/(\d+)\//);
  if (m) return m[1];

  // GitHub Actions PR event payload also exposes the number via GITHUB_EVENT_PATH
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    try {
      const payload = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
      if (payload?.pull_request?.number) return String(payload.pull_request.number);
      if (payload?.number) return String(payload.number);
    } catch { /* malformed event payload */ }
  }

  return null;
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

function getCurrentBranch(root) {
  try {
    return execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root, stdio: 'pipe' }).toString().trim();
  } catch {
    return null;
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

// Plan decision prompt with [e]dit support: opens the plan in $EDITOR for the
// user to tweak, then re-validates. Loops until accept/skip/quit.
async function promptDecision(plan, root) {
  while (true) {
    const raw = (await prompt(chalk.cyan('      [a]ccept  [s]kip  [e]dit  [q]uit > '))).trim().toLowerCase();
    if (['a', 'accept', 'y', 'yes'].includes(raw)) return 'a';
    if (['s', 'skip', 'n', 'no'].includes(raw))    return 's';
    if (['q', 'quit'].includes(raw))               return 'q';
    if (['e', 'edit'].includes(raw)) {
      const edited = await editPlanInEditor(plan, root);
      if (!edited) {
        console.log(chalk.yellow('      Edit cancelled — keeping original plan.'));
      } else {
        // Mutate plan in place so the caller's reference picks up the changes
        plan.summary = edited.summary;
        plan.files   = edited.files;
        plan.risk    = edited.risk;
        // Re-validate then re-show
        const validation = validatePlan(root, plan);
        if (!validation.ok) {
          console.log(chalk.red(`      Edited plan invalid: ${validation.reason}`));
          console.log(chalk.gray('      Returning to prompt — try editing again, or skip.'));
          continue;
        }
        printPlan(plan, root);
      }
      // Loop back and re-prompt
      continue;
    }
    console.log(chalk.gray('      Unknown choice. Type a, s, e, or q.'));
  }
}

async function editPlanInEditor(plan, root) {
  const editor = process.env.EDITOR || process.env.VISUAL || 'vi';
  const tmpFile = path.join(root, '.ship-safe', `plan-edit-${Date.now()}.json`);
  fs.mkdirSync(path.dirname(tmpFile), { recursive: true });
  // Strip _resolvedFind annotations before showing — they're internal
  const exportable = JSON.parse(JSON.stringify(plan, (k, v) => k === '_resolvedFind' ? undefined : v));
  fs.writeFileSync(tmpFile, JSON.stringify(exportable, null, 2), 'utf8');

  try {
    execFileSync(editor, [tmpFile], { stdio: 'inherit' });
    const updated = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
    fs.unlinkSync(tmpFile);
    return updated;
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch { /* best effort */ }
    console.log(chalk.red(`      Editor failed: ${err.message}`));
    return null;
  }
}
