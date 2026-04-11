/**
 * Scan Skill Command
 * ===================
 *
 * Downloads and analyzes an AI agent skill before installation.
 * Checks for malicious patterns, permission abuse, typosquatting,
 * and known threat intelligence indicators.
 *
 * USAGE:
 *   ship-safe scan-skill <url>          Analyze a skill from URL
 *   ship-safe scan-skill <path>         Analyze a local skill file
 *   ship-safe scan-skill . --all        Scan all skills in openclaw.json
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { createHash } from 'crypto';
import * as output from '../utils/output.js';
import { ThreatIntel } from '../utils/threat-intel.js';

// =============================================================================
// HERMES SKILL FRONTMATTER PATTERNS (Track D — cross-skill/tool binding)
// =============================================================================

// Built-in tool registries that skills may reference.
// Ship Safe tools are added lazily in checkHermesFrontmatter() to avoid
// loading hermes-tool-registry.js (and its crypto import) on every invocation.
const KNOWN_TOOL_REGISTRIES = {
  // Common Hermes community tools (names only — no handler)
  'web_search': 'hermes-community',
  'web_browser': 'hermes-community',
  'file_read': 'hermes-community',
  'file_write': 'hermes-community',
  'code_execute': 'hermes-community',
  'github_api': 'hermes-community',
  'memory_store': 'hermes-community',
  'memory_retrieve': 'hermes-community',
};

// Hermes-specific patterns to check in skill markdown/frontmatter
const HERMES_SKILL_PATTERNS = [
  {
    name: 'Hermes: XML tool_call injection',
    regex: /<tool_call>[\s\S]{0,300}<\/tool_call>/gi,
    severity: 'critical',
    note: 'Skill body contains a <tool_call> block — will be executed by Hermes agents that load this skill.',
  },
  {
    name: 'Hermes: function_calls injection',
    regex: /<function_calls>[\s\S]{0,300}<\/function_calls>/gi,
    severity: 'critical',
    note: 'Skill body contains a <function_calls> block — classic Hermes function-call injection.',
  },
  {
    name: 'Hermes: Forced tool invocation instruction',
    regex: /(?:you\s+must\s+(?:call|invoke|use)\s+(?:the\s+)?tool|always\s+(?:call|invoke|run)\s+(?:the\s+)?(?:tool|function)|tool\s+MUST\s+be\s+(?:called|invoked|used))/gi,
    severity: 'high',
    note: 'Skill instructs agent to call a specific tool unconditionally — bypasses agent autonomy.',
  },
  {
    name: 'Hermes: Plan/goal hijacking',
    regex: /(?:update\s+(?:your\s+)?(?:goal|plan|objective)\s+to|change\s+(?:your\s+)?(?:goal|plan|objective)|your\s+(?:new\s+)?(?:goal|plan|primary\s+objective)\s+(?:is|should\s+be))/gi,
    severity: 'critical',
    note: 'Skill attempts to overwrite the agent\'s goal or plan state — ASI-01 Goal Hijacking.',
  },
  {
    name: 'Hermes: Memory layer write instruction',
    regex: /(?:write\s+(?:this|the\s+following)\s+to\s+(?:memory|episodic|semantic|working)\s+memory|store\s+(?:this|the\s+following)\s+in\s+(?:memory|episodic|semantic))/gi,
    severity: 'high',
    note: 'Skill instructs agent to write attacker-controlled data to memory — ASI-06 Memory Poisoning.',
  },
];

// =============================================================================
// POPULAR SKILL NAMES (for typosquatting detection)
// =============================================================================

const POPULAR_SKILLS = [
  'web-search', 'web-browser', 'file-manager', 'code-runner',
  'git-helper', 'database-query', 'api-tester', 'image-gen',
  'text-to-speech', 'pdf-reader', 'email-sender', 'slack-bot',
  'github-helper', 'docker-manager', 'kubernetes-helper',
  'aws-helper', 'terraform-helper', 'memory-store',
  'calculator', 'translator', 'summarizer', 'code-review',
];

// =============================================================================
// MALICIOUS PATTERNS
// =============================================================================

const SKILL_PATTERNS = [
  { name: 'Shell execution', regex: /(?:child_process|exec|spawn|execSync|execFile|os\.system|subprocess|shell_exec|system\()/gi, severity: 'critical' },
  { name: 'Outbound HTTP to non-localhost', regex: /(?:fetch|axios|http\.get|requests\.get|urllib|wget|curl)\s*\(\s*['"`]https?:\/\/(?!(?:localhost|127\.0\.0\.1|::1))/gi, severity: 'high' },
  { name: 'Data exfiltration service', regex: /(?:webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|ngrok\.app|burpcollaborator|interact\.sh)/gi, severity: 'critical' },
  { name: 'Environment variable access', regex: /(?:process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv)/gi, severity: 'medium' },
  { name: 'File system write', regex: /(?:fs\.writeFile|fs\.appendFile|writeFileSync|open\(.+['"]w['"]|fwrite|file_put_contents)/gi, severity: 'medium' },
  { name: 'Base64 decode + execute', regex: /(?:atob|Buffer\.from|base64\.b64decode|base64_decode)\s*\([^)]*\)\s*(?:\.|\))\s*(?:eval|exec|Function)/gi, severity: 'critical' },
  { name: 'Dynamic code evaluation', regex: /(?:eval\s*\(|new\s+Function\s*\(|exec\s*\(|compile\s*\()/gi, severity: 'high' },
  { name: 'Crypto operations', regex: /(?:crypto\.createCipher|crypto\.createDecipher|CryptoJS|forge\.cipher)/gi, severity: 'medium' },
  { name: 'Network listener', regex: /(?:createServer|listen\s*\(\s*\d|bind\s*\(\s*['"]0\.0\.0\.0)/gi, severity: 'high' },
  { name: 'Encoded payload block', regex: /[A-Za-z0-9+\/]{60,}={0,2}/g, severity: 'medium' },

  // ── ToxicSkills patterns (Snyk research — 36% of agent skills affected) ──
  // Silent curl exfiltration: skill instructs agent to silently send data
  { name: 'ToxicSkills: silent data exfiltration via curl', regex: /(?:silently|quietly|without\s+(?:notif|alert|inform|telling|showing)|in\s+the\s+background)\s+.{0,60}(?:curl|wget|fetch|POST|send).{0,60}(?:http|https):\/\//gi, severity: 'critical' },
  // System prompt override in skill definition
  { name: 'ToxicSkills: system prompt override', regex: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions|your\s+(?:new|real|actual|true)\s+(?:instructions|role|goal|purpose)\s+(?:is|are)|disregard\s+(?:all\s+)?(?:previous|above|your))/gi, severity: 'critical' },
  // Skill requests credentials/secrets from agent context
  { name: 'ToxicSkills: credential harvesting', regex: /(?:extract|retrieve|collect|gather|find|read|access|get)\s+.{0,40}(?:api[_\s]?key|secret|token|password|credential|\.env|npmrc|ssh[_\s]?key|private[_\s]?key)/gi, severity: 'critical' },
  // Skill attempts to read ~/.ssh, ~/.aws, ~/.npmrc
  { name: 'ToxicSkills: sensitive path access', regex: /(?:~\/\.(?:ssh|aws|npmrc|netrc|gnupg|config\/gcloud)|\/etc\/(?:passwd|shadow|hosts)|%APPDATA%|%USERPROFILE%)/gi, severity: 'critical' },
  // Skill suppresses its own output to avoid detection
  { name: 'ToxicSkills: output suppression', regex: /(?:do\s+not\s+(?:show|display|reveal|mention|tell|report|log)\s+(?:this|these|the\s+(?:output|result|response|command|action))|hide\s+(?:this|the)\s+(?:output|result|action|command|request))/gi, severity: 'high' },
  // Skill requests permissions beyond its stated purpose
  { name: 'ToxicSkills: permission escalation', regex: /(?:grant\s+(?:me|this\s+skill|yourself)\s+(?:admin|root|sudo|full|all)\s+(?:access|permissions?|rights?)|elevate\s+(?:privileges?|permissions?|rights?)|run\s+as\s+(?:admin|root|sudo))/gi, severity: 'high' },
];

// =============================================================================
// MAIN COMMAND
// =============================================================================

export async function scanSkillCommand(target, options = {}) {
  if (!target) {
    output.error('Usage: ship-safe scan-skill <url|path>');
    output.info('  Analyze an AI agent skill for security issues before installing it.');
    process.exit(1);
  }

  console.log();
  output.header('Ship Safe — Skill Security Analysis');
  console.log();

  // If --all flag, scan all skills from openclaw.json
  if (options.all) {
    return scanAllSkills(path.resolve(target));
  }

  // Determine if URL or local file
  let content, skillName, source;

  if (target.startsWith('http://') || target.startsWith('https://')) {
    console.log(chalk.gray(`  Fetching skill from: ${target}`));
    try {
      const response = await fetch(target);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      content = await response.text();
      skillName = new URL(target).pathname.split('/').pop() || 'remote-skill';
      source = target;
    } catch (err) {
      output.error(`Failed to fetch skill: ${err.message}`);
      process.exit(1);
    }
  } else {
    const filePath = path.resolve(target);
    if (!fs.existsSync(filePath)) {
      output.error(`File not found: ${filePath}`);
      process.exit(1);
    }
    content = fs.readFileSync(filePath, 'utf-8');
    skillName = path.basename(filePath);
    source = filePath;
  }

  console.log(chalk.gray(`  Skill: ${skillName}`));
  console.log(chalk.gray(`  Size: ${content.length} bytes`));
  console.log();

  const findings = await analyzeSkill(content, skillName, source);

  if (options.json) {
    console.log(JSON.stringify({ skill: skillName, source, findings, summary: getSummary(findings) }, null, 2));
    return;
  }

  printSkillFindings(findings, skillName);
}

// =============================================================================
// SKILL ANALYSIS
// =============================================================================

async function analyzeSkill(content, skillName, source) {
  const findings = [];

  // 1. Static pattern analysis
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of SKILL_PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(line)) {
        findings.push({
          check: 'static-analysis',
          name: pattern.name,
          severity: pattern.severity,
          line: i + 1,
          matched: line.trim().slice(0, 100),
        });
      }
    }
  }

  // 2. Permission manifest audit (if JSON)
  try {
    const manifest = JSON.parse(content);
    if (manifest.permissions) {
      const dangerousPerm = [/\bshell\b/i, /\bexec\b/i, /\bsystem\b/i, /\badmin\b/i, /\broot\b/i,
        /filesystem\s*:\s*(write|read-write)/i, /network\s*:\s*(unrestricted|all)/i,
        /^filesystem$/i, /^network$/i];
      for (const perm of (Array.isArray(manifest.permissions) ? manifest.permissions : [])) {
        const permStr = typeof perm === 'string' ? perm : perm.name || '';
        if (dangerousPerm.some(p => p.test(permStr))) {
          findings.push({
            check: 'permission-audit',
            name: `Dangerous permission: ${permStr}`,
            severity: 'high',
            line: 0,
            matched: `permissions: [${permStr}]`,
          });
        }
      }
    }

    // Check for suspicious fields
    if (manifest.postInstall || manifest.postinstall) {
      findings.push({
        check: 'permission-audit',
        name: 'Post-install script defined',
        severity: 'high',
        line: 0,
        matched: 'postInstall hook detected',
      });
    }
  } catch { /* Not JSON, skip manifest audit */ }

  // 3. Typosquatting detection
  const typosquatResult = checkTyposquatting(skillName);
  if (typosquatResult) {
    findings.push({
      check: 'typosquatting',
      name: `Possible typosquat of "${typosquatResult.target}"`,
      severity: 'high',
      line: 0,
      matched: `Levenshtein distance: ${typosquatResult.distance} from "${typosquatResult.target}"`,
    });
  }

  // 4. Threat intel hash check
  const hash = createHash('sha256').update(content).digest('hex');
  const intelMatch = ThreatIntel.lookupHash(hash);
  if (intelMatch) {
    findings.push({
      check: 'threat-intel',
      name: `Known malicious skill: ${intelMatch.name}`,
      severity: 'critical',
      line: 0,
      matched: `SHA-256: ${hash} — ${intelMatch.description}`,
    });
  }

  // 5. Threat intel signature check
  const sigMatches = ThreatIntel.matchSignatures(content);
  for (const sig of sigMatches) {
    findings.push({
      check: 'threat-intel',
      name: `Threat intel signature match: ${sig.description}`,
      severity: sig.severity || 'critical',
      line: 0,
      matched: `Pattern: ${sig.pattern}`,
    });
  }

  // 6. Hermes-specific: frontmatter tool binding + permission drift validation
  findings.push(...(await checkHermesFrontmatter(content)));

  // 7. Hermes-specific: function-call injection and goal hijacking in body
  findings.push(...checkHermesBodyPatterns(content, lines));

  return findings;
}

// =============================================================================
// HERMES FRONTMATTER VALIDATION (Track D)
// =============================================================================

/**
 * Parse YAML frontmatter block (between --- delimiters) from markdown skill.
 * Returns a plain object with string/array values; null if no frontmatter.
 */
function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;

  const fm = {};
  const yamlBlock = match[1];

  for (const line of yamlBlock.split('\n')) {
    const kv = line.match(/^(\w[\w-]*):\s*(.*)$/);
    if (!kv) continue;
    const [, key, rawVal] = kv;
    const val = rawVal.trim();

    if (val.startsWith('[') && val.endsWith(']')) {
      // Inline array: [a, b, c]
      fm[key] = val.slice(1, -1).split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean);
    } else {
      fm[key] = val.replace(/^['"]|['"]$/g, '');
    }
  }

  // Collect multi-line list values (indented - items)
  const listRe = /^(\w[\w-]*):\s*\n((?:\s+-\s+.+\n?)+)/gm;
  let m;
  while ((m = listRe.exec(yamlBlock)) !== null) {
    const [, key, block] = m;
    fm[key] = block.match(/-\s+(.+)/g)?.map(s => s.replace(/^-\s+/, '').replace(/['"]/g, '').trim()) ?? [];
  }

  return fm;
}

let _hermesToolsLoaded = false;
async function ensureHermesToolsLoaded() {
  if (_hermesToolsLoaded) return;
  try {
    const { HERMES_TOOLS } = await import('../utils/hermes-tool-registry.js');
    for (const t of HERMES_TOOLS) KNOWN_TOOL_REGISTRIES[t.name] = 'ship-safe';
  } catch { /* non-fatal — registry unavailable */ }
  _hermesToolsLoaded = true;
}

async function checkHermesFrontmatter(content) {
  await ensureHermesToolsLoaded();
  const findings = [];
  const fm = parseFrontmatter(content);

  // Not a markdown skill with frontmatter — skip
  if (!fm) return findings;

  // ── Check: missing permissions field ──────────────────────────────────────
  if (!fm.permissions) {
    findings.push({
      check: 'hermes-frontmatter',
      name: 'Hermes: Skill missing permissions field (ASI-02 Excessive Agency)',
      severity: 'medium',
      line: 0,
      matched: 'No permissions: field in frontmatter — skill may be granted more access than intended',
    });
  } else {
    // ── Check: wildcard permissions ──────────────────────────────────────────
    const perms = Array.isArray(fm.permissions) ? fm.permissions : [fm.permissions];
    const wildcards = perms.filter(p => /^\*$|^all$|^any$/i.test(String(p)));
    if (wildcards.length > 0) {
      findings.push({
        check: 'hermes-frontmatter',
        name: 'Hermes: Wildcard permissions (* / all) — excessive agency (ASI-02)',
        severity: 'high',
        line: 0,
        matched: `permissions: [${wildcards.join(', ')}]`,
      });
    }

    // ── Check: dangerous explicit permissions ────────────────────────────────
    // Match whole-word or exact qualified values — don't fire on "filesystem: read-only"
    const dangerousPatterns = [
      /\bshell\b/i, /\bexec\b/i, /\bsystem\b/i, /\badmin\b/i, /\broot\b/i, /\bsudo\b/i,
      /filesystem\s*:\s*write/i, /filesystem\s*:\s*read-write/i,
      /network\s*:\s*unrestricted/i, /network\s*:\s*all/i,
      /^filesystem$/i, /^network$/i,  // bare "filesystem" or "network" without qualifier is ambiguous → flag
    ];
    for (const perm of perms) {
      if (dangerousPatterns.some(p => p.test(String(perm)))) {
        findings.push({
          check: 'hermes-frontmatter',
          name: `Hermes: Dangerous permission declared: ${perm}`,
          severity: 'high',
          line: 0,
          matched: `permissions: [${perm}]`,
        });
      }
    }
  }

  // ── Check: missing version pin ────────────────────────────────────────────
  if (!fm.version) {
    findings.push({
      check: 'hermes-frontmatter',
      name: 'Hermes: Skill missing version field — unpinned skill (ASI-10 Supply Chain)',
      severity: 'medium',
      line: 0,
      matched: 'No version: field in frontmatter — skill version drift cannot be detected',
    });
  }

  // ── Check: cross-skill tool binding validation ────────────────────────────
  const tools = Array.isArray(fm.tools) ? fm.tools : fm.tools ? [fm.tools] : [];
  for (const toolName of tools) {
    if (!KNOWN_TOOL_REGISTRIES[toolName]) {
      findings.push({
        check: 'hermes-tool-binding',
        name: `Hermes: Unresolvable tool reference: "${toolName}"`,
        severity: 'high',
        line: 0,
        matched: `tools: [${toolName}] — not found in any known tool registry. May cause silent failures or late-binding substitution.`,
      });
    }
  }

  // ── Check: tools declared but no permissions field ────────────────────────
  if (tools.length > 0 && !fm.permissions) {
    findings.push({
      check: 'hermes-tool-binding',
      name: 'Hermes: Skill declares tools without permissions (permission drift)',
      severity: 'high',
      line: 0,
      matched: `tools: [${tools.join(', ')}] declared but no permissions: field — skill runs with ambient agent permissions`,
    });
  }

  return findings;
}

function checkHermesBodyPatterns(content, lines) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of HERMES_SKILL_PATTERNS) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(line)) {
        findings.push({
          check: 'hermes-injection',
          name: pattern.name,
          severity: pattern.severity,
          line: i + 1,
          matched: line.trim().slice(0, 100),
        });
      }
    }
  }

  // Multi-line checks for <tool_call> blocks that span lines
  for (const pattern of HERMES_SKILL_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const match = pattern.regex.exec(content);
    if (match) {
      // Avoid duplicate if already caught line-by-line
      const alreadyFound = findings.some(f => f.name === pattern.name);
      if (!alreadyFound) {
        findings.push({
          check: 'hermes-injection',
          name: pattern.name,
          severity: pattern.severity,
          line: 0,
          matched: match[0].slice(0, 100),
        });
      }
    }
  }

  return findings;
}

// =============================================================================
// TYPOSQUATTING
// =============================================================================

function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i - 1] === a[j - 1]
        ? matrix[i - 1][j - 1]
        : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

function checkTyposquatting(skillName) {
  const name = skillName.toLowerCase().replace(/[^a-z0-9-]/g, '');
  for (const popular of POPULAR_SKILLS) {
    const distance = levenshtein(name, popular);
    if (distance > 0 && distance <= 2 && name !== popular) {
      return { target: popular, distance };
    }
  }
  return null;
}

// =============================================================================
// SCAN ALL SKILLS IN PROJECT
// =============================================================================

async function scanAllSkills(rootPath) {
  const openclawPath = path.join(rootPath, 'openclaw.json');
  if (!fs.existsSync(openclawPath)) {
    output.warning('No openclaw.json found. Nothing to scan.');
    return;
  }

  try {
    const config = JSON.parse(fs.readFileSync(openclawPath, 'utf-8'));
    const skills = config.skills || [];

    if (skills.length === 0) {
      output.info('No skills defined in openclaw.json.');
      return;
    }

    console.log(chalk.gray(`  Found ${skills.length} skill(s) in openclaw.json`));
    console.log();

    for (const skill of skills) {
      const url = typeof skill === 'string' ? skill : skill.source || skill.url;
      const name = typeof skill === 'string' ? skill : skill.name || 'unnamed';

      if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
        console.log(chalk.cyan(`  Scanning skill: ${name}`));
        try {
          const response = await fetch(url);
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const content = await response.text();
          const findings = await analyzeSkill(content, name, url);
          if (findings.length > 0) {
            printSkillFindings(findings, name);
          } else {
            console.log(chalk.green(`    ✔ Clean`));
          }
        } catch (err) {
          console.log(chalk.yellow(`    ⚠ Could not fetch: ${err.message}`));
        }
      } else {
        console.log(chalk.gray(`    → ${name}: local skill (static analysis only)`));
      }
      console.log();
    }
  } catch (err) {
    output.error(`Failed to parse openclaw.json: ${err.message}`);
  }
}

// =============================================================================
// OUTPUT
// =============================================================================

function printSkillFindings(findings, skillName) {
  const summary = getSummary(findings);

  if (findings.length === 0) {
    console.log(chalk.green.bold(`  ✔ ${skillName}: No security issues found.`));
    console.log();
    return;
  }

  console.log(chalk.red.bold(`  ✘ ${skillName}: ${findings.length} issue(s) found`));
  console.log();

  for (const f of findings) {
    const sevColor = f.severity === 'critical' ? chalk.red.bold
      : f.severity === 'high' ? chalk.yellow
      : chalk.blue;

    console.log(`    ${sevColor(`[${f.severity.toUpperCase()}]`)} ${chalk.white(f.name)}`);
    if (f.line > 0) console.log(chalk.gray(`      Line ${f.line}: ${f.matched}`));
    else if (f.matched) console.log(chalk.gray(`      ${f.matched}`));
  }
  console.log();

  if (summary.critical > 0) {
    console.log(chalk.red.bold('    ⚠ DO NOT INSTALL this skill — critical security issues detected.'));
    console.log();
  }
}

function getSummary(findings) {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
  };
}
