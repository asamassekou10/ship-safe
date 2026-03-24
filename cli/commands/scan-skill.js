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

  const findings = analyzeSkill(content, skillName, source);

  if (options.json) {
    console.log(JSON.stringify({ skill: skillName, source, findings, summary: getSummary(findings) }, null, 2));
    return;
  }

  printSkillFindings(findings, skillName);
}

// =============================================================================
// SKILL ANALYSIS
// =============================================================================

function analyzeSkill(content, skillName, source) {
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
      const dangerous = ['shell', 'exec', 'system', 'network', 'filesystem', 'admin', 'root'];
      for (const perm of (Array.isArray(manifest.permissions) ? manifest.permissions : [])) {
        const permStr = typeof perm === 'string' ? perm : perm.name || '';
        if (dangerous.some(d => permStr.toLowerCase().includes(d))) {
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
          const findings = analyzeSkill(content, name, url);
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
