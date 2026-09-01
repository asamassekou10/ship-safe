/**
 * Rotate Command
 * ==============
 *
 * Guides you through revoking and rotating exposed secrets.
 * For each secret type found, opens the provider's key management page
 * and shows step-by-step revocation instructions.
 *
 * For GitHub tokens, calls the GitHub credentials revocation API directly
 * (no auth required — designed for reporting exposed credentials).
 *
 * USAGE:
 *   ship-safe rotate .                         Scan local files and rotate found secrets
 *   ship-safe rotate . --provider github        Only rotate GitHub tokens
 *   ship-safe rotate --plan rotation-plan.json  Execute a plan from shipsafe.sh/rotate
 *
 * RECOMMENDED ORDER:
 *   1. ship-safe rotate      ← revoke the key so it can't be used
 *   2. ship-safe remediate   ← fix source code
 *   3. Commit fixed files
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { execFileSync } from 'child_process';
import chalk from 'chalk';
import ora from 'ora';
import fg from 'fast-glob';
import {
  SECRET_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  TEST_FILE_PATTERNS,
  MAX_FILE_SIZE
} from '../utils/patterns.js';
import { isHighEntropyMatch } from '../utils/entropy.js';
import * as output from '../utils/output.js';
import { fetchSafeUrl } from '../utils/remote-fetch.js';

// =============================================================================
// PROVIDER ROTATION INFO
// =============================================================================

/**
 * Maps pattern names to provider revocation info.
 * url:          Where to revoke/rotate the key
 * instructions: Exact steps to follow
 * apiRevoke:    If true, attempt programmatic revocation via API
 * providerKey:  Short identifier for --provider flag filtering
 */
const PROVIDER_INFO = {
  // AI Providers
  'OpenAI API Key': {
    provider: 'openai',
    name: 'OpenAI',
    url: 'https://platform.openai.com/api-keys',
    instructions: [
      'Go to platform.openai.com/api-keys',
      'Find the compromised key (starts with sk-...)',
      'Click the trash icon to revoke it',
      'Create a new key and update your .env'
    ]
  },
  'OpenAI Project Key': {
    provider: 'openai',
    name: 'OpenAI',
    url: 'https://platform.openai.com/api-keys',
    instructions: [
      'Go to platform.openai.com/api-keys',
      'Find the compromised project key',
      'Revoke it and create a new one'
    ]
  },
  'Anthropic API Key': {
    provider: 'anthropic',
    name: 'Anthropic',
    url: 'https://console.anthropic.com/settings/keys',
    instructions: [
      'Go to console.anthropic.com/settings/keys',
      'Delete the compromised key',
      'Create a new key and update your .env'
    ]
  },
  'Google AI (Gemini) API Key': {
    provider: 'google',
    name: 'Google AI',
    url: 'https://aistudio.google.com/app/apikey',
    instructions: [
      'Go to aistudio.google.com/app/apikey',
      'Delete the compromised key',
      'Create a new one and update your .env'
    ]
  },
  'Replicate API Token': {
    provider: 'replicate',
    name: 'Replicate',
    url: 'https://replicate.com/account/api-tokens',
    instructions: [
      'Go to replicate.com/account/api-tokens',
      'Delete the compromised token',
      'Create a new one and update your .env'
    ]
  },
  'Hugging Face Token': {
    provider: 'huggingface',
    name: 'Hugging Face',
    url: 'https://huggingface.co/settings/tokens',
    instructions: [
      'Go to huggingface.co/settings/tokens',
      'Revoke the compromised token',
      'Create a new one and update your .env'
    ]
  },
  'Groq API Key': {
    provider: 'groq',
    name: 'Groq',
    url: 'https://console.groq.com/keys',
    instructions: [
      'Go to console.groq.com/keys',
      'Delete the compromised key',
      'Create a new one and update your .env'
    ]
  },

  // GitHub — API revocation supported
  'GitHub Personal Access Token': {
    provider: 'github',
    name: 'GitHub',
    url: 'https://github.com/settings/tokens',
    apiRevoke: true,
    instructions: [
      'Attempting API revocation...',
      'Then go to github.com/settings/tokens to confirm it\'s revoked',
      'Create a new token with minimal required scopes'
    ]
  },
  'GitHub OAuth Token': {
    provider: 'github',
    name: 'GitHub',
    url: 'https://github.com/settings/tokens',
    apiRevoke: true,
    instructions: [
      'Attempting API revocation...',
      'Verify at github.com/settings/applications'
    ]
  },
  'GitHub App Token': {
    provider: 'github',
    name: 'GitHub',
    url: 'https://github.com/settings/tokens',
    apiRevoke: true,
    instructions: [
      'Attempting API revocation...',
      'Verify revocation at github.com/settings/tokens'
    ]
  },
  'GitHub Fine-Grained PAT': {
    provider: 'github',
    name: 'GitHub',
    url: 'https://github.com/settings/personal-access-tokens',
    apiRevoke: true,
    instructions: [
      'Attempting API revocation...',
      'Verify at github.com/settings/personal-access-tokens'
    ]
  },

  // Payments
  'Stripe Live Secret Key': {
    provider: 'stripe',
    name: 'Stripe',
    url: 'https://dashboard.stripe.com/apikeys',
    instructions: [
      'Go to dashboard.stripe.com/apikeys',
      'Click the "..." menu next to the compromised key',
      'Select "Roll key" — this revokes old and creates new simultaneously',
      'Update the new key in your .env immediately'
    ]
  },
  'Stripe Test Secret Key': {
    provider: 'stripe',
    name: 'Stripe',
    url: 'https://dashboard.stripe.com/test/apikeys',
    instructions: [
      'Go to dashboard.stripe.com/test/apikeys',
      'Roll the test key',
      'Update your .env'
    ]
  },
  'Stripe Webhook Secret': {
    provider: 'stripe',
    name: 'Stripe',
    url: 'https://dashboard.stripe.com/webhooks',
    instructions: [
      'Go to dashboard.stripe.com/webhooks',
      'Select the webhook endpoint',
      'Rotate the signing secret',
      'Update STRIPE_WEBHOOK_SECRET in your .env'
    ]
  },

  // Cloud & Hosting
  'AWS Access Key ID': {
    provider: 'aws',
    name: 'AWS',
    url: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    instructions: [
      'Run: aws iam delete-access-key --access-key-id <YOUR_KEY_ID>',
      'Then: aws iam create-access-key --user-name <YOUR_USER>',
      'Or go to console.aws.amazon.com → IAM → Security credentials',
      'Delete the compromised key and create a new one',
      'Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your .env'
    ]
  },
  'AWS Secret Access Key': {
    provider: 'aws',
    name: 'AWS',
    url: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    instructions: [
      'Deactivate key: aws iam update-access-key --status Inactive --access-key-id <ID>',
      'Delete key: aws iam delete-access-key --access-key-id <ID>',
      'Create new: aws iam create-access-key --user-name <USER>',
      'Update .env with new credentials'
    ]
  },
  'Vercel Token': {
    provider: 'vercel',
    name: 'Vercel',
    url: 'https://vercel.com/account/tokens',
    instructions: [
      'Go to vercel.com/account/tokens',
      'Delete the compromised token',
      'Create a new one and update your .env'
    ]
  },
  'NPM Token': {
    provider: 'npm',
    name: 'npm',
    url: 'https://www.npmjs.com/settings/~/tokens',
    instructions: [
      'Go to npmjs.com/settings/~/tokens',
      'Revoke the compromised token',
      'Create a new granular access token'
    ]
  },
  'Netlify Personal Access Token': {
    provider: 'netlify',
    name: 'Netlify',
    url: 'https://app.netlify.com/user/applications#personal-access-tokens',
    instructions: [
      'Go to app.netlify.com/user/applications',
      'Revoke the compromised token',
      'Create a new one and update your .env'
    ]
  },
  'DigitalOcean Token': {
    provider: 'digitalocean',
    name: 'DigitalOcean',
    url: 'https://cloud.digitalocean.com/account/api/tokens',
    instructions: [
      'Go to cloud.digitalocean.com/account/api/tokens',
      'Delete the compromised token',
      'Create a new one and update your .env'
    ]
  },

  // Communication
  'Slack Token': {
    provider: 'slack',
    name: 'Slack',
    url: 'https://api.slack.com/apps',
    instructions: [
      'Go to api.slack.com/apps',
      'Select your app → OAuth & Permissions',
      'Revoke all tokens under "OAuth Tokens for Your Workspace"',
      'Reinstall the app to get fresh tokens'
    ]
  },
  'Slack Webhook': {
    provider: 'slack',
    name: 'Slack',
    url: 'https://api.slack.com/apps',
    instructions: [
      'Go to api.slack.com/apps → your app → Incoming Webhooks',
      'Revoke the compromised webhook URL',
      'Create a new webhook for the channel'
    ]
  },
  'Discord Webhook': {
    provider: 'discord',
    name: 'Discord',
    url: 'https://discord.com/channels/@me',
    instructions: [
      'Go to the Discord channel → Edit Channel → Integrations → Webhooks',
      'Delete the compromised webhook',
      'Create a new one and update your .env'
    ]
  },

  // Email
  'SendGrid API Key': {
    provider: 'sendgrid',
    name: 'SendGrid',
    url: 'https://app.sendgrid.com/settings/api_keys',
    instructions: [
      'Go to app.sendgrid.com/settings/api_keys',
      'Revoke the compromised key',
      'Create a new key with minimum required permissions'
    ]
  },
  'Resend API Key': {
    provider: 'resend',
    name: 'Resend',
    url: 'https://resend.com/api-keys',
    instructions: [
      'Go to resend.com/api-keys',
      'Delete the compromised key',
      'Create a new one and update your .env'
    ]
  },

  // Databases
  'Supabase Service Role Key': {
    provider: 'supabase',
    name: 'Supabase',
    url: 'https://supabase.com/dashboard/project/_/settings/api',
    instructions: [
      'Go to supabase.com/dashboard → your project → Settings → API',
      'Copy the current service role key for reference',
      'Click "Reset" to generate a new JWT secret — this rotates all keys',
      'Update SUPABASE_SERVICE_ROLE_KEY in your .env',
      'WARNING: This also rotates the anon key — update that too'
    ]
  },
  'PlanetScale Password': {
    provider: 'planetscale',
    name: 'PlanetScale',
    url: 'https://app.planetscale.com',
    instructions: [
      'Go to app.planetscale.com → your database → Passwords',
      'Delete the compromised password',
      'Create a new password and update your connection string'
    ]
  },
  'Neon Database Connection String': {
    provider: 'neon',
    name: 'Neon',
    url: 'https://console.neon.tech',
    instructions: [
      'Go to console.neon.tech → your project → Connection Details',
      'Reset the database password',
      'Update DATABASE_URL in your .env with the new connection string'
    ]
  },
};

// =============================================================================
// GITHUB API REVOCATION
// =============================================================================

/**
 * Attempt to revoke a GitHub token via the public credentials revocation API.
 * This endpoint does not require authentication — it's designed for reporting
 * exposed credentials found in code.
 *
 * Docs: https://docs.github.com/en/rest/credentials/revoke
 */
async function revokeGitHubToken(token) {
  try {
    const response = await fetch('https://api.github.com/credentials/revoke', {
      method: 'DELETE',
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'User-Agent': 'ship-safe-cli'
      },
      body: JSON.stringify({ access_token: token })
    });

    // 204 = revoked successfully, 422 = already revoked/invalid
    return response.status === 204 || response.status === 422;
  } catch {
    return false; // Network error — fall back to manual
  }
}

// =============================================================================
// BROWSER OPEN
// =============================================================================

function openBrowser(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') throw new Error('Provider URL must use HTTPS');
    const platform = process.platform;
    if (platform === 'win32') execFileSync('rundll32.exe', ['url.dll,FileProtocolHandler', parsed.href], { stdio: 'ignore' });
    else if (platform === 'darwin') execFileSync('open', [parsed.href], { stdio: 'ignore' });
    else execFileSync('xdg-open', [parsed.href], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// =============================================================================
// SCAN
// =============================================================================

async function findFiles(rootPath) {
  const globIgnore = Array.from(SKIP_DIRS).map(dir => `**/${dir}/**`);
  const files = await fg('**/*', {
    cwd: rootPath, absolute: true, onlyFiles: true, ignore: globIgnore, dot: true
  });
  const filtered = [];
  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) continue;
    const basename = path.basename(file);
    if (basename.endsWith('.min.js') || basename.endsWith('.min.css')) continue;
    if (TEST_FILE_PATTERNS.some(p => p.test(file))) continue;
    if (basename === '.env' || basename === '.env.example') continue;
    try {
      const stats = fs.statSync(file);
      if (stats.size > MAX_FILE_SIZE) continue;
    } catch { continue; }
    filtered.push(file);
  }
  return filtered;
}

async function scanFile(filePath) {
  const findings = [];
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      if (/ship-safe-ignore/i.test(line)) continue;
      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        let match;
        while ((match = pattern.pattern.exec(line)) !== null) {
          if (pattern.requiresEntropyCheck && !isHighEntropyMatch(match[0])) continue;
          findings.push({
            line: lineNum + 1,
            matched: match[0],
            patternName: pattern.name,
            severity: pattern.severity,
          });
        }
      }
    }
  } catch { /* skip */ }
  return findings;
}

// =============================================================================
// MASK HELPER
// =============================================================================

function maskToken(token) {
  if (token.length <= 8) return '****';
  return token.substring(0, 6) + '*'.repeat(Math.min(token.length - 6, 16)) + token.slice(-4);
}

// =============================================================================
// PLAN-BASED ROTATION (--plan rotation-plan.json)
// =============================================================================

function promptHidden(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    try { stdin.setRawMode(true); } catch { /* not a TTY */ }
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    function onData(ch) {
      if (ch === '\n' || ch === '\r' || ch === '\u0003') {
        stdin.removeListener('data', onData);
        try { stdin.setRawMode(!!wasRaw); } catch { /* ignore */ }
        stdin.pause();
        process.stdout.write('\n');
        if (ch === '\u0003') process.exit(0);
        resolve(value);
      } else if (ch === '\u007f' || ch === '\b') {
        value = value.slice(0, -1);
      } else {
        value += ch;
        process.stdout.write('*');
      }
    }
    stdin.on('data', onData);
  });
}

async function updateVercelEnvVar(token, projectId, envId, envType, newValue, teamId) {
  const params = new URLSearchParams();
  if (teamId) params.set('teamId', teamId);
  const endpoint = `https://api.vercel.com/v9/projects/${encodeURIComponent(projectId)}/env/${encodeURIComponent(envId)}?${params}`;
  const r = await fetchSafeUrl(endpoint, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: newValue, type: envType || 'encrypted' }),
  });
  if (!r.ok) {
    const body = await r.text();
    throw new Error(`${r.status}: ${body}`);
  }
}

export async function rotatePlanCommand(planFile) {
  // ── 1. Read and validate plan ──────────────────────────────────────────────
  const planPath = path.resolve(planFile);
  if (!fs.existsSync(planPath)) {
    output.error(`Plan file not found: ${planPath}`);
    process.exit(1);
  }

  let plan;
  try {
    plan = JSON.parse(fs.readFileSync(planPath, 'utf-8'));
  } catch {
    output.error('Failed to parse rotation plan JSON. Make sure it was downloaded from shipsafe.sh/rotate');
    process.exit(1);
  }

  const issuers = plan.issuers;
  if (!issuers || typeof issuers !== 'object' || Object.keys(issuers).length === 0) {
    output.success('No credentials in rotation plan — nothing to rotate.');
    return;
  }

  const totalEnvVars = Object.values(issuers).reduce((sum, g) => sum + (g.affected?.length ?? 0), 0);
  const issuerList = Object.entries(issuers);

  output.header('Credential Rotation Plan');
  console.log(chalk.gray(`\n  Plan generated: ${plan.generated ?? 'unknown'}`));
  console.log(chalk.gray(`  Projects scanned: ${plan.projectsScanned ?? 'unknown'}`));
  console.log(chalk.gray(`  Env vars to update: ${totalEnvVars}`));
  console.log(chalk.gray(`  Credential types: ${issuerList.length}\n`));

  // ── 2. Prompt for Vercel token ────────────────────────────────────────────
  console.log(chalk.cyan.bold('  This command will update your Vercel env vars via the API.'));
  console.log(chalk.gray('  Your token is used only for API calls and is never stored.\n'));

  const vercelToken = await promptHidden(chalk.white('  Enter your Vercel API token: '));
  if (!vercelToken) {
    output.error('No Vercel token provided. Aborting.');
    process.exit(1);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const teamId = plan.teamId || '';

  // ── 3. Process each issuer ────────────────────────────────────────────────
  const auditLog = [];
  let totalUpdated = 0;
  let totalFailed = 0;

  for (let i = 0; i < issuerList.length; i++) {
    const [issuerKey, issuerData] = issuerList[i];
    const affected = issuerData.affected ?? [];
    if (affected.length === 0) continue;

    const projectCount = new Set(affected.map(a => a.projectId)).size;
    console.log(chalk.white.bold(`\n  [${i + 1}/${issuerList.length}] ${issuerData.name ?? issuerKey}`));
    console.log(chalk.gray(`       ${affected.length} env var${affected.length !== 1 ? 's' : ''} across ${projectCount} project${projectCount !== 1 ? 's' : ''}`));

    if (issuerData.rotateUrl) {
      console.log(chalk.gray(`       Rotate URL: ${chalk.cyan(issuerData.rotateUrl)}`));
      const opened = openBrowser(issuerData.rotateUrl);
      if (opened) {
        console.log(chalk.gray('       ✓ Opened in browser'));
      } else {
        console.log(chalk.yellow(`       → Open manually: ${issuerData.rotateUrl}`));
      }
    } else {
      console.log(chalk.yellow('       No rotation URL — rotate manually in the provider dashboard.'));
    }

    // Get one new value per unique env var name for this issuer
    const uniqueKeys = [...new Set(affected.map(a => a.envVar))];
    const newValues = {};

    for (const envKey of uniqueKeys) {
      const newVal = await promptHidden(chalk.white(`\n  Paste new value for ${chalk.cyan(envKey)}: `));
      if (!newVal) {
        console.log(chalk.yellow(`  Skipping ${envKey} (no value entered)`));
        continue;
      }
      newValues[envKey] = newVal;
    }

    if (Object.keys(newValues).length === 0) {
      console.log(chalk.gray('  Skipped all env vars for this issuer.\n'));
      continue;
    }

    // Update each affected env var via Vercel API
    const spinner = ora({ text: `  Updating ${affected.length} env var${affected.length !== 1 ? 's' : ''}...`, color: 'cyan' }).start();
    let issuerUpdated = 0;
    let issuerFailed = 0;

    for (const item of affected) {
      const newVal = newValues[item.envVar];
      if (!newVal) continue;
      try {
        await updateVercelEnvVar(vercelToken, item.projectId, item.envId, item.envType, newVal, teamId);
        issuerUpdated++;
        auditLog.push({
          ts: new Date().toISOString(),
          issuer: issuerKey,
          project: item.projectName,
          projectId: item.projectId,
          envVar: item.envVar,
          status: 'updated',
        });
      } catch (e) {
        issuerFailed++;
        auditLog.push({
          ts: new Date().toISOString(),
          issuer: issuerKey,
          project: item.projectName,
          projectId: item.projectId,
          envVar: item.envVar,
          status: 'failed',
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }

    totalUpdated += issuerUpdated;
    totalFailed += issuerFailed;

    if (issuerFailed === 0) {
      spinner.succeed(chalk.green(`  Updated ${issuerUpdated} env var${issuerUpdated !== 1 ? 's' : ''}`));
    } else {
      spinner.warn(chalk.yellow(`  Updated ${issuerUpdated}, failed ${issuerFailed}`));
    }
  }

  rl.close();

  // ── 4. Write audit log ────────────────────────────────────────────────────
  const auditPath = path.resolve('rotation-audit.json');
  fs.writeFileSync(auditPath, JSON.stringify({ rotatedAt: new Date().toISOString(), auditLog }, null, 2));

  // ── 5. Summary ────────────────────────────────────────────────────────────
  console.log();
  console.log(chalk.cyan.bold('  Rotation complete'));
  console.log(chalk.white(`  ✓ ${totalUpdated} env var${totalUpdated !== 1 ? 's' : ''} updated`));
  if (totalFailed > 0) {
    console.log(chalk.red(`  ✗ ${totalFailed} failed — see rotation-audit.json for details`));
  }
  console.log(chalk.gray(`\n  Audit log written to: ${auditPath}`));
  console.log(chalk.gray('  Run ship-safe scan . to confirm no hardcoded credentials remain.\n'));
}

export async function rotateCommand(targetPath = '.', options = {}) {
  // If --plan flag provided, delegate to plan-based rotation
  if (options.plan) {
    return rotatePlanCommand(options.plan);
  }
  const absolutePath = path.resolve(targetPath);

  if (!fs.existsSync(absolutePath)) {
    output.error(`Path does not exist: ${absolutePath}`);
    process.exit(1);
  }

  // ── 1. Scan ───────────────────────────────────────────────────────────────
  const spinner = ora({ text: 'Scanning for secrets to rotate...', color: 'cyan' }).start();

  const files = await findFiles(absolutePath);
  const scanResults = [];
  for (const file of files) {
    const findings = await scanFile(file);
    if (findings.length > 0) scanResults.push({ file, findings });
  }

  spinner.stop();

  if (scanResults.length === 0) {
    output.success('No secrets found — nothing to rotate!');
    return;
  }

  // ── 2. Deduplicate findings by pattern name ───────────────────────────────
  const uniqueFindings = new Map(); // patternName → {matched, file, line}
  for (const { file, findings } of scanResults) {
    for (const f of findings) {
      if (!uniqueFindings.has(f.patternName)) {
        uniqueFindings.set(f.patternName, { ...f, file });
      }
    }
  }

  // ── 3. Filter by --provider if specified ──────────────────────────────────
  let findingsToRotate = [...uniqueFindings.values()];
  if (options.provider) {
    findingsToRotate = findingsToRotate.filter(f => {
      const info = PROVIDER_INFO[f.patternName];
      return info && info.provider === options.provider.toLowerCase();
    });
    if (findingsToRotate.length === 0) {
      output.warning(`No secrets found for provider: ${options.provider}`);
      return;
    }
  }

  output.header('Secret Rotation Guide');
  console.log(chalk.gray(`\n  Found ${findingsToRotate.length} unique secret type(s) to rotate\n`));
  console.log(chalk.yellow.bold('  Rotate secrets BEFORE fixing code or cleaning git history.\n'));

  // ── 4. Process each finding ───────────────────────────────────────────────
  for (const finding of findingsToRotate) {
    const info = PROVIDER_INFO[finding.patternName];

    console.log(chalk.white.bold(`\n  ▸ ${finding.patternName}`));
    console.log(chalk.gray(`    Found: ${maskToken(finding.matched)}`));

    if (!info) {
      // Unknown provider — give generic instructions
      console.log(chalk.yellow('    No specific rotation guide available for this secret type.'));
      console.log(chalk.gray('    → Revoke it manually in the provider\'s dashboard'));
      console.log(chalk.gray('    → Create a new key and update your .env'));
      continue;
    }

    console.log(chalk.gray(`    Provider: ${info.name}`));
    console.log(chalk.gray(`    Revocation URL: ${chalk.cyan(info.url)}`));
    console.log();

    // GitHub: attempt API revocation
    if (info.apiRevoke && finding.patternName.includes('GitHub')) {
      const apiSpinner = ora({ text: '  Attempting API revocation...', color: 'cyan' }).start();
      const revoked = await revokeGitHubToken(finding.matched);
      if (revoked) {
        apiSpinner.succeed(chalk.green('  Token revoked via GitHub API'));
      } else {
        apiSpinner.warn(chalk.yellow('  API revocation failed — revoke manually (see URL above)'));
      }
    }

    // Show step-by-step instructions
    console.log(chalk.gray('    Steps:'));
    info.instructions.forEach((step, i) => {
      console.log(chalk.gray(`      ${i + 1}. ${step}`));
    });

    // Open browser
    const opened = openBrowser(info.url);
    if (opened) {
      console.log(chalk.gray(`\n    ✓ Opened ${info.url} in your browser`));
    } else {
      console.log(chalk.gray(`\n    → Open manually: ${info.url}`));
    }
  }

  // ── 5. Final guidance ─────────────────────────────────────────────────────
  console.log();
  console.log(chalk.cyan.bold('  After rotating all keys:'));
  console.log(chalk.white('  1.') + chalk.gray(' Run ship-safe remediate . to fix your source code'));
  console.log(chalk.white('  2.') + chalk.gray(' Commit the cleaned files'));
  console.log(chalk.white('  3.') + chalk.gray(' Run ship-safe scan . to confirm nothing was missed'));
  console.log();
}
