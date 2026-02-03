/**
 * Checklist Command
 * =================
 *
 * Interactive launch-day security checklist.
 *
 * USAGE:
 *   ship-safe checklist              Interactive mode (prompts for each item)
 *   ship-safe checklist --no-interactive   Print checklist without prompts
 *
 * This walks you through the 10-point security checklist before launch.
 */

import chalk from 'chalk';
import readline from 'readline';
import * as output from '../utils/output.js';

// =============================================================================
// CHECKLIST ITEMS
// =============================================================================

const CHECKLIST_ITEMS = [
  {
    title: 'No exposed .git folder',
    check: 'curl -I https://yoursite.com/.git/config (should return 404)',
    risk: 'Attackers can download your entire codebase including commit history with secrets.',
    fix: 'Configure web server to block .git access. Vercel/Netlify do this by default.'
  },
  {
    title: 'Debug mode disabled',
    check: 'Verify NODE_ENV=production, DEBUG=false in your deployment.',
    risk: 'Debug mode exposes stack traces, environment variables, and internal paths.',
    fix: 'Set production environment variables in your hosting platform.'
  },
  {
    title: 'Database RLS/Security rules enabled',
    check: 'Supabase: Check Policies tab. Firebase: Check Rules tab.',
    risk: 'Without row-level security, any user can read/write any data.',
    fix: 'Define explicit RLS policies for each table. Never use "allow all" rules.'
  },
  {
    title: 'No hardcoded API keys in frontend',
    check: 'Run: npx ship-safe scan ./src',
    risk: 'Anyone viewing source code can steal your API keys.',
    fix: 'Move secrets to server-side environment variables. Use API routes to proxy.'
  },
  {
    title: 'HTTPS enforced',
    check: 'Visit http://yoursite.com - should redirect to https://',
    risk: 'HTTP traffic can be intercepted and modified (MITM attacks).',
    fix: 'Enable "Force HTTPS" in your hosting platform settings.'
  },
  {
    title: 'Security headers configured',
    check: 'Visit securityheaders.com and enter your URL.',
    risk: 'Missing headers enable clickjacking, XSS, and data sniffing.',
    fix: 'Use ship-safe init --headers to add security headers config.'
  },
  {
    title: 'Rate limiting on auth endpoints',
    check: 'Try hitting /login 100 times quickly. Should block you.',
    risk: 'Without rate limiting, attackers can brute-force passwords.',
    fix: 'Add rate limiting middleware or use auth providers with built-in protection.'
  },
  {
    title: 'No sensitive data in URLs',
    check: 'Search codebase for: ?token=, ?api_key=, ?password=',
    risk: 'URLs are logged everywhere. Tokens in URLs get leaked.',
    fix: 'Send sensitive data in headers or POST body, never in URLs.'
  },
  {
    title: 'Error messages don\'t leak info',
    check: 'Trigger errors intentionally. Check for stack traces in response.',
    risk: 'Detailed errors help attackers understand your system.',
    fix: 'Show generic errors to users. Log details server-side only.'
  },
  {
    title: 'Admin routes protected',
    check: 'Try accessing /admin, /api/admin, /dashboard without auth.',
    risk: 'Exposed admin panels are the #1 target for attackers.',
    fix: 'Add auth middleware. Consider IP whitelisting for admin routes.'
  }
];

// =============================================================================
// MAIN CHECKLIST FUNCTION
// =============================================================================

export async function checklistCommand(options = {}) {
  console.log();
  console.log(chalk.cyan.bold('='.repeat(60)));
  console.log(chalk.cyan.bold('  Launch Day Security Checklist'));
  console.log(chalk.cyan.bold('='.repeat(60)));
  console.log();
  console.log(chalk.gray('Complete these 10 checks before going live.'));
  console.log(chalk.gray('Each one takes under 1 minute to verify.'));
  console.log();

  if (options.interactive === false) {
    // Non-interactive: just print the checklist
    printChecklist();
    return;
  }

  // Interactive mode
  await runInteractiveChecklist();
}

// =============================================================================
// NON-INTERACTIVE MODE
// =============================================================================

function printChecklist() {
  for (let i = 0; i < CHECKLIST_ITEMS.length; i++) {
    const item = CHECKLIST_ITEMS[i];
    const num = i + 1;

    console.log(chalk.white.bold(`${num}. [ ] ${item.title}`));
    console.log(chalk.gray(`   Check: ${item.check}`));
    console.log(chalk.yellow(`   Risk: ${item.risk}`));
    console.log(chalk.green(`   Fix: ${item.fix}`));
    console.log();
  }

  console.log(chalk.cyan('='.repeat(60)));
  console.log(chalk.gray('Copy this checklist or run with interactive mode:'));
  console.log(chalk.white('  npx ship-safe checklist'));
  console.log(chalk.cyan('='.repeat(60)));
}

// =============================================================================
// INTERACTIVE MODE
// =============================================================================

async function runInteractiveChecklist() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const results = [];

  console.log(chalk.gray('For each item, press:'));
  console.log(chalk.green('  y') + chalk.gray(' = Done/Verified'));
  console.log(chalk.yellow('  s') + chalk.gray(' = Skip for now'));
  console.log(chalk.red('  n') + chalk.gray(' = Not done (will show fix)'));
  console.log(chalk.gray('  q = Quit'));
  console.log();

  for (let i = 0; i < CHECKLIST_ITEMS.length; i++) {
    const item = CHECKLIST_ITEMS[i];
    const num = i + 1;

    console.log(chalk.cyan('-'.repeat(60)));
    console.log(chalk.white.bold(`\n${num}/${CHECKLIST_ITEMS.length}: ${item.title}\n`));
    console.log(chalk.gray(`How to check: ${item.check}`));
    console.log();

    const answer = await askQuestion(rl, chalk.white('Status? [y/s/n/q]: '));

    if (answer.toLowerCase() === 'q') {
      console.log(chalk.yellow('\nChecklist paused. Run again to continue.'));
      rl.close();
      return;
    }

    if (answer.toLowerCase() === 'y') {
      results.push({ item, status: 'done' });
      console.log(chalk.green('\u2714 Marked as complete\n'));
    } else if (answer.toLowerCase() === 's') {
      results.push({ item, status: 'skipped' });
      console.log(chalk.yellow('\u2192 Skipped\n'));
    } else {
      results.push({ item, status: 'todo' });
      console.log();
      console.log(chalk.red('\u26a0 Risk: ') + item.risk);
      console.log(chalk.green('\u2192 Fix: ') + item.fix);
      console.log();
    }
  }

  rl.close();

  // Print summary
  printSummary(results);
}

function askQuestion(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

function printSummary(results) {
  const done = results.filter(r => r.status === 'done').length;
  const skipped = results.filter(r => r.status === 'skipped').length;
  const todo = results.filter(r => r.status === 'todo').length;

  console.log();
  console.log(chalk.cyan('='.repeat(60)));
  console.log(chalk.cyan.bold('  Summary'));
  console.log(chalk.cyan('='.repeat(60)));
  console.log();
  console.log(chalk.green(`  \u2714 Completed: ${done}`));
  console.log(chalk.yellow(`  \u2192 Skipped: ${skipped}`));
  console.log(chalk.red(`  \u2718 Todo: ${todo}`));
  console.log();

  if (todo === 0 && skipped === 0) {
    console.log(chalk.green.bold('  \ud83d\ude80 You\'re ready to ship safely!'));
  } else if (todo > 0) {
    console.log(chalk.yellow('  Items still need attention:'));
    for (const r of results.filter(r => r.status === 'todo')) {
      console.log(chalk.red(`    \u2022 ${r.item.title}`));
    }
  }

  console.log();
  console.log(chalk.gray('  Tip: Security is ongoing. Schedule monthly reviews.'));
  console.log(chalk.cyan('='.repeat(60)));
}
