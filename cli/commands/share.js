/**
 * Share Command — Publish a scan report as a public URL
 *
 * Usage:
 *   ship-safe share [path]
 *
 * Reads the latest scan from .ship-safe/history.json (or runs a fresh scan),
 * uploads it to shipsafe.sh, and returns a shareable link valid for 7 days.
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import ora from 'ora';

const SHARE_ENDPOINT = 'https://shipsafe.sh/api/share';

export async function shareCommand(targetPath = '.', options = {}) {
  const root = path.resolve(targetPath);

  // ── Load last scan from history ──────────────────────────────────────────
  const historyPath = path.join(root, '.ship-safe', 'history.json');
  let report = null;

  if (fs.existsSync(historyPath)) {
    try {
      const history = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
      const entries = Array.isArray(history) ? history : [history];
      if (entries.length > 0) report = entries[entries.length - 1];
    } catch {
      // fall through
    }
  }

  if (!report) {
    console.log(chalk.yellow('  No scan found. Run a scan first:'));
    console.log(chalk.gray('  npx ship-safe audit .'));
    process.exit(1);
  }

  const spinner = ora({ text: 'Uploading report...', color: 'cyan' }).start();

  try {
    const res = await fetch(SHARE_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        score:    report.score ?? null,
        grade:    report.grade ?? null,
        repo:     report.rootPath ? path.basename(report.rootPath) : null,
        findings: report.totalFindings ?? 0,
        report,
      }),
    });

    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }

    const { url } = await res.json();
    spinner.succeed(chalk.green('Report shared!'));
    console.log();
    console.log(chalk.white('  Share URL: ') + chalk.cyan.bold(url));
    console.log(chalk.gray('  Link expires in 7 days.'));
    console.log();
  } catch (err) {
    spinner.fail(chalk.red('Failed to share report'));
    console.log(chalk.gray(`  ${err.message}`));
    process.exit(1);
  }
}
