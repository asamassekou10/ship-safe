/**
 * Update Intel Command
 * =====================
 *
 * Updates the local threat intelligence feed from the remote source.
 *
 * USAGE:
 *   ship-safe update-intel              Fetch latest threat intel
 *   ship-safe update-intel --url <url>  Use custom feed URL
 */

import chalk from 'chalk';
import * as output from '../utils/output.js';
import { ThreatIntel } from '../utils/threat-intel.js';

export async function updateIntelCommand(options = {}) {
  console.log();
  output.header('Ship Safe — Threat Intelligence Update');
  console.log();

  const currentStats = ThreatIntel.stats();
  console.log(chalk.gray(`  Current version: ${currentStats.version}`));
  console.log(chalk.gray(`  Last updated: ${currentStats.updated || 'unknown'}`));
  console.log(chalk.gray(`  Indicators: ${currentStats.hashes} hashes, ${currentStats.servers} servers, ${currentStats.signatures} signatures`));
  console.log();

  console.log(chalk.cyan('  Checking for updates...'));

  const result = await ThreatIntel.update(options.url);

  if (result.error) {
    output.error(`Update failed: ${result.error}`);
    console.log(chalk.gray('  The local seed data will still be used for scanning.'));
    console.log(chalk.gray('  Check your network connection and try again.'));
    console.log();
    return;
  }

  if (!result.updated) {
    console.log(chalk.green('  ✔ Already up to date.'));
    console.log();
    return;
  }

  console.log();
  console.log(chalk.green.bold('  ✔ Threat intelligence updated!'));
  console.log();
  console.log(`  ${chalk.gray('Version:')} ${result.oldVersion} → ${chalk.cyan(result.newVersion)}`);
  if (result.stats) {
    console.log(`  ${chalk.gray('Malicious skill hashes:')} ${result.stats.hashes}`);
    console.log(`  ${chalk.gray('Compromised MCP servers:')} ${result.stats.servers}`);
    console.log(`  ${chalk.gray('Config signatures:')} ${result.stats.signatures}`);
  }
  console.log();
}
