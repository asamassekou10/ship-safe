/**
 * Output Utilities
 * ================
 *
 * Consistent, pretty terminal output for the CLI.
 * Uses chalk for colors and provides helper functions
 * for common output patterns.
 */

import chalk from 'chalk';

// =============================================================================
// SEVERITY COLORS
// =============================================================================

export const severityColors = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue
};

export const severityIcons = {
  critical: '\u2620\ufe0f ',  // skull
  high: '\u26a0\ufe0f ',      // warning
  medium: '\u26a1',           // lightning
  low: '\u2139\ufe0f '        // info
};

// =============================================================================
// OUTPUT HELPERS
// =============================================================================

/**
 * Print a section header
 */
export function header(text) {
  console.log();
  console.log(chalk.cyan.bold('='.repeat(60)));
  console.log(chalk.cyan.bold(`  ${text}`));
  console.log(chalk.cyan.bold('='.repeat(60)));
}

/**
 * Print a subheader
 */
export function subheader(text) {
  console.log();
  console.log(chalk.white.bold(text));
  console.log(chalk.gray('-'.repeat(text.length)));
}

/**
 * Print a success message
 */
export function success(text) {
  console.log(chalk.green('\u2714 ') + text);
}

/**
 * Print a warning message
 */
export function warning(text) {
  console.log(chalk.yellow('\u26a0 ') + text);
}

/**
 * Print an error message
 */
export function error(text) {
  console.log(chalk.red('\u2718 ') + text);
}

/**
 * Print an info message
 */
export function info(text) {
  console.log(chalk.blue('\u2139 ') + text);
}

const confidenceColors = {
  high:   chalk.red,
  medium: chalk.yellow,
  low:    chalk.gray,
};

/**
 * Print a finding (secret detected)
 */
export function finding(file, line, patternName, severity, matched, description, confidence) {
  const color = severityColors[severity] || chalk.white;
  const icon = severityIcons[severity] || '';
  const confColor = confidenceColors[confidence] || chalk.gray;
  const confLabel = confidence ? `  ${chalk.gray('Confidence:')} ${confColor(confidence)}` : '';

  console.log();
  console.log(chalk.white.bold(`${file}:${line}`));
  console.log(`  ${icon}${color(`[${severity.toUpperCase()}]`)} ${chalk.white(patternName)}`);
  console.log(`  ${chalk.gray('Found:')} ${chalk.yellow(maskSecret(matched))}`);
  if (confLabel) console.log(confLabel);
  console.log(`  ${chalk.gray('Why:')} ${description}`);
}

/**
 * Print a vulnerability finding (code issue — show matched code, not masked)
 */
export function vulnerabilityFinding(file, line, patternName, severity, matched, description) {
  const color = severityColors[severity] || chalk.white;
  const icon = severityIcons[severity] || '';
  const snippet = matched.length > 80 ? matched.slice(0, 80) + '…' : matched;

  console.log();
  console.log(chalk.white.bold(`${file}:${line}`));
  console.log(`  ${icon}${color(`[${severity.toUpperCase()}]`)} ${chalk.white(patternName)}`);
  console.log(`  ${chalk.gray('Code:')}  ${chalk.cyan(snippet)}`);
  console.log(`  ${chalk.gray('Why:')}  ${description}`);
}

/**
 * Mask the middle of a secret for safe display
 */
export function maskSecret(secret) {
  if (secret.length <= 10) {
    return secret.substring(0, 3) + '***';
  }
  return secret.substring(0, 6) + '***' + secret.substring(secret.length - 4);
}

/**
 * Print a summary box
 *
 * stats can include:
 *   total, critical, high, medium, filesScanned
 *   secretsTotal (optional), vulnsTotal (optional)
 */
export function summary(stats) {
  console.log();
  console.log(chalk.cyan('='.repeat(60)));

  if (stats.total === 0) {
    console.log(chalk.green.bold('  \u2714 No issues detected!'));
  } else {
    const secretsTotal = stats.secretsTotal ?? stats.total;
    const vulnsTotal = stats.vulnsTotal ?? 0;

    if (secretsTotal > 0) {
      console.log(chalk.red.bold(`  \u26a0 Found ${secretsTotal} secret(s)`));
    }
    if (vulnsTotal > 0) {
      console.log(chalk.yellow.bold(`  \u26a0 Found ${vulnsTotal} code vulnerability/vulnerabilities`));
    }

    if (stats.critical > 0) {
      console.log(chalk.red(`    \u2022 Critical: ${stats.critical}`));
    }
    if (stats.high > 0) {
      console.log(chalk.red(`    \u2022 High: ${stats.high}`));
    }
    if (stats.medium > 0) {
      console.log(chalk.yellow(`    \u2022 Medium: ${stats.medium}`));
    }
  }

  console.log(chalk.gray(`  Files scanned: ${stats.filesScanned}`));
  console.log(chalk.cyan('='.repeat(60)));
}

/**
 * Print recommended actions after finding code vulnerabilities
 */
export function vulnRecommendations() {
  console.log();
  console.log(chalk.yellow.bold('Code Vulnerability Actions:'));
  console.log();
  console.log(chalk.white('1.') + ' Fix the flagged code patterns (see "Why" descriptions above)');
  console.log(chalk.white('2.') + ' Use  # ship-safe-ignore  on lines that are safe (e.g. internal tools, controlled input)');
  console.log(chalk.white('3.') + ' Run  npx ship-safe checklist  for a full launch-day security review');
  console.log();
}

/**
 * Print recommended actions after finding secrets
 */
export function recommendations() {
  console.log();
  console.log(chalk.cyan.bold('Recommended Actions:'));
  console.log();
  console.log(chalk.white('1.') + ' Move secrets to environment variables (.env file)');
  console.log(chalk.white('2.') + ' Add .env to your .gitignore');
  console.log(chalk.white('3.') + chalk.yellow(' If already committed:'));
  console.log(chalk.gray('   \u2022 Rotate the compromised credentials immediately'));
  console.log(chalk.gray('   \u2022 Use git-filter-repo or BFG Repo-Cleaner to remove from history'));
  console.log(chalk.gray('   \u2022 Remember: deleting doesn\'t remove git history!'));
  console.log();
  console.log(chalk.white('4.') + ' Set up pre-commit hooks to catch this automatically:');
  console.log(chalk.gray('   npm install --save-dev husky'));
  console.log(chalk.gray('   npx husky add .husky/pre-commit "npx ship-safe scan ."'));
  console.log();
}

/**
 * Print a checklist item
 */
export function checklistItem(number, title, checked = null) {
  const checkbox = checked === null
    ? chalk.gray('[ ]')
    : checked
      ? chalk.green('[\u2714]')
      : chalk.red('[\u2718]');

  console.log(`${checkbox} ${chalk.white.bold(`${number}.`)} ${title}`);
}

/**
 * Print progress (for verbose mode)
 */
export function progress(text) {
  process.stdout.write(chalk.gray(`\r${text}`));
}

/**
 * Clear the current line
 */
export function clearLine() {
  process.stdout.write('\r' + ' '.repeat(80) + '\r');
}
