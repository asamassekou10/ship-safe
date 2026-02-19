/**
 * Ship Safe CLI - Module Entry Point
 * ===================================
 *
 * This file exports the CLI commands for programmatic use.
 * For normal CLI usage, run: npx ship-safe
 */

export { scanCommand } from './commands/scan.js';
export { checklistCommand } from './commands/checklist.js';
export { initCommand } from './commands/init.js';
export { agentCommand } from './commands/agent.js';
export { SECRET_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS } from './utils/patterns.js';
