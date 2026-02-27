/**
 * Agent Orchestrator
 * ==================
 *
 * Coordinates all security agents, deduplicates findings,
 * and produces a unified report.
 *
 * USAGE:
 *   const orchestrator = new Orchestrator();
 *   orchestrator.register(new InjectionTester());
 *   const results = await orchestrator.runAll(rootPath, options);
 */

import path from 'path';
import ora from 'ora';
import chalk from 'chalk';
import { ReconAgent } from './recon-agent.js';

// =============================================================================
// ORCHESTRATOR
// =============================================================================

export class Orchestrator {
  constructor() {
    /** @type {import('./base-agent.js').BaseAgent[]} */
    this.agents = [];
    this.reconAgent = new ReconAgent();
  }

  /**
   * Register an agent for execution.
   */
  register(agent) {
    this.agents.push(agent);
    return this;
  }

  /**
   * Register multiple agents at once.
   */
  registerAll(agents) {
    for (const agent of agents) {
      this.register(agent);
    }
    return this;
  }

  /**
   * Run all registered agents against the codebase.
   *
   * @param {string} rootPath — Absolute path to the project root
   * @param {object} options  — { verbose, agents[], categories[] }
   * @returns {Promise<object>} — { recon, findings[], agentResults[] }
   */
  async runAll(rootPath, options = {}) {
    const absolutePath = path.resolve(rootPath);

    // ── 1. Recon — map the attack surface ─────────────────────────────────────
    const reconSpinner = ora({ text: 'Mapping attack surface...', color: 'cyan' }).start();
    const recon = await this.reconAgent.analyze({ rootPath: absolutePath, options });
    reconSpinner.succeed(chalk.green('Attack surface mapped'));

    // ── 2. Discover files once (shared across agents) ─────────────────────────
    const files = await this.reconAgent.discoverFiles(absolutePath);

    // ── 3. Filter agents if specific ones requested ───────────────────────────
    let agentsToRun = this.agents;
    if (options.agents && options.agents.length > 0) {
      const requested = options.agents.map(a => a.toLowerCase());
      agentsToRun = this.agents.filter(a => {
        const name = a.name.toLowerCase();
        const cat = a.category.toLowerCase();
        return requested.some(r => name === r || name.includes(r) || cat === r);
      });
    }
    if (options.categories && options.categories.length > 0) {
      const requested = new Set(options.categories.map(c => c.toLowerCase()));
      agentsToRun = agentsToRun.filter(a => requested.has(a.category.toLowerCase()));
    }

    // ── 4. Run each agent ─────────────────────────────────────────────────────
    const context = { rootPath: absolutePath, files, recon, options };
    const agentResults = [];
    let allFindings = [];

    for (const agent of agentsToRun) {
      const spinner = ora({
        text: `Running ${agent.name}...`,
        color: 'cyan'
      }).start();

      try {
        const findings = await agent.analyze(context);
        agentResults.push({
          agent: agent.name,
          category: agent.category,
          findingCount: findings.length,
          success: true,
        });
        allFindings = allFindings.concat(findings);
        spinner.succeed(
          findings.length === 0
            ? chalk.green(`${agent.name}: clean`)
            : chalk.yellow(`${agent.name}: ${findings.length} finding(s)`)
        );
      } catch (err) {
        agentResults.push({
          agent: agent.name,
          category: agent.category,
          findingCount: 0,
          success: false,
          error: err.message,
        });
        spinner.fail(chalk.red(`${agent.name}: error — ${err.message}`));
      }
    }

    // ── 5. Deduplicate ────────────────────────────────────────────────────────
    allFindings = this.deduplicate(allFindings);

    // ── 6. Sort by severity ───────────────────────────────────────────────────
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) =>
      (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
    );

    return { recon, findings: allFindings, agentResults };
  }

  /**
   * Run only agents matching a specific category.
   */
  async runCategory(category, rootPath, options = {}) {
    return this.runAll(rootPath, { ...options, categories: [category] });
  }

  /**
   * Remove duplicate findings (same file + line + rule).
   */
  deduplicate(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const key = `${f.file}:${f.line}:${f.rule}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

export default Orchestrator;
