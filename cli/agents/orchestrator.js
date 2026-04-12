/**
 * Agent Orchestrator
 * ==================
 *
 * Coordinates all security agents, deduplicates findings,
 * and produces a unified report.
 *
 * Features:
 * - Per-agent timeouts (default 30s, configurable via --timeout)
 * - Parallel execution with configurable concurrency (default 6)
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
import { VerifierAgent } from './verifier-agent.js';
import { DeepAnalyzer } from './deep-analyzer.js';

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_TIMEOUT = 30_000; // 30s per agent
const DEFAULT_CONCURRENCY = 6;

// =============================================================================
// ORCHESTRATOR
// =============================================================================

export class Orchestrator {
  constructor() {
    /** @type {import('./base-agent.js').BaseAgent[]} */
    this.agents = [];
    this.reconAgent = new ReconAgent();
    this.verifierAgent = new VerifierAgent();
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
   * Run a single agent with a timeout.
   */
  async runAgent(agent, context, timeout) {
    return Promise.race([
      agent.analyze(context),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`timed out after ${timeout / 1000}s`)), timeout);
      }),
    ]);
  }

  /**
   * Run all registered agents against the codebase.
   *
   * @param {string} rootPath — Absolute path to the project root
   * @param {object} options  — { verbose, agents[], categories[], timeout, concurrency }
   * @returns {Promise<object>} — { recon, findings[], agentResults[] }
   */
  async runAll(rootPath, options = {}) {
    const absolutePath = path.resolve(rootPath);
    const timeout = options.timeout || DEFAULT_TIMEOUT;
    const concurrency = options.concurrency || DEFAULT_CONCURRENCY;

    // ── 1. Recon — map the attack surface ─────────────────────────────────────
    const quiet = options.quiet || false;
    const reconSpinner = quiet ? null : ora({ text: 'Mapping attack surface...', color: 'cyan' }).start();
    const recon = await this.reconAgent.analyze({ rootPath: absolutePath, options });
    if (reconSpinner) reconSpinner.succeed(chalk.green('Attack surface mapped'));

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

    // ── 4. Build shared context ─────────────────────────────────────────────
    // sharedFindings allows cross-agent awareness: later agents can see
    // what earlier agents found (e.g., secrets agent finds a key,
    // supply-chain agent can check if it's committed to a public repo).
    const sharedFindings = [];
    const context = { rootPath: absolutePath, files, recon, options, sharedFindings };
    if (options.changedFiles) {
      context.changedFiles = options.changedFiles;
    }

    // ── 5. Run agents in parallel (chunked by concurrency) ──────────────────
    const agentResults = [];
    let allFindings = [];

    const spinner = quiet ? null : ora({
      text: `Running ${agentsToRun.length} agents in parallel...`,
      color: 'cyan'
    }).start();

    // Filter agents by framework relevance (shouldRun check)
    const relevantAgents = agentsToRun.filter(a => {
      if (typeof a.shouldRun === 'function') {
        return a.shouldRun(recon);
      }
      return true;
    });
    const skippedAgents = agentsToRun.length - relevantAgents.length;

    for (let i = 0; i < relevantAgents.length; i += concurrency) {
      const chunk = relevantAgents.slice(i, i + concurrency);
      const settled = await Promise.allSettled(
        chunk.map(agent => this.runAgent(agent, context, timeout))
      );

      for (let j = 0; j < chunk.length; j++) {
        const agent = chunk[j];
        const result = settled[j];

        if (result.status === 'fulfilled') {
          const findings = result.value;
          agentResults.push({
            agent: agent.name,
            category: agent.category,
            findingCount: findings.length,
            success: true,
          });
          allFindings = allFindings.concat(findings);
          // Share findings with subsequent agents
          sharedFindings.push(...findings);
        } else {
          agentResults.push({
            agent: agent.name,
            category: agent.category,
            findingCount: 0,
            success: false,
            error: result.reason.message,
          });
        }
      }
    }

    // Show results summary
    if (spinner) {
      const succeeded = agentResults.filter(a => a.success).length;
      const failed = agentResults.filter(a => !a.success).length;
      const totalFindings = allFindings.length;

      const skipNote = skippedAgents > 0 ? `, ${skippedAgents} skipped (not relevant)` : '';
      if (failed > 0) {
        spinner.warn(chalk.yellow(
          `${succeeded}/${relevantAgents.length} agents completed, ${failed} failed, ${totalFindings} finding(s)${skipNote}`
        ));
      } else {
        spinner.succeed(
          totalFindings === 0
            ? chalk.green(`${succeeded} agents: clean${skipNote}`)
            : chalk.yellow(`${succeeded} agents: ${totalFindings} finding(s)${skipNote}`)
        );
      }
    }

    // Show per-agent results when not in quiet mode
    if (!quiet) {
      for (const r of agentResults) {
        if (r.success) {
          const icon = r.findingCount === 0 ? chalk.green('  ✔') : chalk.yellow('  ⚠');
          const msg = r.findingCount === 0
            ? chalk.green(`${r.agent}: clean`)
            : chalk.yellow(`${r.agent}: ${r.findingCount} finding(s)`);
          console.log(`${icon} ${msg}`);
        } else {
          console.log(chalk.red(`  ✗ ${r.agent}: ${r.error}`));
        }
      }
    }

    // ── 6. Deduplicate ────────────────────────────────────────────────────────
    allFindings = this.deduplicate(allFindings);

    // ── 7. Second-pass verification (confirms or downgrades findings) ───────
    if (!options.skipVerifier) {
      const verifySpinner = quiet ? null : ora({ text: 'Verifying findings...', color: 'cyan' }).start();
      allFindings = this.verifierAgent.verify(allFindings, options);
      const verified = allFindings.filter(f => f.verified === true).length;
      const downgraded = allFindings.filter(f => f.verified === false).length;
      if (verifySpinner) {
        verifySpinner.succeed(chalk.green(
          `Verified: ${verified} confirmed, ${downgraded} downgraded`
        ));
      }
    }

    // ── 8. Deep LLM analysis (optional, --deep flag) ───────────────────────
    if (options.deep) {
      const analyzer = DeepAnalyzer.create(absolutePath, {
        local: options.local,
        model: options.model,
        budgetCents: options.budget || 50,
        verbose: options.verbose,
      });

      if (analyzer) {
        const deepSpinner = quiet ? null : ora({ text: `Deep analysis with ${analyzer.provider.name}...`, color: 'cyan' }).start();
        try {
          allFindings = await analyzer.analyze(allFindings, { rootPath: absolutePath, recon });
          const stats = analyzer.getStats();
          if (deepSpinner) {
            if (stats.multiTier) {
              const tierNote = stats.tier3Count > 0
                ? `, ${stats.tier3Count} escalated to Opus`
                : stats.tier2Count > 0 ? `, ${stats.tier2Count} via Sonnet` : '';
              const skipNote = stats.skippedCount > 0 ? `, ${stats.skippedCount} triaged away` : '';
              deepSpinner.succeed(chalk.green(
                `Deep analysis (Haiku→Sonnet→Opus): ${stats.analyzedCount} analyzed${tierNote}${skipNote} (${stats.spentCents}¢)`
              ));
            } else {
              deepSpinner.succeed(chalk.green(
                `Deep analysis: ${stats.analyzedCount} findings analyzed (${stats.spentCents}¢)`
              ));
            }
          }
        } catch (err) {
          if (deepSpinner) deepSpinner.fail(chalk.yellow(`Deep analysis failed: ${err.message}`));
        }
      } else if (!quiet) {
        console.log(chalk.gray('  Deep analysis: no LLM provider found (set ANTHROPIC_API_KEY or use --local)'));
      }
    }

    // ── 9. Context-aware confidence tuning ──────────────────────────────────
    allFindings = this.tuneConfidence(allFindings);

    // ── 10. Sort by severity ──────────────────────────────────────────────────
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
   * Downgrade confidence for findings in test files, comments, docs, or examples.
   * Reduces false-positive noise since ScoringEngine applies confidence multipliers.
   */
  tuneConfidence(findings) {
    const TEST_PATH = /(?:__tests__|\.test\.|\.spec\.|\/test\/|\/tests\/|\/fixtures?\/)/i;
    const DOC_EXT = new Set(['.md', '.txt', '.rst', '.adoc', '.rdoc']);
    const EXAMPLE_PATH = /(?:\/examples?\/|\/samples?\/|\/demos?\/|\/fixtures?\/|\/mocks?\/)/i;
    const COMMENT_LINE = /^\s*(?:\/\/|#|\/?\*|<!--)/;

    for (const f of findings) {
      const ext = (f.file || '').match(/\.[^.]+$/)?.[0]?.toLowerCase() || '';

      // Findings in documentation files
      if (DOC_EXT.has(ext)) {
        f.confidence = 'low';
        continue;
      }

      // Findings in test files
      if (TEST_PATH.test(f.file || '')) {
        f.confidence = 'low';
        continue;
      }

      // Findings in example/sample/demo paths: high → medium
      if (EXAMPLE_PATH.test(f.file || '') && f.confidence === 'high') {
        f.confidence = 'medium';
        continue;
      }

      // Findings on comment lines
      if (f.matched && COMMENT_LINE.test(f.matched)) {
        f.confidence = 'low';
      }
    }

    return findings;
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
