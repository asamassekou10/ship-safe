/**
 * Capabilities Command
 * ====================
 *
 * Prints what an AI coding agent working in this repository can reach, and the
 * combinations of that reach which are dangerous together while unremarkable
 * apart.
 *
 * USAGE:
 *   ship-safe capabilities [path]        Capability graph and attack chains
 *   ship-safe capabilities . --env       Include the operator's own MCP servers
 *   ship-safe capabilities . --json      Machine-readable graph, chains, findings
 *
 * The --env form reads MCP configuration from the home directory. Those servers
 * are genuinely reachable from a session in this repo, which makes them worth
 * seeing locally — and they are off by default, because personal server names
 * do not belong in a repository's security report or in a pipeline's output.
 */

import path from 'path';
import fs from 'fs';
import chalk from 'chalk';
import * as output from '../utils/output.js';
import {
  buildCapabilityGraph,
  findAttackChains,
  summarizeCapabilities,
  chainFindings,
} from '../utils/capability-graph.js';
import { validateCitations } from '../utils/evidence.js';

const KIND_LABEL = {
  shell: 'shell',
  filesystem: 'filesystem',
  network: 'network',
  'mcp-tool': 'MCP tool',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export async function capabilitiesCommand(targetPath = '.', options = {}) {
  const rootPath = path.resolve(targetPath);

  if (!fs.existsSync(rootPath)) {
    output.error(`Path does not exist: ${rootPath}`);
    process.exit(1);
  }

  const graph = buildCapabilityGraph(rootPath, { includeEnvironment: Boolean(options.env) });
  const chains = findAttackChains(graph)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const findings = chainFindings(chains, rootPath);

  // Validate before reporting. A chain citing configuration that is not there
  // is exactly the failure this tool exists to catch in other people's output.
  for (const finding of findings) {
    for (const claim of finding.evidence.claims) validateCitations(claim, { rootPath });
  }

  if (options.json) {
    console.log(JSON.stringify({
      root: rootPath,
      sources: graph.sources,
      capabilities: summarizeCapabilities(graph),
      credentials: graph.credentials.map((c) => ({ ...c, id: undefined })),
      surfaces: graph.surfaces,
      chains,
      findings,
    }, null, 2));
    return;
  }

  render(graph, chains, rootPath);
  if (chains.some((c) => c.severity === 'critical')) process.exitCode = 1;
}

function render(graph, chains, rootPath) {
  output.header('Agent Capability Graph');

  if (!graph.sources.length) {
    output.info('No agent configuration, MCP servers, instruction files, or workflows found here.');
    console.log(chalk.dim('  Nothing to reason about — this repository grants an agent no configured reach.\n'));
    return;
  }

  console.log(chalk.dim(`  Read from ${graph.sources.length} source(s) under ${path.basename(rootPath)}/\n`));

  // ── Reach ────────────────────────────────────────────────────────────────
  const groups = summarizeCapabilities(graph);
  const byActor = new Map();
  for (const group of groups) {
    if (!byActor.has(group.actor)) byActor.set(group.actor, []);
    byActor.get(group.actor).push(group);
  }

  for (const [actorId, actorGroups] of byActor) {
    const actor = graph.actors.find((a) => a.id === actorId);
    const flags = [
      actor?.unattended ? chalk.red('unattended') : null,
      actor?.autoEnablesRepoServers ? chalk.yellow('auto-enables repo servers') : null,
      actor?.scope === 'environment' ? chalk.dim('environment') : null,
    ].filter(Boolean);

    console.log(`  ${chalk.bold(actor?.name || actorId)}${flags.length ? ` ${flags.join(' ')}` : ''}`);
    console.log(chalk.dim(`  ${actor?.file || ''}`));

    actorGroups.forEach((group, index) => {
      const last = index === actorGroups.length - 1;
      const branch = last ? '└──' : '├──';
      const label = `${KIND_LABEL[group.kind] || group.kind}: ${group.access}`;
      const count = group.wildcard
        ? chalk.red('wildcard')
        : chalk.dim(group.count === 1 ? '1 grant' : `${group.count} grants`);
      console.log(`   ${branch} ${label}  ${count}`);
      if (group.examples.length && !group.wildcard) {
        console.log(chalk.dim(`   ${last ? '   ' : '│  '}   e.g. ${group.examples[0].value}`));
      }
    });
    console.log('');
  }

  // ── Credentials in reach ─────────────────────────────────────────────────
  if (graph.credentials.length) {
    output.subheader('Credentials in reach');
    for (const cred of graph.credentials) {
      const marker = cred.inline ? chalk.red(' literal value') : '';
      console.log(`  ${chalk.bold(cred.name)}${marker}  ${chalk.dim(`${cred.file}:${cred.line}`)}`);
    }
    console.log('');
  }

  // ── Untrusted surfaces ───────────────────────────────────────────────────
  if (graph.surfaces.length) {
    output.subheader('Untrusted input the agent ingests');
    for (const surface of graph.surfaces) {
      console.log(`  ${chalk.bold(surface.file)}${surface.trigger ? chalk.dim(` (${surface.trigger})`) : ''}`);
      console.log(chalk.dim(`    ${surface.note}`));
    }
    console.log('');
  }

  // ── Chains ───────────────────────────────────────────────────────────────
  if (!chains.length) {
    output.success('No dangerous capability combinations found.');
    console.log(chalk.dim('  Individual grants above may still deserve review.\n'));
    return;
  }

  output.subheader(`Attack chains (${chains.length})`);
  for (const chain of chains) {
    const color = chain.severity === 'critical' ? chalk.red : chalk.yellow;
    console.log(`\n  ${color.bold(chain.severity.toUpperCase())}  ${chalk.bold(chain.title)}`);
    chain.steps.forEach((step, index) => {
      console.log(`    ${chalk.dim(`${index + 1}.`)} ${step.text}`);
      console.log(chalk.dim(`       ${step.file}:${step.line}`));
    });
    console.log(`    ${chalk.bold('Impact:')} ${chain.impact}`);
    console.log(`    ${chalk.bold('Boundary:')} ${chain.recommendation}`);
  }
  console.log('');
}
