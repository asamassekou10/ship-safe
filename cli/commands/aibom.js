/**
 * AIBOM Command
 * =============
 *
 * Generate an AI Bill of Materials (models, LLM/ML SDKs, MCP servers, agent
 * configs) and, optionally, an EU AI Act high-risk readiness report.
 *
 * USAGE:
 *   ship-safe aibom [path]                Generate AIBOM -> aibom.json
 *   ship-safe aibom . -o ai-bom.json      Custom output path
 *   ship-safe aibom . --ai-act            Also print the EU AI Act readiness report
 *   ship-safe aibom . --json              Print AIBOM JSON to stdout
 */

import path from 'path';
import chalk from 'chalk';
import { AIBOMGenerator } from '../agents/aibom-generator.js';
import * as output from '../utils/output.js';

export async function aibomCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  const generator = new AIBOMGenerator();
  const bom = generator.generate(absolutePath);

  if (options.json) {
    console.log(JSON.stringify(bom, null, 2));
    return;
  }

  console.log();
  output.header('Ship Safe — AI Bill of Materials');
  console.log();

  const outputFile = options.output || 'aibom.json';
  generator.generateToFile(absolutePath, outputFile);

  const byType = (t) => bom.components.filter((c) => c.properties?.some((p) => p.name === 'ai:type' && p.value === t));
  const models = byType('model');
  const sdks = byType('sdk');
  const mcp = byType('mcp-server');
  const configs = byType('agent-config');
  const unsafeModels = models.filter((m) => m.properties?.some((p) => p.name === 'ai:serialization' && /pickle/.test(p.value)));

  console.log(chalk.gray(`  Project: ${bom.metadata.component.name}`));
  console.log();
  console.log(`  ${chalk.cyan('Models')}:         ${models.length}${unsafeModels.length ? chalk.red(`  (${unsafeModels.length} pickle-based)`) : ''}`);
  console.log(`  ${chalk.cyan('AI SDKs')}:        ${sdks.length}`);
  console.log(`  ${chalk.cyan('MCP Servers')}:    ${mcp.length}`);
  console.log(`  ${chalk.cyan('Agent Configs')}:  ${configs.length}`);
  console.log(`  ${chalk.cyan('Total')}:          ${bom.components.length}`);
  console.log();

  if (sdks.length > 0) {
    console.log(chalk.white.bold('  AI providers:'));
    const providers = [...new Set(sdks.map((s) => s.properties?.find((p) => p.name === 'ai:provider')?.value).filter(Boolean))];
    console.log(chalk.gray(`    ${providers.join(', ')}`));
    console.log();
  }

  console.log(chalk.gray(`  Written to ${outputFile}`));
  console.log();

  if (options.aiAct) {
    printAIActReadiness(generator.generateAIActReadiness(absolutePath));
  }
}

function printAIActReadiness(r) {
  output.header('EU AI Act — High-Risk Readiness');
  console.log();
  const color = r.level === 'strong' ? chalk.green : r.level === 'partial' ? chalk.yellow : chalk.red;
  console.log(`  Readiness: ${color.bold(`${r.score}%`)} ${color(`(${r.level})`)}  ·  ${r.passed}/${r.total} checks  ·  ${r.aiComponents} AI component(s)`);
  console.log();
  for (const c of r.checks) {
    const mark = c.pass ? chalk.green('✓') : chalk.red('✗');
    console.log(`  ${mark} ${c.pass ? chalk.gray(c.name) : chalk.white(c.name)}`);
  }
  console.log();
  if (r.gaps.length > 0) {
    console.log(chalk.yellow.bold('  Gaps to close before Aug 2 2026:'));
    for (const g of r.gaps) console.log(chalk.yellow(`    · ${g}`));
    console.log();
  }
  console.log(chalk.gray(`  ${r.disclaimer}`));
  console.log();
}
