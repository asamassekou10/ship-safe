/**
 * ABOM Command
 * =============
 *
 * Generate an Agent Bill of Materials in CycloneDX format.
 * Lists all AI agent components: MCP servers, skills, configs, LLM providers.
 *
 * USAGE:
 *   ship-safe abom [path]               Generate ABOM
 *   ship-safe abom . -o agent-bom.json  Custom output path
 */

import path from 'path';
import chalk from 'chalk';
import { ABOMGenerator } from '../agents/abom-generator.js';
import * as output from '../utils/output.js';

export async function abomCommand(targetPath = '.', options = {}) {
  const absolutePath = path.resolve(targetPath);
  const outputFile = options.output || 'abom.json';

  console.log();
  output.header('Ship Safe — Agent Bill of Materials');
  console.log();

  const generator = new ABOMGenerator();
  const bom = generator.generate(absolutePath);

  if (options.json) {
    console.log(JSON.stringify(bom, null, 2));
    return;
  }

  generator.generateToFile(absolutePath, outputFile);

  const agentComponents = bom.components.filter(c => c.properties?.some(p => p.name?.startsWith('agent:')));
  const mcpServers = agentComponents.filter(c => c.properties?.some(p => p.value === 'mcp-server'));
  const skills = agentComponents.filter(c => c.properties?.some(p => p.value === 'openclaw-skill'));
  const configs = agentComponents.filter(c => c.properties?.some(p => p.value === 'agent-rules' || p.value === 'agent-config'));
  const providers = agentComponents.filter(c => c.properties?.some(p => p.value === 'llm-provider'));

  console.log(chalk.gray(`  Project: ${bom.metadata.component.name}`));
  console.log();
  console.log(`  ${chalk.cyan('MCP Servers')}:      ${mcpServers.length}`);
  console.log(`  ${chalk.cyan('OpenClaw Skills')}:  ${skills.length}`);
  console.log(`  ${chalk.cyan('Agent Configs')}:    ${configs.length}`);
  console.log(`  ${chalk.cyan('LLM Providers')}:    ${providers.length}`);
  console.log(`  ${chalk.cyan('Total Components')}: ${bom.components.length}`);
  console.log();

  if (mcpServers.length > 0) {
    console.log(chalk.white.bold('  MCP Servers:'));
    for (const s of mcpServers) {
      const cmd = s.properties?.find(p => p.name === 'agent:command')?.value || 'N/A';
      console.log(chalk.gray(`    · ${s.name} (${cmd})`));
    }
    console.log();
  }

  if (skills.length > 0) {
    console.log(chalk.white.bold('  OpenClaw Skills:'));
    for (const s of skills) {
      const verified = s.properties?.find(p => p.name === 'agent:verified')?.value;
      const icon = verified === 'true' ? chalk.green('✔') : chalk.yellow('?');
      console.log(chalk.gray(`    ${icon} ${s.name}`));
    }
    console.log();
  }

  console.log(chalk.green(`  ✔ ABOM saved to ${outputFile}`));
  console.log(chalk.gray(`    Format: CycloneDX ${bom.specVersion}`));
  console.log();
}
