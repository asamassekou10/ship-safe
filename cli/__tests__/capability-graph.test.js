/**
 * Capability graph — inventory, citation accuracy, and chain construction.
 *
 * The fixtures below are the shapes the graph exists to reason about: an
 * instruction file anyone can edit, a wildcard tool approval, a server holding
 * a credential, and a workflow that runs repository-controlled code with
 * repository secrets. Individually ordinary; the chains are the point.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  buildCapabilityGraph,
  findAttackChains,
  summarizeCapabilities,
  chainFindings,
} from '../utils/capability-graph.js';
import { validateCitations } from '../utils/evidence.js';

let ROOT;

const write = (rel, content) => {
  const abs = path.join(ROOT, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
};

before(() => {
  ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-capgraph-'));

  write('.claude/settings.json', JSON.stringify({
    permissionMode: 'bypassPermissions',
    enableAllProjectMcpServers: true,
    permissions: {
      allow: ['Bash(git push:*)', 'Write', 'Read(src/**)', 'WebFetch', 'mcp__github__create_pull_request', 'mcp__github__get_file'],
      deny: ['Read(.env)'],
    },
  }, null, 2));

  write('.mcp.json', JSON.stringify({
    mcpServers: {
      github: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github'],
        autoApprove: ['*'],
        env: { GITHUB_TOKEN: 'ghp_literalvaluenotareference' },
      },
      docs: {
        command: 'node',
        args: ['./docs-server.js'],
        env: { DOCS_URL: 'https://example.com' },
      },
    },
  }, null, 2));

  write('CLAUDE.md', '# Project instructions\n\nBuild with npm run build.\n');

  write('.github/workflows/release.yml', [
    'name: release',
    'on:',
    '  pull_request_target:',
    '    types: [opened]',
    'jobs:',
    '  publish:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: npm publish',
    '        env:',
    '          NPM_TOKEN: ${{ secrets.RELEASE_TOKEN }}',
    '          AGAIN: ${{ secrets.RELEASE_TOKEN }}',
    '          RUNNER: ${{ secrets.GITHUB_TOKEN }}',
  ].join('\n'));
});

after(() => fs.rmSync(ROOT, { recursive: true, force: true }));

describe('capability inventory', () => {
  it('reads every configured source', () => {
    const graph = buildCapabilityGraph(ROOT);
    assert.deepEqual(graph.sources.sort(), ['.claude/settings.json', '.github/workflows/release.yml', '.mcp.json', 'CLAUDE.md']);
  });

  it('classifies tool grants by what they can do', () => {
    const groups = summarizeCapabilities(buildCapabilityGraph(ROOT));
    const kinds = groups.map((g) => `${g.kind}:${g.access}`);

    assert.ok(kinds.includes('shell:execute'), 'Bash is shell execution');
    assert.ok(kinds.includes('filesystem:write'), 'Write is a filesystem write');
    assert.ok(kinds.includes('filesystem:read'), 'Read is not');
    assert.ok(kinds.includes('network:read'), 'WebFetch leaves the machine');
    assert.ok(kinds.includes('mcp-tool:write'), 'create_pull_request changes state');
    assert.ok(kinds.includes('mcp-tool:read'), 'get_file does not');
  });

  it('marks an agent that runs without per-action approval', () => {
    const graph = buildCapabilityGraph(ROOT);
    const agent = graph.actors.find((a) => a.id === 'agent:.claude/settings.json');
    assert.equal(agent.unattended, true);
    assert.equal(agent.autoEnablesRepoServers, true);
  });

  it('treats a stdio MCP server as the shell capability it is', () => {
    const graph = buildCapabilityGraph(ROOT);
    const server = graph.capabilities.find((c) => c.actor === 'mcp:.mcp.json:docs' && c.kind === 'shell');
    assert.ok(server, 'a server launched by command can run code on this machine');
    assert.match(server.value, /node \.\/docs-server\.js/);
  });

  it('records a credential without recording its value', () => {
    const graph = buildCapabilityGraph(ROOT);
    const token = graph.credentials.find((c) => c.name === 'GITHUB_TOKEN');
    assert.equal(token.inline, true, 'a literal is distinguishable from an env reference');
    assert.equal(JSON.stringify(graph).includes('ghp_literalvalue'), false, 'the secret is never copied into the graph');
  });

  it('ignores env entries that are not credentials', () => {
    const graph = buildCapabilityGraph(ROOT);
    assert.equal(graph.credentials.some((c) => c.name === 'DOCS_URL'), false);
  });

  it('counts a repeated workflow secret once', () => {
    const graph = buildCapabilityGraph(ROOT);
    const release = graph.credentials.filter((c) => c.name === 'RELEASE_TOKEN');
    assert.equal(release.length, 1);
    assert.equal(release[0].references, 2);
  });

  it('skips GITHUB_TOKEN, which is scoped per run rather than standing', () => {
    const graph = buildCapabilityGraph(ROOT);
    assert.equal(graph.credentials.some((c) => c.holder?.startsWith('workflow:') && c.name === 'GITHUB_TOKEN'), false);
  });

  it('treats an instruction file and a privileged trigger as untrusted surfaces', () => {
    const kinds = buildCapabilityGraph(ROOT).surfaces.map((s) => s.kind);
    assert.ok(kinds.includes('repo-instructions'));
    assert.ok(kinds.includes('privileged-trigger'));
  });

  it('leaves the operator machine out unless asked', () => {
    const graph = buildCapabilityGraph(ROOT, { includeEnvironment: false });
    assert.equal(graph.actors.some((a) => a.scope === 'environment'), false);
    assert.equal(graph.sources.some((s) => s.startsWith('~')), false);
  });

  it('says nothing about a repository that configures nothing', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-capgraph-empty-'));
    const graph = buildCapabilityGraph(empty);
    assert.deepEqual(graph.sources, []);
    assert.deepEqual(findAttackChains(graph), []);
    fs.rmSync(empty, { recursive: true, force: true });
  });

  it('reports nothing for a config it cannot parse rather than guessing', () => {
    const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-capgraph-broken-'));
    fs.mkdirSync(path.join(broken, '.claude'));
    fs.writeFileSync(path.join(broken, '.claude/settings.json'), '{ "permissions": { "allow": [ ');
    assert.deepEqual(buildCapabilityGraph(broken).sources, []);
    fs.rmSync(broken, { recursive: true, force: true });
  });
});

describe('attack chains', () => {
  it('finds the injection-to-unattended-write path', () => {
    const chains = findAttackChains(buildCapabilityGraph(ROOT));
    const chain = chains.find((c) => c.rule === 'CHAIN_UNTRUSTED_INSTRUCTIONS_TO_UNATTENDED_WRITE');

    assert.ok(chain, 'repo instructions + no approval + write grants is a path');
    assert.equal(chain.severity, 'critical');
    assert.ok(chain.steps.length >= 3);
    assert.match(chain.steps[0].text, /CLAUDE\.md/);
  });

  it('finds the wildcard grant over a credentialed server', () => {
    const chains = findAttackChains(buildCapabilityGraph(ROOT));
    const chain = chains.find((c) => c.rule === 'CHAIN_WILDCARD_GRANT_OVER_CREDENTIALED_SERVER');

    assert.ok(chain);
    assert.equal(chain.severity, 'critical', 'a wildcard next to a credential is worse than a wildcard alone');
    assert.match(chain.steps.map((s) => s.text).join(' '), /GITHUB_TOKEN/);
  });

  it('finds the write-access-to-CI-credentials path', () => {
    const chains = findAttackChains(buildCapabilityGraph(ROOT));
    const chain = chains.find((c) => c.rule === 'CHAIN_AGENT_WRITE_REACHES_CI_CREDENTIALS');

    assert.ok(chain);
    assert.equal(chain.severity, 'critical', 'a privileged trigger raises it');
    assert.match(chain.steps.map((s) => s.text).join(' '), /RELEASE_TOKEN/);
  });

  it('flags a credential written as a literal', () => {
    const chains = findAttackChains(buildCapabilityGraph(ROOT));
    assert.ok(chains.some((c) => c.rule === 'CHAIN_INLINE_CREDENTIAL_IN_AGENT_CONFIG'));
  });

  it('does not chain instructions to shell when approval is still required', () => {
    const attended = fs.mkdtempSync(path.join(os.tmpdir(), 'ship-safe-capgraph-attended-'));
    fs.mkdirSync(path.join(attended, '.claude'));
    fs.writeFileSync(path.join(attended, '.claude/settings.json'), JSON.stringify({ permissions: { allow: ['Bash(npm test)'] } }));
    fs.writeFileSync(path.join(attended, 'AGENTS.md'), '# instructions');

    const chains = findAttackChains(buildCapabilityGraph(attended));
    assert.equal(chains.some((c) => c.rule === 'CHAIN_UNTRUSTED_INSTRUCTIONS_TO_UNATTENDED_WRITE'), false);
    assert.ok(chains.some((c) => c.rule === 'CHAIN_UNTRUSTED_INSTRUCTIONS_TO_SHELL'), 'the weaker chain still applies');
    fs.rmSync(attended, { recursive: true, force: true });
  });

  it('cites a real file and line for every step', () => {
    const chains = findAttackChains(buildCapabilityGraph(ROOT));
    assert.ok(chains.length > 0);

    for (const chain of chains) {
      for (const step of chain.steps) {
        const abs = path.join(ROOT, step.file);
        assert.ok(fs.existsSync(abs), `${chain.rule} cites a missing file: ${step.file}`);
        const lines = fs.readFileSync(abs, 'utf-8').split('\n').length;
        assert.ok(step.line >= 1 && step.line <= lines, `${chain.rule} cites ${step.file}:${step.line} beyond ${lines} lines`);
      }
    }
  });
});

describe('chain findings', () => {
  it('emits findings whose citations pass validation', () => {
    const findings = chainFindings(findAttackChains(buildCapabilityGraph(ROOT)), ROOT);
    assert.ok(findings.length > 0);

    for (const finding of findings) {
      const [claim] = finding.evidence.claims;
      assert.equal(claim.source, 'chain');
      assert.equal(validateCitations(claim, { rootPath: ROOT }).status, 'valid');
      assert.ok(claim.attackPath.length > 0, 'a chain finding carries its path');
    }
  });

  it('claims likely, never confirmed, from configuration alone', () => {
    const findings = chainFindings(findAttackChains(buildCapabilityGraph(ROOT)), ROOT);
    for (const finding of findings) {
      assert.equal(finding.evidence.verdict, 'likely', 'confirmed is reserved for a pass that reproduces the effect');
    }
  });
});
