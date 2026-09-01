/**
 * Capability graph — what can the agent working in this repo actually reach?
 * ===========================================================================
 *
 * Every other agent in this tool answers a question about one file. This one
 * answers a question about a machine: given the MCP servers configured, the
 * permissions granted, the workflows that run, and the instruction files an
 * assistant reads before it does anything, what is the set of things a coding
 * agent in this repository can touch — and which combinations of those things
 * are dangerous together while being unremarkable apart?
 *
 * That framing is the reason this exists rather than another rule file. A
 * wildcard MCP permission is a shrug on its own. A workflow holding a release
 * token is normal. An AGENTS.md that a contributor can edit is how the format
 * is meant to work. The three in one repository are a path from a pull request
 * to a signed release, and no single-file rule can see it, because no single
 * file contains it.
 *
 * It also answers the objection the product keeps running into — "why not ask
 * my coding agent to review this?" A coding agent reviewing the repo cannot see
 * the user's MCP config, cannot enumerate the permissions it was launched with,
 * and is the very actor whose reach is in question. This graph is assembled
 * from outside it.
 *
 * Deterministic throughout. Every node cites the file and line it was read
 * from, so a chain is a claim about observed configuration rather than a story
 * about one.
 *
 * USAGE:
 *   const graph = buildCapabilityGraph(rootPath);
 *   const chains = findAttackChains(graph);
 */

import fs from 'fs';
import path from 'path';
import { MCP_CONFIG_FILES } from '../agents/mcp-security-agent.js';
import { createFinding } from '../agents/base-agent.js';
import { attachEvidence, createClaim } from './evidence.js';

// =============================================================================
// WHAT WE LOOK AT
// =============================================================================

/** Permission and settings files that state what an agent is allowed to do. */
const SETTINGS_FILES = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.cursor/settings.json',
  '.vscode/settings.json',
];

/**
 * Files an assistant reads as instructions before acting. Anyone who can land a
 * commit can change these, which is what makes them a surface rather than
 * configuration.
 */
const INSTRUCTION_FILES = [
  'CLAUDE.md', '.claude/CLAUDE.md', 'AGENTS.md', 'AGENT.md',
  '.cursorrules', '.windsurfrules', '.clinerules',
  '.github/copilot-instructions.md', 'GEMINI.md', '.gemini/rules.md',
];

/** Tool names that write, execute, or leave the machine. */
const TOOL_ACCESS = [
  { match: /^Bash(\(|$)/i,                       kind: 'shell',      access: 'execute' },
  { match: /^(Write|Edit|MultiEdit|NotebookEdit)(\(|$)/i, kind: 'filesystem', access: 'write' },
  { match: /^(Read|Glob|Grep)(\(|$)/i,           kind: 'filesystem', access: 'read' },
  { match: /^(WebFetch|WebSearch)(\(|$)/i,       kind: 'network',    access: 'read' },
];

/** Env var names that look like a credential rather than a setting. */
const CREDENTIAL_NAME = /(?:_?(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|DSN|CONNECTION_?STRING))$/i;

/** MCP tool names whose effect leaves the local machine or changes state. */
const WRITE_TOOL_HINT = /(?:write|create|update|delete|remove|push|merge|publish|deploy|execute|run|exec|shell|command|insert|upsert|mutate|send|post)/i;

// =============================================================================
// GRAPH CONSTRUCTION
// =============================================================================

/**
 * Read the configuration around a repository into a graph of actors,
 * capabilities, surfaces, and credentials.
 *
 * `includeEnvironment` pulls in the operator's own MCP configuration from their
 * home directory. That is genuinely useful locally — those servers are reachable
 * from this repo's session — and is off by default because the names of someone's
 * personal servers have no business in a repository's security report, and
 * because a benchmark or a pipeline that reads them stops being reproducible.
 */
export function buildCapabilityGraph(rootPath, { includeEnvironment = false, homeDir = null } = {}) {
  const graph = {
    root: rootPath,
    actors: [],
    capabilities: [],
    surfaces: [],
    credentials: [],
    sources: [],
  };

  readSettings(graph, rootPath);
  readMcpConfigs(graph, rootPath, { includeEnvironment, homeDir });
  readInstructionFiles(graph, rootPath);
  readWorkflows(graph, rootPath);

  return graph;
}

// ── Actors ──────────────────────────────────────────────────────────────────

function actor(graph, { id, name, kind, file, line = 1, scope = 'project' }) {
  const existing = graph.actors.find((a) => a.id === id);
  if (existing) return existing;
  const node = { id, name, kind, file, line, scope };
  graph.actors.push(node);
  return node;
}

function capability(graph, node) {
  graph.capabilities.push(node);
  return node;
}

// ── Settings: what the agent was granted ────────────────────────────────────

function readSettings(graph, rootPath) {
  for (const rel of SETTINGS_FILES) {
    const abs = path.join(rootPath, rel);
    const parsed = readJson(abs);
    if (!parsed) continue;

    graph.sources.push(rel);
    const owner = actor(graph, {
      id: `agent:${rel}`,
      name: agentNameFor(rel),
      kind: 'agent',
      file: rel,
    });

    const permissions = parsed.json.permissions || {};
    const allow = [].concat(permissions.allow || [], parsed.json.allowedTools || []);
    const deny = [].concat(permissions.deny || []);

    for (const entry of allow) {
      const spec = String(entry);
      const line = findLine(parsed.text, spec);

      const mcpTool = spec.match(/^mcp__([^_]+(?:_[^_]+)*?)__(.+)$/);
      if (mcpTool) {
        capability(graph, {
          actor: owner.id, kind: 'mcp-tool', access: accessOfTool(mcpTool[2]),
          value: spec, server: mcpTool[1], tool: mcpTool[2],
          granted: 'allow', file: rel, line, scope: 'project',
        });
        continue;
      }

      const match = TOOL_ACCESS.find((t) => t.match.test(spec));
      if (match) {
        capability(graph, {
          actor: owner.id, kind: match.kind, access: match.access,
          value: spec, granted: 'allow', file: rel, line, scope: 'project',
        });
      }
    }

    // A permission mode that skips prompting turns every capability the agent
    // has into an unattended one, which is what most chains below depend on.
    const mode = parsed.json.permissionMode || parsed.json.defaultMode || permissions.defaultMode || '';
    if (/bypassPermissions|acceptEdits|danger|dangerously/i.test(String(mode))
        || parsed.json.dangerouslySkipPermissions === true) {
      owner.unattended = true;
      owner.unattendedSource = { file: rel, line: findLine(parsed.text, String(mode) || 'dangerouslySkipPermissions') };
    }

    if (parsed.json.enableAllProjectMcpServers === true) {
      owner.autoEnablesRepoServers = true;
      owner.autoEnableSource = { file: rel, line: findLine(parsed.text, 'enableAllProjectMcpServers') };
    }

    owner.deniedCount = deny.length;
  }
}

function accessOfTool(toolName) {
  return WRITE_TOOL_HINT.test(toolName) ? 'write' : 'read';
}

function agentNameFor(rel) {
  if (rel.startsWith('.claude/')) return 'Claude Code';
  if (rel.startsWith('.cursor/')) return 'Cursor';
  if (rel.startsWith('.vscode/')) return 'VS Code';
  return rel;
}

// ── MCP: what the agent can call ────────────────────────────────────────────

function readMcpConfigs(graph, rootPath, { includeEnvironment, homeDir }) {
  const candidates = MCP_CONFIG_FILES.map((rel) => ({ abs: path.join(rootPath, rel), rel, scope: 'project' }));

  if (includeEnvironment) {
    const home = homeDir || process.env.HOME || process.env.USERPROFILE;
    if (home) {
      candidates.push(
        { abs: path.join(home, '.cursor', 'mcp.json'), rel: '~/.cursor/mcp.json', scope: 'environment' },
        { abs: path.join(home, '.claude.json'), rel: '~/.claude.json', scope: 'environment' },
        { abs: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), rel: '~/Library/Application Support/Claude/claude_desktop_config.json', scope: 'environment' },
        { abs: path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'), rel: '~/AppData/Roaming/Claude/claude_desktop_config.json', scope: 'environment' },
      );
    }
  }

  for (const { abs, rel, scope } of candidates) {
    const parsed = readJson(abs);
    if (!parsed) continue;

    const servers = parsed.json.mcpServers || parsed.json.servers || parsed.json.mcp?.servers || {};
    if (!servers || typeof servers !== 'object') continue;
    graph.sources.push(rel);

    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      const line = findLine(parsed.text, `"${name}"`);
      const owner = actor(graph, {
        id: `mcp:${rel}:${name}`, name, kind: 'mcp-server', file: rel, line, scope,
      });
      owner.command = server.command || server.url || null;

      // A stdio server is a program this machine launches. That is a shell
      // capability wearing a config file's clothes.
      if (server.command) {
        capability(graph, {
          actor: owner.id, kind: 'shell', access: 'execute',
          value: [server.command, ...(server.args || [])].join(' ').slice(0, 200),
          granted: 'mcp-server', file: rel, line, scope,
        });
      }

      for (const [envName, envValue] of Object.entries(server.env || {})) {
        if (!CREDENTIAL_NAME.test(envName)) continue;
        graph.credentials.push({
          id: `cred:${rel}:${name}:${envName}`,
          name: envName,
          holder: owner.id,
          // The value is never recorded. Whether it is inline or interpolated
          // is the part that matters, and the secret itself is not ours to copy.
          inline: typeof envValue === 'string' && !/^\$\{?[A-Z_]/.test(envValue) && envValue.length > 0,
          file: rel, line: findLine(parsed.text, `"${envName}"`) || line, scope,
        });
      }

      const auto = server.autoApprove || server.alwaysAllow || server.autoAllow;
      if (auto) {
        const tools = Array.isArray(auto) ? auto : ['*'];
        for (const tool of tools) {
          capability(graph, {
            actor: owner.id, kind: 'mcp-tool',
            access: tool === '*' ? 'write' : accessOfTool(String(tool)),
            value: String(tool), server: name, tool: String(tool),
            granted: 'auto-approved', wildcard: tool === '*',
            file: rel, line, scope,
          });
        }
      }
    }
  }
}

// ── Surfaces: what untrusted input the agent ingests ────────────────────────

function readInstructionFiles(graph, rootPath) {
  for (const rel of INSTRUCTION_FILES) {
    const abs = path.join(rootPath, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    graph.sources.push(rel);
    graph.surfaces.push({
      id: `surface:${rel}`,
      kind: 'repo-instructions',
      file: rel,
      line: 1,
      note: 'Read as instructions by an assistant working in this repository, and editable by anyone who can land a commit.',
    });
  }
}

/**
 * Workflows contribute two things: triggers that run repository-controlled code
 * with repository credentials, and the names of the credentials they expose.
 */
function readWorkflows(graph, rootPath) {
  const dir = path.join(rootPath, '.github', 'workflows');
  if (!fs.existsSync(dir)) return;

  let entries;
  try {
    entries = fs.readdirSync(dir).filter((f) => /\.ya?ml$/i.test(f));
  } catch { return; }

  for (const entry of entries) {
    const rel = path.join('.github', 'workflows', entry).replace(/\\/g, '/');
    let text;
    try { text = fs.readFileSync(path.join(dir, entry), 'utf-8'); } catch { continue; }
    graph.sources.push(rel);

    const lines = text.split('\n');
    lines.forEach((lineText, index) => {
      const line = index + 1;

      if (/^\s*(?:pull_request_target|workflow_run)\s*:/.test(lineText)) {
        graph.surfaces.push({
          id: `surface:${rel}:${line}`,
          kind: 'privileged-trigger',
          trigger: lineText.trim().replace(/:.*$/, ''),
          file: rel, line,
          note: 'Runs with repository credentials in a context a fork can influence.',
        });
      }

      for (const match of lineText.matchAll(/secrets\.([A-Z0-9_]+)/g)) {
        if (match[1] === 'GITHUB_TOKEN') continue; // scoped per-run; not a standing credential
        // The same secret is referenced on many lines of a workflow. It is one
        // credential; recording it once with a reference count keeps a chain
        // from reading like five separate problems.
        const id = `cred:${rel}:${match[1]}`;
        const seen = graph.credentials.find((c) => c.id === id);
        if (seen) { seen.references += 1; continue; }
        graph.credentials.push({
          id,
          name: match[1],
          holder: `workflow:${rel}`,
          inline: false,
          references: 1,
          file: rel, line, scope: 'project',
        });
      }
    });
  }
}

// =============================================================================
// AGGREGATION
// =============================================================================

/**
 * Collapse capabilities into one row per actor, kind, and access level.
 *
 * A settings file can hold hundreds of individually approved commands. Listing
 * them is not a description of reach — "shell execution, 573 pre-granted
 * entries" is, and naming two of them shows the reader what kind of entries
 * they are without pretending the other 571 are different in nature.
 */
export function summarizeCapabilities(graph) {
  const groups = new Map();

  for (const cap of graph.capabilities) {
    const key = `${cap.actor}|${cap.kind}|${cap.access}`;
    if (!groups.has(key)) {
      groups.set(key, {
        actor: cap.actor, kind: cap.kind, access: cap.access,
        scope: cap.scope, count: 0, wildcard: false, examples: [],
      });
    }
    const group = groups.get(key);
    group.count += 1;
    group.wildcard = group.wildcard || Boolean(cap.wildcard);
    if (group.examples.length < 2) {
      group.examples.push({ value: truncate(cap.value), file: cap.file, line: cap.line });
    }
  }

  return [...groups.values()].sort((a, b) => b.count - a.count);
}

// =============================================================================
// CHAINS
// =============================================================================

/**
 * Combinations that are dangerous together and unremarkable apart.
 *
 * Each returns a chain with numbered steps, every step citing the file and line
 * it was observed at. A chain with an unciteable step is a hypothesis, and this
 * function does not deal in those.
 */
export function findAttackChains(graph) {
  const chains = [];
  const instructions = graph.surfaces.filter((s) => s.kind === 'repo-instructions');
  const triggers = graph.surfaces.filter((s) => s.kind === 'privileged-trigger');
  const writeCaps = graph.capabilities.filter((c) => c.access === 'write' || c.access === 'execute');
  const shellCaps = graph.capabilities.filter((c) => c.kind === 'shell');
  const wildcards = graph.capabilities.filter((c) => c.wildcard);
  const inlineCreds = graph.credentials.filter((c) => c.inline);

  // ── 1. Repo-controlled instructions reaching an unattended write path ─────
  const unattended = graph.actors.filter((a) => a.unattended);
  for (const surface of instructions) {
    for (const agentNode of unattended) {
      const reachable = groupsFor(graph, agentNode.id, (g) => g.access === 'write' || g.access === 'execute');
      if (!reachable.length) continue;
      chains.push({
        rule: 'CHAIN_UNTRUSTED_INSTRUCTIONS_TO_UNATTENDED_WRITE',
        title: 'Repository-controlled instructions reach an unattended write capability',
        severity: 'critical',
        steps: [
          step(`${surface.file} is read as instructions and can be changed by anyone who lands a commit`, surface.file, surface.line),
          step(`${agentNode.name} runs without per-action approval`, agentNode.unattendedSource?.file || agentNode.file, agentNode.unattendedSource?.line || agentNode.line),
          ...reachable.map((g) => step(describeGroup(g), g.examples[0].file, g.examples[0].line)),
        ],
        impact: 'Text committed to this repository can direct the agent to write files or run commands with no human in the loop.',
        recommendation: 'Require approval for write and execute tools during sessions on untrusted branches, or remove the pre-granted entries.',
      });
    }
  }

  // ── 2. Instructions reaching a shell capability at all ───────────────────
  const shellGroups = summarizeCapabilities(graph).filter((g) => g.kind === 'shell');
  if (instructions.length && shellCaps.length && !unattended.length) {
    const surface = instructions[0];
    chains.push({
      rule: 'CHAIN_UNTRUSTED_INSTRUCTIONS_TO_SHELL',
      title: 'Repository-controlled instructions reach a shell capability',
      severity: 'high',
      steps: [
        step(`${surface.file} is read as instructions before the agent acts`, surface.file, surface.line),
        ...shellGroups.map((g) => step(describeGroup(g), g.examples[0].file, g.examples[0].line)),
      ],
      impact: 'A contributed instruction file can propose commands to an agent that is able to run them. Approval is the only remaining control.',
      recommendation: 'Treat instruction files as untrusted input in review, and keep approval prompts on for shell tools.',
    });
  }

  // ── 3. A wildcard tool grant next to a standing credential ───────────────
  for (const wildcard of wildcards) {
    const holder = graph.actors.find((a) => a.id === wildcard.actor);
    const creds = graph.credentials.filter((c) => c.holder === wildcard.actor);
    chains.push({
      rule: 'CHAIN_WILDCARD_GRANT_OVER_CREDENTIALED_SERVER',
      title: 'Wildcard tool approval on a server that holds a credential',
      severity: creds.length ? 'critical' : 'high',
      steps: [
        step(`${holder?.name || wildcard.actor} auto-approves every tool it exposes`, wildcard.file, wildcard.line),
        ...creds.slice(0, 3).map((c) => step(`${c.name} is configured on that server${c.inline ? ' as a literal value' : ''}`, c.file, c.line)),
      ],
      impact: creds.length
        ? 'Any tool this server adds — including one added in a later version — is approved in advance and runs with that credential.'
        : 'Any tool this server adds in a later version is approved in advance, without review.',
      recommendation: 'Replace the wildcard with an explicit list of the tools actually used.',
    });
  }

  // ── 4. Agent write access reaching workflow credentials ──────────────────
  const workflowCreds = graph.credentials.filter((c) => String(c.holder).startsWith('workflow:'));
  if (writeCaps.length && workflowCreds.length) {
    chains.push({
      rule: 'CHAIN_AGENT_WRITE_REACHES_CI_CREDENTIALS',
      title: 'Agent write access reaches workflow credentials',
      severity: triggers.length ? 'critical' : 'high',
      steps: [
        ...summarizeCapabilities(graph)
          .filter((g) => g.access === 'write' || g.access === 'execute')
          .map((g) => step(`${describeGroup(g)} — enough to modify repository contents`, g.examples[0].file, g.examples[0].line)),
        ...(triggers.length ? [step(`${triggers[0].trigger} runs repository-controlled code with repository credentials`, triggers[0].file, triggers[0].line)] : []),
        ...workflowCreds.slice(0, 3).map((c) => step(`${c.name} is exposed to that workflow`, c.file, c.line)),
      ],
      impact: 'A change the agent writes is a change CI executes. The agent\'s blast radius includes every secret the pipeline holds.',
      recommendation: 'Keep workflow files out of the agent\'s writable set, and scope release credentials to workflows a fork cannot influence.',
    });
  }

  // ── 5. A credential written literally into a config file ─────────────────
  for (const cred of inlineCreds) {
    chains.push({
      rule: 'CHAIN_INLINE_CREDENTIAL_IN_AGENT_CONFIG',
      title: 'Credential stored literally in an agent configuration file',
      severity: 'critical',
      steps: [step(`${cred.name} holds a literal value rather than an environment reference`, cred.file, cred.line)],
      impact: 'The credential is readable by every process that reads this config, and by anyone the file is shared with.',
      recommendation: 'Move the value to the environment and reference it as ${' + cred.name + '}.',
    });
  }

  return chains;
}

function groupsFor(graph, actorId, predicate) {
  return summarizeCapabilities(graph).filter((g) => g.actor === actorId && predicate(g));
}

/** "shell execution, 573 pre-granted entries (e.g. Bash(git status), …)" */
function describeGroup(group) {
  const label = `${group.kind} ${group.access}`;
  const examples = group.examples.map((e) => e.value).join(', ');
  if (group.wildcard) return `${label} granted by wildcard`;
  return group.count === 1
    ? `${label} granted: ${examples}`
    : `${label}, ${group.count} pre-granted entries (e.g. ${examples})`;
}

function step(text, file, line) {
  return { text, file, line: line || 1 };
}

function truncate(value, max = 60) {
  const str = String(value);
  return str.length > max ? `${str.slice(0, max - 1)}…` : str;
}

// =============================================================================
// READING HELPERS
// =============================================================================

function readJson(abs) {
  let text;
  try {
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
    text = fs.readFileSync(abs, 'utf-8');
  } catch { return null; }

  try {
    return { json: JSON.parse(stripJsonComments(text)), text };
  } catch {
    // A config we cannot parse is not a config we can reason about. Saying
    // nothing is correct; guessing at half-valid JSON is not.
    return null;
  }
}

/** VS Code and Cursor settings files are JSONC in practice. */
function stripJsonComments(text) {
  return text
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');
}

/**
 * Locate a needle so a node can cite the line it came from.
 *
 * The value handed in has been through JSON.parse, so its escaping no longer
 * matches the file — a permission entry containing a backslash is one character
 * in memory and two on disk, and a naive search silently cites line 1. Re-encode
 * before searching, and fall back to a distinctive prefix for entries long
 * enough to be wrapped or truncated.
 */
function findLine(text, needle) {
  if (!needle) return 1;
  const lines = text.split('\n');

  for (const candidate of [JSON.stringify(String(needle)).slice(1, -1), String(needle)]) {
    const index = lines.findIndex((line) => line.includes(candidate));
    if (index !== -1) return index + 1;
    if (candidate.length > 24) {
      const prefix = candidate.slice(0, 24);
      const partial = lines.findIndex((line) => line.includes(prefix));
      if (partial !== -1) return partial + 1;
    }
  }
  return 1;
}

// =============================================================================
// FINDINGS
// =============================================================================

/**
 * Express chains as findings so they flow through scoring, reports, and CI the
 * same way everything else does.
 *
 * The claim is 'likely', never 'confirmed'. Every link is directly observed, so
 * the *reachability* is a fact — but the finding asserts that an attacker could
 * use the path, and configuration alone does not establish that. 'confirmed'
 * stays reserved for a pass that reproduces the effect, which keeps the word
 * worth something.
 */
export function chainFindings(chains, rootPath = process.cwd()) {
  return chains.map((chain) => {
    const anchor = chain.steps[0];
    const finding = createFinding({
      file: path.resolve(rootPath, anchor.file),
      line: anchor.line,
      severity: chain.severity,
      category: 'agentic',
      rule: chain.rule,
      title: chain.title,
      description: `${chain.impact} Path: ${chain.steps.map((s) => s.text).join(' → ')}`,
      fix: chain.recommendation,
      cwe: 'CWE-269',
      confidence: 'high',
    });

    return attachEvidence(finding, createClaim({
      source: 'chain',
      verdict: 'likely',
      rationale: chain.impact,
      citations: chain.steps.map((s) => ({ file: path.resolve(rootPath, s.file), line: s.line })),
      attackPath: chain.steps.map((s) => s.text),
    }));
  });
}
