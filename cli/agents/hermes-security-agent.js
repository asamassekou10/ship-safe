/**
 * HermesSecurityAgent — Ship Safe × Hermes Agent
 * =================================================
 *
 * Detects security vulnerabilities specific to Hermes Agent deployments:
 * tool registry poisoning, function-call injection, memory layer attacks,
 * skill permission drift, multi-agent trust boundary violations, and
 * agent manifest attestation failures.
 *
 * Hermes Agent (NousResearch) is an open-source autonomous agent framework
 * featuring a 4-layer memory system, markdown skill playbooks, a self-
 * registering tool registry, and multi-agent orchestration — all of which
 * introduce novel attack surfaces beyond traditional LLM prompt injection.
 *
 * SCANNING TARGETS:
 *   - hermes.config.{js,ts,json,yaml}
 *   - agents.{json,yaml}, agent-manifest.{json,yaml}
 *   - tool-registry.{js,ts,json}, tools/*.{js,ts,json}
 *   - skills/*.md, .hermes/**, hermes-skills/**
 *   - Any source file importing @nousresearch/hermes-agent or hermes-agent
 *   - Memory layer files: .hermes/memory/, episodic/, semantic/, working/
 *
 * OWASP MAPPING:
 *   ASI-01 Goal Hijacking, ASI-02 Excessive Agency,
 *   ASI-03 Unsafe Tool Use, ASI-04 Inadequate Sandboxing,
 *   ASI-05 Untrusted Tools, ASI-06 Memory Poisoning,
 *   ASI-07 Lack of Oversight, ASI-10 Supply Chain
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// FILES THIS AGENT SCANS
// =============================================================================

const HERMES_FILE_PATTERNS = [
  '**/hermes.config.{js,ts,json,yaml,yml}',
  '**/agents.{json,yaml,yml}',
  '**/agent-manifest.{json,yaml,yml}',
  '**/tool-registry.{js,ts,json}',
  '**/tools/**/*.{js,ts,json}',
  '**/skills/**/*.md',
  '**/.hermes/**/*',
  '**/hermes-skills/**/*.md',
  '**/hermes-tools/**/*.{js,ts}',
  '**/*.{js,ts,py}',           // Source files using hermes-agent SDK
];

// =============================================================================
// SINGLE-LINE REGEX PATTERNS
// =============================================================================

const PATTERNS = [

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-1: Tool Registry Poisoning
  // Attacker controls the source URL of the tool registry, injecting
  // malicious tool definitions that silently replace legitimate ones.
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_REGISTRY_REMOTE_URL',
    title: 'Hermes: Tool Registry Loaded From Unvalidated Remote URL',
    regex: /(?:loadRegistry|registerTools|toolRegistry|addTools)\s*\(\s*(?:await\s+fetch|http|https|axios|got|request)\s*\(\s*[^'"]/gi,
    severity: 'critical',
    cwe: 'CWE-829',
    owasp: 'ASI05',
    description: 'The Hermes tool registry is populated from an unvalidated remote URL. An attacker who controls or MITMs the endpoint can inject malicious tool definitions that override legitimate tools — silently hijacking all agent tool calls.',
    fix: 'Pin the registry URL to a specific commit hash or use a signed manifest. Validate each tool definition against an allowlist schema before registration.',
    confidence: 'high',
  },

  {
    rule: 'HERMES_REGISTRY_ENV_VAR_URL',
    title: 'Hermes: Tool Registry URL Controlled by Environment Variable',
    regex: /(?:loadRegistry|registerTools|toolRegistry)\s*\(\s*process\.env\.[A-Z_]+/gi,
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'ASI05',
    description: 'Tool registry URL sourced from an environment variable. If the env var is compromised (leaked .env, CI/CD secret exposure), an attacker can redirect the registry to a malicious endpoint without changing source code.',
    fix: 'Hard-code the registry URL or use a configuration file checked into source control with integrity verification.',
    confidence: 'high',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-2: Function-Call Injection
  // LLM output used directly as the tool name or arguments without an allowlist.
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_FUNCTION_CALL_NO_ALLOWLIST',
    title: 'Hermes: LLM Output Used as Tool Name Without Allowlist',
    regex: /(?:callTool|executeTool|invokeTool|runTool|dispatch)\s*\(\s*(?:response|output|result|llmOutput|toolCall|parsed)[\w.[\]'"]*(?:\.name|\.tool_name|\.function_name|(?:\[['"]name['"]\]))/gi,
    severity: 'critical',
    cwe: 'CWE-20',
    owasp: 'ASI03',
    description: 'LLM response used directly as the tool name to invoke without an allowlist check. A prompt injection attack can force the agent to call any registered tool — including dangerous system tools — by injecting a crafted tool name into the LLM output.',
    fix: 'Validate the tool name against an explicit allowlist before dispatch: if (!ALLOWED_TOOLS.has(toolName)) throw new Error("Forbidden tool: " + toolName);',
    confidence: 'high',
  },

  {
    rule: 'HERMES_XML_TOOL_CALL_UNSAFE_PARSE',
    title: 'Hermes: Unsafe Parsing of XML-Wrapped Tool Call',
    regex: /(?:parseXML|xml2js|xmlParser|DOMParser|new\s+XMLParser)\s*\([^)]*(?:tool_call|function_call|hermes_call)/gi,
    severity: 'high',
    cwe: 'CWE-611',
    owasp: 'ASI03',
    description: 'XML-wrapped Hermes function calls parsed without XXE protection. A malicious <tool_call> payload could trigger XML External Entity (XXE) injection, reading local files or performing SSRF attacks through the XML parser.',
    fix: 'Disable external entity resolution: set processEntities: false (xml2js), or use a JSON-only parser for Hermes function calls where possible.',
    confidence: 'medium',
  },

  {
    rule: 'HERMES_TOOL_ARGS_UNVALIDATED',
    title: 'Hermes: Tool Arguments Passed to Dangerous Sink Without Validation',
    regex: /(?:exec|execSync|spawn|eval|Function|query|db\.run|shell)\s*\(\s*(?:args|arguments|toolArgs|params|input|callArgs)[\w.[\]'"]*\b/gi,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'ASI03',
    description: 'Tool call arguments from the LLM passed directly to a dangerous sink (shell, eval, DB query) without sanitization. Prompt injection can craft tool arguments that execute arbitrary commands or SQL.',
    fix: 'Validate all tool arguments against the declared JSON Schema before passing to the implementation. Reject any argument that does not match the expected type and format.',
    confidence: 'high',
  },

  {
    rule: 'HERMES_ADDITIONAL_PROPERTIES_TRUE',
    title: 'Hermes: Tool Schema Allows Arbitrary Properties (additionalProperties: true)',
    regex: /additionalProperties\s*[:=]\s*true/gi,
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'ASI03',
    description: 'Tool input schema sets additionalProperties: true, allowing the LLM to pass any arbitrary arguments. This bypasses schema validation and can be used to inject unexpected parameters that change tool behavior.',
    fix: 'Set additionalProperties: false on all tool input schemas. Only accept explicitly declared properties.',
    confidence: 'high',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-3: Plan/Goal Hijacking
  // Hermes agent planners store goals in mutable state. If user-controlled
  // content reaches the goal/plan state, the agent can be redirected.
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_PLAN_USER_INPUT',
    title: 'Hermes: User Input Written Directly Into Agent Plan/Goal State',
    regex: /(?:agent\.goal|agent\.plan|setGoal|setPlan|updatePlan|agent\.task)\s*=\s*(?:req\.|request\.|userInput|body\.|params\.|query\.)/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI01',
    description: 'User-controlled input assigned directly to the agent\'s goal or plan state. An attacker can hijack the agent\'s entire execution trajectory by crafting input that replaces the intended goal with a malicious objective.',
    fix: 'Never write raw user input into agent goal/plan state. Use a constrained task template: goal = TEMPLATE.replace("{task}", sanitize(userInput)).',
    confidence: 'high',
  },

  {
    rule: 'HERMES_GOAL_PROMPT_INJECTION',
    title: 'Hermes: Goal State Contains Unescaped Template Interpolation',
    regex: /(?:goal|plan|task|objective)\s*[:=`]\s*[`'"]\s*[\s\S]{0,80}\$\{(?:req|request|user|input|body|params|query)/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI01',
    description: 'Goal or plan state built via template literal interpolation of request/user data. Attacker can break out of the template and inject arbitrary goal instructions.',
    fix: 'Sanitize user input before interpolation and validate the final goal string against expected patterns. Prefer structured task objects over free-form strings.',
    confidence: 'high',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-4: Memory Layer Attacks
  // Hermes has 4 memory layers: in-context, external, episodic, semantic.
  // Unvalidated writes to persistent memory layers enable cross-session poisoning.
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_MEMORY_UNVALIDATED_WRITE',
    title: 'Hermes: User-Controlled Content Written to Persistent Memory Layer',
    regex: /(?:memory\.store|memory\.save|episodicMemory\.add|semanticMemory\.upsert|addMemory|storeMemory|persistMemory)\s*\(\s*(?:req\.|userInput|body\.|params\.|input|content|message)\b/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI06',
    description: 'User-controlled content written directly to a Hermes persistent memory layer (episodic or semantic). This enables cross-session memory poisoning: an attacker injects false memories that influence all future agent sessions.',
    fix: 'Sanitize and classify content before writing to persistent memory. Apply a confidence/source filter: only write memories derived from trusted tool outputs, not raw user messages.',
    confidence: 'high',
  },

  {
    rule: 'HERMES_MEMORY_EXFIL_PATTERN',
    title: 'Hermes: Memory Layer Read Result Sent to External URL',
    regex: /(?:memory\.retrieve|memory\.search|recallMemory|getMemory)\s*\([^)]*\)[\s\S]{0,200}(?:fetch|axios|http|https)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)/gi,
    severity: 'critical',
    cwe: 'CWE-201',
    owasp: 'ASI06',
    description: 'Memory layer retrieval result immediately sent to an external HTTP endpoint. A compromised skill or tool chain can exfiltrate all accumulated agent memories — including sensitive context from prior sessions.',
    fix: 'Audit all code paths that read from memory layers. Never forward memory retrieval results to external endpoints without explicit user consent and data classification.',
    confidence: 'medium',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-5: Skill Permission Drift
  // A skill's declared tool permissions should match what it actually invokes.
  // ────────────────────────────────────────────────────────────────────────────
  // NOTE: HERMES_SKILL_NO_PERMISSIONS_FIELD is detected by checkSkillFrontmatter()
  // (a structural multi-line check), not as a line-by-line PATTERNS entry.
  // A line-by-line regex cannot reliably detect the absence of a field in a
  // multi-line frontmatter block.

  {
    rule: 'HERMES_SKILL_WILDCARD_PERMISSIONS',
    title: 'Hermes: Skill Requests Wildcard Tool Permissions',
    regex: /permissions\s*[:=]\s*\[\s*['"]?\*['"]?\s*\]/gi,
    severity: 'high',
    cwe: 'CWE-250',
    owasp: 'ASI02',
    description: 'Skill declares wildcard permissions (["*"]), granting itself access to all registered tools. A malicious or compromised skill with wildcard permissions can invoke any tool without restriction.',
    fix: 'Replace wildcard with an explicit list of required tools: permissions: ["web_search", "summarize"]. Reject skills that request wildcard permissions.',
    confidence: 'high',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-6: Multi-Agent Trust Boundary Violations
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_SUB_AGENT_CREDENTIAL_FORWARD',
    title: 'Hermes: Parent Agent Credentials Forwarded to Sub-Agent',
    regex: /(?:spawnAgent|createSubAgent|callAgent|delegateTo|orchestrate)\s*\([^)]*(?:apiKey|token|credentials|secrets|env\.)/gi,
    severity: 'critical',
    cwe: 'CWE-522',
    owasp: 'ASI02',
    description: 'Parent agent\'s credentials or API keys forwarded to a sub-agent. If the sub-agent is compromised via prompt injection, it gains the parent\'s full credential set and can pivot to other services.',
    fix: 'Issue scoped, short-lived credentials to each sub-agent. Never forward the parent\'s primary credentials. Use capability tokens that grant only what the sub-agent needs.',
    confidence: 'high',
  },

  {
    rule: 'HERMES_UNBOUNDED_AGENT_DEPTH',
    title: 'Hermes: Multi-Agent Recursion Without Depth Limit',
    regex: /(?:spawnAgent|createSubAgent|callAgent|delegateTo)\s*\([^)]*\)(?![\s\S]{0,300}(?:depth|maxDepth|depthLimit|recursionLimit))/gi,
    severity: 'high',
    cwe: 'CWE-674',
    owasp: 'ASI07',
    description: 'Agent spawning a sub-agent without a recursion depth limit. An adversarial prompt can trigger unbounded agent recursion, exhausting resources or causing goal drift through infinite delegation chains.',
    fix: 'Track agent call depth and enforce a maximum: if (depth >= MAX_AGENT_DEPTH) throw new AgentDepthLimitError(). Recommended max: 3-5 levels.',
    confidence: 'medium',
  },

  {
    rule: 'HERMES_AGENT_OUTPUT_UNVALIDATED_ACTION',
    title: 'Hermes: Sub-Agent Output Triggers Action Without Validation',
    regex: /(?:agentResult|subAgentOutput|delegateResult|orchestrationResult)[\w.[\]'"]*\s*(?:\.|->)\s*(?:execute|run|apply|dispatch|write|delete|send|post|put)/gi,
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'ASI01',
    description: 'Sub-agent output directly triggers a real-world action (write, delete, send) without human validation. A compromised sub-agent can use this to perform destructive or exfiltrating actions through the parent.',
    fix: 'Require explicit user confirmation before acting on sub-agent output for any irreversible action. Apply output validation schemas to all inter-agent messages.',
    confidence: 'medium',
  },

  // ────────────────────────────────────────────────────────────────────────────
  // TRACK A-7: Agent Manifest Attestation
  // ────────────────────────────────────────────────────────────────────────────
  {
    rule: 'HERMES_MANIFEST_NO_INTEGRITY',
    title: 'Hermes: Agent Manifest Loaded Without Integrity Check',
    regex: /(?:loadManifest|readManifest|parseManifest|loadAgent)\s*\(\s*(?:filePath|manifestPath|agentPath|configPath)\s*\)(?![\s\S]{0,200}(?:integrity|checksum|hash|verify|signature))/gi,
    severity: 'high',
    cwe: 'CWE-345',
    owasp: 'ASI10',
    description: 'Agent manifest loaded from disk or network without verifying its integrity hash or signature. A supply-chain attack can replace the manifest file, silently changing agent behavior, tool lists, and permissions.',
    fix: 'Compute and verify a SHA-256 hash of the manifest at load time. For production, use a signed manifest: verify the signature against a trusted public key before trusting its contents.',
    confidence: 'medium',
  },

  {
    rule: 'HERMES_MANIFEST_NO_VERSION_PIN',
    title: 'Hermes: hermes-agent Dependency Uses Mutable Version Range',
    // Match only package.json-style version specs with range operators, not import statements.
    // Fires on: "@nousresearch/hermes-agent": "^1.2.0" or "~1.0.0" or "*"
    // Does NOT fire on import/require statements.
    regex: /["']@nousresearch\/hermes-agent["']\s*:\s*["'][\^~*><=][^"']{1,20}["']/gi,
    severity: 'medium',
    cwe: 'CWE-829',
    owasp: 'ASI10',
    description: 'hermes-agent dependency uses a mutable version range — a compromised minor or patch release would affect all agents using this package without any code change.',
    fix: 'Pin to an exact version: "@nousresearch/hermes-agent": "1.2.3". Commit the lockfile.',
    confidence: 'high',
  },

];

// =============================================================================
// STRUCTURAL / MULTI-LINE CHECKS
// =============================================================================

/**
 * Detect tool namespace collisions — two tools with the same name registered
 * in the same registry (shadowing attack).
 */
function checkToolNameCollisions(content, filePath, agent) {
  const findings = [];
  const nameRe = /(?:registerTool|addTool|tools\.push|tools\.set)\s*\(\s*\{[^}]*?name\s*[:=]\s*['"]([^'"]+)['"]/gi;
  const names = new Map(); // name → first line number

  let match;
  while ((match = nameRe.exec(content)) !== null) {
    const toolName = match[1];
    const line = content.slice(0, match.index).split('\n').length;

    if (names.has(toolName)) {
      findings.push(createFinding({
        file: filePath,
        line,
        severity: 'high',
        category: agent.category,
        rule: 'HERMES_TOOL_NAME_COLLISION',
        title: `Hermes: Tool Name Collision — "${toolName}" Registered Twice`,
        description: `The tool name "${toolName}" is registered more than once in the same registry. The second registration silently shadows the first. This is a tool-shadowing attack vector: a malicious plugin or dynamically loaded tool can replace a trusted tool by registering under the same name.`,
        matched: `duplicate tool name: "${toolName}" (first at line ${names.get(toolName)})`,
        confidence: 'high',
        cwe: 'CWE-15',
        owasp: 'ASI05',
        fix: `Before registering a tool, check: if (registry.has("${toolName}")) throw new Error("Tool name collision: ${toolName}"). Use a registry that rejects duplicate registrations.`,
      }));
    } else {
      names.set(toolName, line);
    }
  }

  return findings;
}

/**
 * Detect cross-agent trust chain: agent A passes its own tool context to
 * agent B unfiltered. Detected by looking for agent spawn calls where the
 * parent's full `tools` or `toolRegistry` is passed as-is.
 */
function checkToolContextForwarding(content, filePath, agent) {
  const findings = [];
  const forwardRe = /(?:spawnAgent|createSubAgent|callAgent)\s*\(\s*\{[^}]*tools\s*[:=]\s*(?:this\.tools|toolRegistry|allTools|registeredTools)\b/gi;

  let match;
  while ((match = forwardRe.exec(content)) !== null) {
    const line = content.slice(0, match.index).split('\n').length;
    findings.push(createFinding({
      file: filePath,
      line,
      severity: 'high',
      category: agent.category,
      rule: 'HERMES_FULL_TOOL_CONTEXT_FORWARD',
      title: 'Hermes: Full Tool Registry Forwarded to Sub-Agent',
      description: 'Parent agent forwards its complete tool registry to a sub-agent. The sub-agent gains access to all of the parent\'s tools — including dangerous system tools it may not need. If the sub-agent is compromised via prompt injection, it can use any of the parent\'s tools.',
      matched: match[0].slice(0, 120),
      confidence: 'high',
      cwe: 'CWE-250',
      owasp: 'ASI02',
      fix: 'Create a scoped tool registry for each sub-agent containing only the tools it needs: spawnAgent({ tools: [allowedTool1, allowedTool2] }).',
    }));
  }

  return findings;
}

/**
 * Check skill frontmatter for permissions field.
 * Skill files are Markdown; frontmatter is YAML between --- delimiters.
 */
function checkSkillFrontmatter(content, filePath, agent) {
  const findings = [];

  // Only check Markdown skill files
  if (!filePath.endsWith('.md')) return findings;

  // Extract YAML frontmatter
  const fmMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!fmMatch) return findings;

  const fm = fmMatch[1];
  const hasName     = /^name\s*:/m.test(fm);
  const hasTool     = /^(?:tools?|tool_use|tool_calls?)\s*:/m.test(fm);

  if (!hasName) return findings; // not a skill file

  // Check for missing permissions
  const hasPermissions = /^permissions?\s*:/m.test(fm);
  if (hasTool && !hasPermissions) {
    findings.push(createFinding({
      file: filePath,
      line: 1,
      severity: 'medium',
      category: agent.category,
      rule: 'HERMES_SKILL_NO_PERMISSIONS_FIELD',
      title: 'Hermes: Skill Declares Tools But Has No permissions Field',
      description: 'This skill uses tools but does not declare a permissions field in its frontmatter. Without explicit permission declarations, the agent runtime may grant the skill access to all tools — violating least-privilege.',
      matched: fm.slice(0, 120),
      confidence: 'medium',
      cwe: 'CWE-1188',
      owasp: 'ASI02',
      fix: 'Add a permissions field to the skill frontmatter listing only the tools this skill needs: permissions: [tool1, tool2].',
    }));
  }

  // Check for wildcard permissions already handled by PATTERNS regex.
  return findings;
}

/**
 * Detect insecure memory layer file access patterns.
 * Hermes stores memory in JSON files under .hermes/memory/; direct JSON.parse
 * of those files without validation is a deserialization risk.
 */
function checkMemoryFileDeserialization(content, filePath, agent) {
  const findings = [];

  // Only flag in source files, not the memory files themselves
  if (filePath.includes('.hermes/memory')) return findings;

  const re = /JSON\.parse\s*\(\s*(?:fs\.readFileSync|await\s+fs\.promises\.readFile)\s*\([^)]*(?:memory|episodic|semantic|working|\.hermes)/gi;
  let match;
  while ((match = re.exec(content)) !== null) {
    const line = content.slice(0, match.index).split('\n').length;
    findings.push(createFinding({
      file: filePath,
      line,
      severity: 'medium',
      category: agent.category,
      rule: 'HERMES_MEMORY_UNSAFE_DESERIALIZE',
      title: 'Hermes: Memory File Deserialized Without Schema Validation',
      description: 'Hermes memory layer file read and parsed with JSON.parse but not validated against a schema. A tampered memory file (e.g., from a prior memory poisoning attack) could contain crafted data that alters agent behavior when loaded.',
      matched: match[0].slice(0, 100),
      confidence: 'medium',
      cwe: 'CWE-502',
      owasp: 'ASI06',
      fix: 'Validate memory file contents against a strict JSON Schema after parsing. Reject any memory entries that contain unexpected fields or types.',
    }));
  }

  return findings;
}

// =============================================================================
// AGENT CLASS
// =============================================================================

export class HermesSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'HermesSecurityAgent',
      'Detects security vulnerabilities in Hermes Agent deployments: tool registry poisoning, function-call injection, memory layer attacks, skill permission drift, and multi-agent trust boundary violations',
      'llm'
    );
  }

  /**
   * Only run if the project appears to use Hermes Agent.
   */
  shouldRun(recon) {
    // Run if hermes is detected in dependencies or frameworks
    if (recon?.dependencies?.some(d => /hermes/i.test(d))) return true;
    if (recon?.frameworks?.some(f => /hermes/i.test(f))) return true;
    // Run if hermes config files were discovered during recon
    if (recon?.configFiles?.some(f => /hermes/i.test(f))) return true;
    // Don't scan every project — Hermes files are distinctive enough to skip otherwise
    return false;
  }

  async analyze(context) {
    const { rootPath, files = [] } = context;
    const findings = [];

    // Discover Hermes-relevant files
    const hermesFiles = this._findHermesFiles(files, rootPath);

    if (hermesFiles.length === 0) return findings;

    for (const filePath of hermesFiles) {
      const content = this.readFile(filePath);
      if (!content) continue;

      // Skip files with blanket suppression
      if (/hermes-security-ignore-file/i.test(content)) continue;

      // Reset stateful regex lastIndex before each file (patterns use /g flag)
      for (const p of PATTERNS) p.regex.lastIndex = 0;

      // Single-line pattern scan
      findings.push(...this.scanFileWithPatterns(filePath, PATTERNS));

      // Structural checks
      findings.push(...checkToolNameCollisions(content, filePath, this));
      findings.push(...checkToolContextForwarding(content, filePath, this));
      findings.push(...checkSkillFrontmatter(content, filePath, this));
      findings.push(...checkMemoryFileDeserialization(content, filePath, this));
    }

    return findings;
  }

  /**
   * Identify files relevant to Hermes Agent analysis.
   */
  _findHermesFiles(allFiles, rootPath) {
    const hermesFiles = new Set();

    for (const file of allFiles) {
      const rel = file.replace(/\\/g, '/');

      // Hermes config and manifest files
      if (/(?:hermes\.config|agents\.(?:json|yaml|yml)|agent-manifest|tool-registry|hermes-tools)\./i.test(rel)) {
        hermesFiles.add(file);
        continue;
      }

      // Skill files
      if (/\/skills\/[^/]+\.md$/i.test(rel) || /\/hermes-skills\//i.test(rel)) {
        hermesFiles.add(file);
        continue;
      }

      // .hermes directory
      if (/\/\.hermes\//i.test(rel)) {
        hermesFiles.add(file);
        continue;
      }

      // Source files — check for hermes imports (avoid reading every file)
      if (/\.(js|ts|mjs|cjs|py)$/.test(rel)) {
        const content = this.readFile(file);
        if (!content) continue;
        if (/(?:hermes[-_]agent|@nousresearch\/hermes|hermes\.config|toolRegistry|registerTool|callTool|spawnAgent|createSubAgent|memory\.store|episodicMemory|semanticMemory|loadManifest)/i.test(content)) {
          hermesFiles.add(file);
        }
      }
    }

    return [...hermesFiles];
  }
}

export default HermesSecurityAgent;
