/**
 * Memory Poisoning Detection Agent
 * ==================================
 *
 * Detects instruction injection in AI agent memory and context files.
 *
 * Memory poisoning occurs when an adversary implants false or malicious
 * instructions into an agent's persistent storage — the agent "learns"
 * the instruction and recalls it in future sessions.
 *
 * Targets:
 *   - Claude Code memory files (.claude/memory/*.md, CLAUDE.md)
 *   - Cursor rules (.cursorrules, .cursor/rules/*.mdc)
 *   - Continue config (.continue/config.json, .continue/rules/*.md)
 *   - Windsurf rules (.windsurfrules)
 *   - Cody config (.cody/)
 *   - Gemini CLI (.gemini/)
 *   - Project docs that agents ingest (README, CONTRIBUTING, docs/)
 *
 * Attack vectors detected:
 *   1. Direct instruction injection — "ignore previous instructions"
 *   2. Hidden directives in markdown — invisible chars, HTML comments
 *   3. Exfiltration instructions — "send", "upload", "POST to"
 *   4. Tool abuse instructions — "run bash", "write to", "delete"
 *   5. Persona hijacking — "you are now", "your new role"
 *   6. Memory persistence — instructions designed to survive context resets
 *
 * Maps to: OWASP Agentic ASI01 (Agent Goal Hijacking),
 *          ASI05 (Memory/Context Poisoning)
 */

import path from 'path';
import fg from 'fast-glob';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// MEMORY / CONTEXT FILES TO SCAN
// =============================================================================

const MEMORY_GLOBS = [
  // Claude Code
  '.claude/memory/*.md',
  '.claude/commands/*.md',
  'CLAUDE.md',
  // Cursor
  '.cursorrules',
  '.cursor/rules/*.mdc',
  '.cursor/rules/*.md',
  // Windsurf
  '.windsurfrules',
  // Continue
  '.continue/config.json',
  '.continue/rules/*.md',
  // Cody
  '.cody/*.md',
  '.cody/config.json',
  // Gemini CLI
  '.gemini/*.md',
  '.gemini/settings.json',
  // Copilot
  '.github/copilot-instructions.md',
  // Aider
  '.aider.conf.yml',
];

// Project docs that agents commonly ingest as context
const DOC_GLOBS = [
  'README.md',
  'CONTRIBUTING.md',
  'docs/**/*.md',
  'AGENTS.md',
  '.github/PULL_REQUEST_TEMPLATE.md',
  '.github/ISSUE_TEMPLATE/*.md',
];

// =============================================================================
// DETECTION PATTERNS
// =============================================================================

const INJECTION_PATTERNS = [
  {
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|rules?|prompts?|constraints?|guidelines?)/gi,
    rule: 'MEMORY_POISON_OVERRIDE',
    title: 'Instruction Override in Agent Memory',
    severity: 'critical',
    description: 'File contains instructions to override previous agent rules. This is a classic prompt injection pattern that persists in agent memory.',
    owasp: 'ASI01',
    cwe: 'CWE-74',
    fix: 'Remove the override instruction. If intentional, use the agent\'s official configuration mechanism instead.',
  },
  {
    regex: /(?:you\s+are\s+now|your\s+new\s+(?:role|persona|identity)|from\s+now\s+on\s+you\s+(?:are|will|must|should))\s+/gi,
    rule: 'MEMORY_POISON_PERSONA',
    title: 'Persona Hijacking in Agent Memory',
    severity: 'high',
    description: 'File attempts to redefine the agent\'s persona or role. If this file is ingested as context, the agent may adopt the injected persona in future sessions.',
    owasp: 'ASI01',
    cwe: 'CWE-74',
    fix: 'Remove the persona redefinition. Use the agent\'s system prompt or official configuration to set roles.',
  },
  {
    regex: /(?:send|upload|post|transmit|exfiltrate|forward)\s+(?:all|any|the|this)?\s*(?:code|data|files?|contents?|secrets?|keys?|tokens?|credentials?|env|environment)\s+(?:to|via|using|through)\s+/gi,
    rule: 'MEMORY_POISON_EXFILTRATE',
    title: 'Exfiltration Instruction in Agent Memory',
    severity: 'critical',
    description: 'File instructs an agent to exfiltrate data to an external destination. If persisted in memory, the agent may execute this across sessions.',
    owasp: 'ASI01',
    cwe: 'CWE-200',
    fix: 'Remove the exfiltration instruction immediately. Audit agent memory for other injected directives.',
  },
  {
    regex: /(?:do\s+not|don'?t|never)\s+(?:tell|inform|show|reveal|display|mention|report|log)\s+(?:the\s+user|anyone|them)/gi,
    rule: 'MEMORY_POISON_SUPPRESS',
    title: 'Output Suppression Instruction',
    severity: 'critical',
    description: 'File instructs the agent to hide actions from the user. This matches the ToxicSkills "output suppression" pattern — the agent does something harmful but doesn\'t report it.',
    owasp: 'ASI01',
    cwe: 'CWE-200',
    fix: 'Remove the suppression instruction. Agents should always report their actions transparently.',
  },
  {
    regex: /(?:whenever|every\s+time|always|each\s+time)\s+(?:you|the\s+agent)\s+(?:start|begin|open|run|execute|encounter)/gi,
    rule: 'MEMORY_POISON_PERSISTENT',
    title: 'Persistent Trigger Instruction',
    severity: 'high',
    description: 'File contains instructions designed to trigger on every session or action — a hallmark of persistent memory poisoning. Unlike a one-time injection, this survives context resets.',
    owasp: 'ASI05',
    cwe: 'CWE-74',
    fix: 'Remove the persistent trigger. If you need recurring behavior, configure it through the agent\'s official hook or startup mechanism.',
  },
  {
    regex: /(?:run|execute|invoke|call|use)\s+(?:bash|shell|terminal|cmd|system|exec|subprocess|os\.system|child_process)/gi,
    rule: 'MEMORY_POISON_TOOL_ABUSE',
    title: 'Shell Execution Instruction in Memory',
    severity: 'high',
    description: 'File instructs the agent to execute shell commands. If persisted in memory, this enables remote code execution via prompt injection.',
    owasp: 'ASI02',
    cwe: 'CWE-78',
    fix: 'Remove direct shell execution instructions. Use the agent\'s sandboxed tool API instead.',
  },
  {
    regex: /(?:fetch|curl|wget|http\.get|axios\.get|request)\s*\(\s*['"`]https?:\/\//gi,
    rule: 'MEMORY_POISON_NETWORK',
    title: 'Network Request Instruction in Memory',
    severity: 'high',
    description: 'File instructs the agent to make network requests to hardcoded URLs. A poisoned memory file can use this to phone home or exfiltrate context.',
    owasp: 'ASI01',
    cwe: 'CWE-918',
    fix: 'Remove the hardcoded network request. If the agent needs to fetch data, configure it through approved MCP servers or tools.',
  },
];

// Hidden content patterns (invisible chars, encoded payloads)
const HIDDEN_CONTENT_PATTERNS = [
  {
    // Unicode zero-width chars used to hide instructions
    regex: /[\u200B\u200C\u200D\u2060\uFEFF]{3,}/g,
    rule: 'MEMORY_HIDDEN_UNICODE',
    title: 'Hidden Unicode Content in Agent File',
    severity: 'critical',
    description: 'File contains clusters of zero-width Unicode characters. These are invisible to humans but may encode hidden instructions that the agent processes.',
    owasp: 'ASI01',
    cwe: 'CWE-116',
    fix: 'Strip all zero-width characters from this file. Use a hex editor to inspect for hidden content.',
  },
  {
    // HTML comments in markdown that could contain injected instructions
    regex: /<!--[\s\S]*?(?:ignore|override|system|role|always|execute|send\s+to|curl|bash)[\s\S]*?-->/gi,
    rule: 'MEMORY_HIDDEN_COMMENT',
    title: 'Suspicious HTML Comment in Agent File',
    severity: 'high',
    description: 'An HTML comment contains what appears to be an injected instruction. Some agents process HTML comments as context, making this a viable injection vector.',
    owasp: 'ASI05',
    cwe: 'CWE-74',
    fix: 'Remove the suspicious HTML comment or move the content to a visible location.',
  },
  {
    // Base64 encoded content in markdown/config files
    regex: /(?:^|[\s"':=])([A-Za-z0-9+/]{60,}={0,2})(?:[\s"',]|$)/gm,
    rule: 'MEMORY_HIDDEN_BASE64',
    title: 'Base64-Encoded Content in Agent File',
    severity: 'medium',
    description: 'File contains a long base64-encoded string. This could hide instructions or payloads that the agent decodes and executes.',
    owasp: 'ASI05',
    cwe: 'CWE-116',
    confidence: 'medium',
    fix: 'Decode the base64 content and verify it is benign. Remove if it contains instructions or executable content.',
  },
];

// =============================================================================
// AGENT
// =============================================================================

export class MemoryPoisoningAgent extends BaseAgent {
  constructor() {
    super(
      'MemoryPoisoningAgent',
      'Detects instruction injection in AI agent memory and context files',
      'agentic'
    );
  }

  shouldRun() {
    return true; // Always run — memory poisoning applies to any project
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    // Discover all memory/context files
    const memoryFiles = await fg(MEMORY_GLOBS, {
      cwd: rootPath,
      absolute: true,
      dot: true,
    });

    const docFiles = await fg(DOC_GLOBS, {
      cwd: rootPath,
      absolute: true,
      dot: true,
    });

    // Scan memory files with higher severity (direct agent context)
    for (const file of memoryFiles) {
      findings.push(...this._scanFile(file, true));
    }

    // Scan doc files with slightly lower confidence (indirect context)
    for (const file of docFiles) {
      findings.push(...this._scanFile(file, false));
    }

    return findings;
  }

  _scanFile(filePath, isDirectMemory) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const findings = [];
    const lines = content.split('\n');

    // Check injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (this.isSuppressed(line)) continue;

        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(line);
        if (match) {
          findings.push(createFinding({
            file: filePath,
            line: i + 1,
            severity: pattern.severity,
            category: 'agentic',
            rule: pattern.rule,
            title: pattern.title,
            description: pattern.description + (isDirectMemory
              ? ' This file is directly loaded into agent context.'
              : ' This file may be ingested by agents as project context.'),
            matched: match[0],
            confidence: isDirectMemory ? 'high' : 'medium',
            cwe: pattern.cwe,
            owasp: pattern.owasp,
            fix: pattern.fix,
          }));
        }
      }
    }

    // Check hidden content patterns (full content, not per-line)
    for (const pattern of HIDDEN_CONTENT_PATTERNS) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(content);
      if (match) {
        // Find approximate line number
        const beforeMatch = content.slice(0, match.index);
        const lineNum = (beforeMatch.match(/\n/g) || []).length + 1;

        findings.push(createFinding({
          file: filePath,
          line: lineNum,
          severity: pattern.severity,
          category: 'agentic',
          rule: pattern.rule,
          title: pattern.title,
          description: pattern.description,
          matched: match[0].slice(0, 100),
          confidence: pattern.confidence || (isDirectMemory ? 'high' : 'medium'),
          cwe: pattern.cwe,
          owasp: pattern.owasp,
          fix: pattern.fix,
        }));
      }
    }

    return findings;
  }
}

export default MemoryPoisoningAgent;
