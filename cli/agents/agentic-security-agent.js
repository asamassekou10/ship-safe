/**
 * Agentic Security Agent
 * ========================
 *
 * Detects security vulnerabilities in AI agent implementations.
 * Covers the OWASP Top 10 for Agentic Applications (2026):
 *   ASI01 — Agent Goal Hijacking
 *   ASI02 — Tool Misuse
 *   ASI03 — Identity & Privilege Abuse
 *   ASI04 — Memory Poisoning
 *   ASI05 — Cascading Hallucination
 *   ASI06 — Supply Chain Vulnerabilities
 *
 * 48% of cybersecurity professionals identify agentic AI as
 * the top attack vector for 2026.
 */

import path from 'path';
import { BaseAgent } from './base-agent.js';

// =============================================================================
// AGENTIC SECURITY PATTERNS
// =============================================================================

const PATTERNS = [
  // ── Goal Hijacking (ASI01) ───────────────────────────────────────────────
  {
    rule: 'AGENT_USER_INPUT_IN_SYSTEM_PROMPT',
    title: 'Agent: User Input in System Prompt / Goal',
    regex: /(?:system|instructions|goal|objective|persona)\s*[:=]\s*(?:`[^`]*\$\{|.*\+\s*(?:req\.|request\.|user|input|message|query|body))/g,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'A03:2021',
    description: 'User input concatenated into agent system prompt or goal definition. Enables agent goal hijacking — the attacker can rewrite the agent\'s objectives.',
    fix: 'Separate system instructions from user input. Use structured message roles (system vs user). Never interpolate user input into system prompts.',
  },
  {
    rule: 'AGENT_NO_GOAL_BOUNDARY',
    title: 'Agent: Missing Goal Boundary Enforcement',
    regex: /(?:agent|assistant|bot)[\s\S]{0,200}(?:system|instructions)\s*[:=]\s*(?:req\.|request\.|input|body|query|params)/g,
    severity: 'critical',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    description: 'Agent goal or system instructions set directly from external input without boundary enforcement.',
    fix: 'Hardcode agent goals. If customization is needed, validate against an allowlist of approved goal templates.',
  },

  // ── Tool Misuse (ASI02) ──────────────────────────────────────────────────
  {
    rule: 'AGENT_UNRESTRICTED_TOOLS',
    title: 'Agent: Unrestricted Tool Access',
    regex: /(?:tools|actions|capabilities|functions)\s*[:=]\s*(?:\[\s*\.{3}|"all"|'all'|"\*"|'\*'|Object\.keys|getAll|listAll)/g,
    severity: 'critical',
    cwe: 'CWE-269',
    owasp: 'A01:2021',
    description: 'Agent given wildcard or unbounded tool access. Prompt injection can trigger any available tool.',
    fix: 'Restrict agent tools to minimum required set. Use explicit allowlists, not wildcard access.',
  },
  {
    rule: 'AGENT_TOOL_NO_CONFIRMATION',
    title: 'Agent: Destructive Tools Without Human Confirmation',
    regex: /(?:auto_approve|auto_execute|requireConfirmation\s*[:=]\s*false|confirm\s*[:=]\s*false|human_in_loop\s*[:=]\s*false|humanInTheLoop\s*[:=]\s*false|approval\s*[:=]\s*false)/gi,
    severity: 'high',
    cwe: 'CWE-862',
    owasp: 'A01:2021',
    description: 'Agent configured to auto-execute tools without human confirmation. Prompt injection can trigger destructive actions.',
    fix: 'Require human-in-the-loop confirmation for destructive operations (write, delete, send, pay).',
  },
  {
    rule: 'AGENT_TOOL_SHELL_ACCESS',
    title: 'Agent: Tool With Shell/Command Execution',
    regex: /(?:tools|functions)[\s\S]{0,500}(?:exec\s*\(|execSync|spawn|child_process|subprocess|os\.system|shell\s*[:=]\s*true)/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'A03:2021',
    description: 'Agent has access to a tool that executes shell commands. Prompt injection achieves RCE.',
    fix: 'Remove shell execution tools from agent capabilities. If needed, use strict command allowlists.',
  },
  {
    rule: 'AGENT_UNVALIDATED_TOOL_OUTPUT',
    title: 'Agent: Tool Output Used Without Validation',
    regex: /(?:tool_result|toolResult|function_result|tool_output)[\s\S]{0,200}(?:eval\s*\(|exec\s*\(|innerHTML|dangerouslySetInnerHTML|\.query\s*\(|\.execute\s*\()/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'A03:2021',
    description: 'Tool output passed directly to dangerous sinks (eval, SQL, HTML). Poisoned tool results can achieve code execution.',
    fix: 'Validate and sanitize all tool outputs before using them in code execution, SQL queries, or HTML rendering.',
  },

  // ── Identity & Privilege Abuse (ASI03) ───────────────────────────────────
  {
    rule: 'AGENT_ESCALATED_PERMISSIONS',
    title: 'Agent: Runs With Elevated Permissions',
    regex: /(?:agent|bot|assistant)[\s\S]{0,300}(?:admin|sudo|root|superuser|service.?role|elevated|full.?access|all.?permissions)/gi,
    severity: 'high',
    cwe: 'CWE-269',
    owasp: 'A04:2021',
    confidence: 'medium',
    description: 'Agent configured with elevated permissions (admin, root, service-role). Prompt injection inherits these privileges.',
    fix: 'Apply principle of least privilege. Agents should have minimal permissions required for their specific task.',
  },
  {
    rule: 'AGENT_CREDENTIAL_FORWARDING',
    title: 'Agent: Credentials Passed Between Tools',
    regex: /(?:tool|function|action)[\s\S]{0,300}(?:credential|password|secret|token|apiKey|api_key)[\s\S]{0,100}(?:forward|pass|send|share|propagate|next)/gi,
    severity: 'high',
    cwe: 'CWE-522',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'Agent forwards credentials between tools or to external services. Compromised tools can steal credentials.',
    fix: 'Scope credentials per-tool. Never forward authentication tokens between tool invocations.',
  },

  // ── Memory Poisoning (ASI04) ─────────────────────────────────────────────
  {
    rule: 'AGENT_MEMORY_USER_WRITE',
    title: 'Agent: User Input Written to Persistent Memory',
    regex: /(?:memory|context|history|state|knowledge)[\s\S]{0,100}(?:\.append|\.push|\.add|\.set|\.save|\.store|\.write|\.update)\s*\(\s*(?:user|input|message|query|req\.|request\.)/g,
    severity: 'high',
    cwe: 'CWE-472',
    owasp: 'A03:2021',
    description: 'User-controlled content written directly to agent persistent memory. Enables memory poisoning — attacker instructions persist across sessions.',
    fix: 'Sanitize and validate content before writing to agent memory. Separate user messages from system state.',
  },
  {
    rule: 'AGENT_MEMORY_NO_EXPIRY',
    title: 'Agent: Persistent Memory Without Expiration',
    regex: /(?:memory|longTermMemory|persistentState)[\s\S]{0,200}(?:save|store|persist|write)(?![\s\S]{0,200}(?:ttl|expir|maxAge|retention|cleanup|prune))/g,
    severity: 'medium',
    cwe: 'CWE-404',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Agent memory persists without expiration policy. Poisoned memories remain indefinitely.',
    fix: 'Set TTL or retention policies on agent memory. Implement periodic cleanup of stale entries.',
  },

  // ── Unbounded Execution ──────────────────────────────────────────────────
  {
    rule: 'AGENT_NO_ITERATION_LIMIT',
    title: 'Agent: Execution Loop Without Iteration Limit',
    regex: /(?:while\s*\(\s*true|for\s*\(\s*;\s*;\s*\)|loop\s*\{)[\s\S]{0,500}(?:agent|llm|completion|chat|generate|invoke)/g,
    severity: 'high',
    cwe: 'CWE-835',
    owasp: 'A04:2021',
    description: 'Agent runs in an unbounded loop without iteration limits. Enables denial of wallet and runaway costs.',
    fix: 'Set maxIterations or maxSteps limit on agent execution loops. Add timeout enforcement.',
  },
  {
    rule: 'AGENT_NO_TIMEOUT',
    title: 'Agent: No Timeout on Execution',
    regex: /(?:agent|AgentExecutor|runAgent|createAgent)\s*\(\s*\{(?:(?!timeout|maxTime|deadline|abort|signal).)*\}\s*\)/gs,
    severity: 'medium',
    cwe: 'CWE-400',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Agent execution without timeout configuration. Runaway agents can consume unlimited resources.',
    fix: 'Set explicit timeout on agent execution. Use AbortController or equivalent mechanism.',
  },
  {
    rule: 'AGENT_NO_COST_LIMIT',
    title: 'Agent: No Spending/Token Limit',
    regex: /(?:agent|completion|chat)[\s\S]{0,300}(?:model|engine)\s*[:=](?![\s\S]{0,300}(?:max_tokens|maxTokens|budget|cost|limit|cap))/g,
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Agent makes LLM calls without token or cost limits. Enables denial of wallet attacks.',
    fix: 'Set max_tokens on all LLM calls. Implement per-session cost budgets.',
  },

  // ── Multi-Agent Risks ────────────────────────────────────────────────────
  {
    rule: 'AGENT_RECURSIVE_INVOCATION',
    title: 'Agent: Recursive Self-Invocation',
    regex: /(?:agent|assistant)[\s\S]{0,200}(?:call|invoke|run|execute)[\s\S]{0,100}(?:self|this|agent|itself)/g,
    severity: 'high',
    cwe: 'CWE-674',
    owasp: 'A04:2021',
    confidence: 'medium',
    description: 'Agent can recursively invoke itself or spawn sub-agents without depth limits. Enables infinite loops.',
    fix: 'Set max recursion depth for agent self-invocation. Track and limit sub-agent spawn depth.',
  },
  {
    rule: 'AGENT_CHAIN_NO_ISOLATION',
    title: 'Agent: Multi-Agent Chain Without Privilege Isolation',
    regex: /(?:pipe|chain|sequence|workflow)[\s\S]{0,300}(?:agent|step|task)[\s\S]{0,200}(?:agent|step|task)(?![\s\S]{0,200}(?:permission|scope|restrict|isolat))/g,
    severity: 'medium',
    cwe: 'CWE-269',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Multi-agent pipeline without privilege isolation between steps. A compromised agent can escalate through the chain.',
    fix: 'Apply privilege isolation between agents in a chain. Each agent should have scoped permissions.',
  },

  // ── Output Safety ────────────────────────────────────────────────────────
  {
    rule: 'AGENT_OUTPUT_TO_ACTION',
    title: 'Agent: LLM Output Directly Triggers Actions',
    regex: /(?:completion|response|output|result|generated)[\s\S]{0,100}(?:\.execute|\.run|\.send|\.post|\.delete|\.pay|\.transfer|\.deploy)/g,
    severity: 'high',
    cwe: 'CWE-862',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'LLM output directly triggers side-effect actions without validation. Hallucinated or injected outputs can cause unintended actions.',
    fix: 'Validate LLM output against expected schemas before executing side effects. Add human confirmation for irreversible actions.',
  },
  {
    rule: 'AGENT_NO_OUTPUT_SCHEMA',
    title: 'Agent: No Schema Validation on LLM Output',
    regex: /(?:JSON\.parse|json\.loads)\s*\(\s*(?:completion|response|output|result|generated|llm|ai|gpt|claude)(?![\s\S]{0,200}(?:schema|validate|zod|yup|joi|ajv|parse|safeParse|type_adapter))/g,
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    description: 'LLM JSON output parsed without schema validation. Malformed or malicious output can cause unexpected behavior.',
    fix: 'Validate LLM structured output against a schema (Zod, Joi, Pydantic) before processing.',
  },

  // ── Audit & Observability ────────────────────────────────────────────────
  {
    rule: 'AGENT_NO_AUDIT_LOG',
    title: 'Agent: Tool Invocations Not Logged',
    regex: /(?:tool_call|function_call|executeTool|callTool|tool\.run)[\s\S]{0,300}(?![\s\S]{0,300}(?:log|audit|record|track|monitor|trace|emit|publish))/g,
    severity: 'medium',
    cwe: 'CWE-778',
    owasp: 'A09:2021',
    confidence: 'low',
    description: 'Agent tool invocations are not being logged or audited. Makes incident response and forensics impossible.',
    fix: 'Log all tool invocations including: tool name, arguments, caller identity, timestamp, and result status.',
  },
];

// =============================================================================
// AGENTIC SECURITY AGENT
// =============================================================================

export class AgenticSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'AgenticSecurityAgent',
      'Detect AI agent security vulnerabilities — goal hijacking, tool misuse, memory poisoning, unbounded execution',
      'llm'
    );
  }

  async analyze(context) {
    const { files } = context;

    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.go'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default AgenticSecurityAgent;
