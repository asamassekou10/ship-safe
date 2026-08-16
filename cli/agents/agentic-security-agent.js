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
import { BaseAgent, createFinding } from './base-agent.js';

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
    regex: /(?:auto_approve|auto_execute)\s*[:=]\s*true|(?:requireConfirmation|confirm|human_in_loop|humanInTheLoop|approval)\s*[:=]\s*false/gi,
    severity: 'high',
    cwe: 'CWE-862',
    owasp: 'A01:2021',
    description: 'Agent configured to auto-execute tools without human confirmation. Prompt injection can trigger destructive actions.',
    fix: 'Require human-in-the-loop confirmation for destructive operations (write, delete, send, pay).',
  },
  {
    rule: 'AGENT_TOOL_SHELL_ACCESS',
    title: 'Agent: Tool With Shell/Command Execution',
    // A file that has the word "tools" somewhere and calls subprocess 500
    // characters later is every agent codebase in existence, which is why
    // this fired 56 times at critical severity on hermes-agent. The finding
    // worth making is that a *tool definition* grants shell, so require the
    // exec to sit inside the tool list or handler literal.
    regex: /\b(?:tools|functions)\s*[:=]\s*[[{][^\]}]{0,300}?(?:exec\s*\(|execSync|spawn\s*\(|child_process|subprocess\.|os\.system|shell\s*[:=]\s*true)|\b(?:tool|function)\s*\(\s*['"][^'"]{0,60}['"][^)]{0,200}?(?:execSync|child_process|subprocess\.|os\.system|shell\s*[:=]\s*true)/g,
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
    // Proximity of the words "agent" and "root" within 300 characters is not
    // evidence of anything in a codebase whose subject is agents — it fired 79
    // times on hermes-agent, largely on paths named `root_path`. Require the
    // privilege to be assigned as configuration.
    regex: /(?:agent|bot|assistant)\w*\s*(?:\.\w+)*\s*[:=]\s*[^\n=]{0,60}\b(?:admin|sudo|superuser|service[_-]?role|elevated|full[_-]?access|all[_-]?permissions)\b|\b(?:role|permission|privilege|run_?as|user)\s*[:=]\s*['"](?:admin|root|superuser|sudo)['"]/gi,
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
  // AGENT_MEMORY_NO_EXPIRY moved to AGENT_STRUCTURAL_RULES below. Like
  // AGENT_NO_AUDIT_LOG it asserted the absence of something (a TTL) using a
  // negative lookahead after a variable-length gap, which backtracks until the
  // lookahead succeeds. 234 findings on hermes-agent, one per mention of the
  // word "memory" near a write.

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
  // AGENT_NO_COST_LIMIT moved to AGENT_STRUCTURAL_RULES: same broken
  // lookahead-after-a-gap as AGENT_NO_AUDIT_LOG, 41 findings on hermes-agent.

  // ── Multi-Agent Risks ────────────────────────────────────────────────────
  {
    rule: 'AGENT_RECURSIVE_INVOCATION',
    title: 'Agent: Recursive Self-Invocation',
    // `self` is a parameter on every Python method, so the loose proximity
    // form matched 104 times on hermes-agent. Require an actual self-call:
    // the agent invoking its own run/invoke entry point.
    regex: /\b(?:self|this)\s*\.\s*(?:run|invoke|call|execute|step)\s*\(|\b(?:agent|assistant)\s*\.\s*(?:run|invoke|call|execute)\s*\([^)]*\b(?:self|this|agent)\b/g,
    severity: 'high',
    cwe: 'CWE-674',
    owasp: 'A04:2021',
    confidence: 'medium',
    description: 'Agent can recursively invoke itself or spawn sub-agents without depth limits. Enables infinite loops.',
    fix: 'Set max recursion depth for agent self-invocation. Track and limit sub-agent spawn depth.',
  },
  //  AGENT_CHAIN_NO_ISOLATION moved to AGENT_STRUCTURAL_RULES. The old regex
  // interleaved trigger-matching and mitigation-scanning in one continuous
  // match: two greedy (?:agent|step|task) matches followed by a negative
  // lookahead for the mitigation words. When the mitigation text itself
  // contained one of the trigger words as a substring (e.g. a value like
  // `isolat: "per-step"`), the greedy alternation consumed it as the second
  // trigger instead of leaving it for the lookahead, and the rule fired
  // despite the mitigation being present. See #145.

  // ── Output Safety ────────────────────────────────────────────────────────
  {
    rule: 'AGENT_OUTPUT_TO_ACTION',
    title: 'Agent: LLM Output Directly Triggers Actions',
    // The action has to be invoked *on* the model output, not merely appear
    // within 100 characters of a variable called `result`. The loose version
    // matched `subprocess.run` anywhere near a `result =` binding and fired
    // 329 times on hermes-agent, almost all of it ordinary CLI code.
    regex: /\b(?:completion|response|output|result|generated)\w*\s*(?:\.\w+)?\s*\.\s*(?:execute|run|send|post|delete|pay|transfer|deploy)\s*\(/g,
    severity: 'high',
    cwe: 'CWE-862',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'LLM output directly triggers side-effect actions without validation. Hallucinated or injected outputs can cause unintended actions.',
    fix: 'Validate LLM output against expected schemas before executing side effects. Add human confirmation for irreversible actions.',
  },
  // AGENT_NO_OUTPUT_SCHEMA moved to AGENT_STRUCTURAL_RULES. Its old lookahead
  // never failed, and one of its own escape hatches was the word `parse`,
  // which `JSON.parse` supplies by definition.

  // ── Credential Isolation ─────────────────────────────────────────────────
  {
    rule: 'AGENT_ENV_FILE_ACCESS',
    title: 'Agent: Reads .env Files Without Restriction',
    regex: /(?:readFile|readFileSync|fs\.read|open)\s*\(\s*(?:.*\.env|.*process\.env|.*dotenv)/g,
    severity: 'high',
    cwe: 'CWE-522',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Agent code reads .env files or loads dotenv directly. If the agent is compromised via prompt injection, all credentials in the environment file are exposed.',
    fix: 'Inject only the specific environment variables the agent needs, not the entire .env file. Use scoped credential providers.',
  },
  {
    rule: 'AGENT_NETWORK_AND_FILE_ACCESS',
    title: 'Agent: Both Network and File Access (Exfiltration Risk)',
    regex: /(?:tools|capabilities|functions)[\s\S]{0,800}(?:(?:fetch|http|request|axios|got|curl)[\s\S]{0,400}(?:read|file|fs|disk|path)|(?:read|file|fs|disk|path)[\s\S]{0,400}(?:fetch|http|request|axios|got|curl))/g,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'Agent has tools for both file access and network requests. This is the exfiltration combination: read credentials from disk, send them over the network.',
    fix: 'Separate file-reading agents from network-capable agents. If both are needed, add human-in-the-loop approval for network requests that follow file reads.',
  },
  {
    rule: 'AGENT_ENV_FORWARDED_TO_TOOL',
    title: 'Agent: Environment Variables Forwarded to Tool',
    regex: /(?:process\.env|os\.environ|ENV)\s*(?:\[|\.)[\s\S]{0,100}(?:tool|function|action|invoke|call|execute)/g,
    severity: 'high',
    cwe: 'CWE-522',
    owasp: 'A02:2021',
    confidence: 'medium',
    description: 'Environment variables (which may contain secrets from Stripe Projects or similar) are forwarded directly to agent tools. A compromised tool receives credentials.',
    fix: 'Pass only the specific variables each tool needs. Never forward the entire process.env to tool invocations.',
  },

  // ── Audit & Observability ────────────────────────────────────────────────
  // AGENT_NO_AUDIT_LOG used to live here as a line pattern. It is a property
  // of a file, not of a line, and as a pattern it was structurally unable to
  // say anything: `[\s\S]{0,300}` followed by a negative lookahead backtracks
  // to whatever length makes the lookahead succeed, so any line mentioning
  // `tool_call` fired. It produced 1904 findings on hermes-agent, second only
  // to the contributor-map email flood. It now lives in
  // AGENT_STRUCTURAL_RULES, which emits at most one finding per file.
];

// =============================================================================
// KIMI K3 / OPENAI-COMPATIBLE TOOL-CALL SECURITY CHECKS
// =============================================================================

const AGENT_STRUCTURAL_RULES = [
  {
    rule: 'AGENT_DYNAMIC_TOOL_LOADING_FROM_CONTEXT',
    title: 'Agent: Dynamic Tool Definitions Loaded From Prompt Context',
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'ASI02:2026',
    description: 'Tool definitions appear to be injected into system/developer context from user, document, or retrieved content. Kimi K3-style dynamic tool loading makes this especially risky: poisoned context can add or reshape tools.',
    fix: 'Load tool definitions from trusted code/config only. Never let user, RAG, document, or tool-result content define available tools.',
    test(content) {
      // The old form asked whether the words "prompt", "tool" and "user"
      // appeared within 1000 characters of each other, which is true of 249
      // files in hermes-agent and of essentially any agent codebase. What
      // matters is a tool/function list being *assigned from* untrusted
      // content, so require that shape directly.
      // A tool or function list assigned from untrusted content.
      const assignedFromUntrusted =
        /\b(?:tools|functions|tool_?definitions|toolSchemas?)\s*[:=]\s*[^\n;]{0,120}\b(?:req\.|request\.|body\.|params\.|query\.|user_?(?:input|message|content)|retrieved|documents?|tool_?results?|completion|response)\b/i.test(content)
        || /\b(?:tools|functions)\s*\.\s*(?:push|extend|append|concat)\s*\(\s*[^)\n]{0,80}\b(?:retrieved|documents?|tool_?results?|user_?(?:input|message)|body\.|req\.)\b/i.test(content);

      // A tool schema read straight off the request, whatever it is then
      // spliced into.
      const toolShapedUntrustedRead =
        /\b(?:req|request|body|params|query|ctx)\.[\w.]*tool[\w.]*/i.test(content);

      // The Kimi K3 shape: the schema never lands in a `tools` array at all,
      // it is concatenated into a system or developer message. The tool
      // definitions still arrive from the request.
      const injectedIntoInstructionMessage =
        /content\s*[:=][^\n]{0,140}\b(?:tool|function)s?\b[^\n]{0,100}\b(?:req\.|request\.|body\.|params\.|query\.|user_?(?:input|message)|retrieved|documents?|tool_?results?)/i.test(content);

      return assignedFromUntrusted || toolShapedUntrustedRead || injectedIntoInstructionMessage;
    },
  },
  {
    rule: 'AGENT_CHAIN_NO_ISOLATION',
    title: 'Agent: Multi-Agent Chain Without Privilege Isolation',
    severity: 'medium',
    cwe: 'CWE-269',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Multi-agent pipeline without privilege isolation between steps. A compromised agent can escalate through the chain.',
    fix: 'Apply privilege isolation between agents in a chain. Each agent should have scoped permissions.',
    test(content) {
      // First locate the chain trigger. Mitigation must be checked within the
      // same declaration/statement, not against unrelated text elsewhere in
      // the file.
      const trigger = /\b(?:pipe|chain|sequence|workflow)\b[\s\S]{0,300}?\b(?:agent|step|task)\b[\s\S]{0,200}?\b(?:agent|step|task)\b/i.exec(content);
      if (!trigger) return false;

      // Scope the mitigation check to the statement containing the chain.
      // This keeps unrelated declarations from suppressing a real finding.
      const statementStart = Math.max(
        content.lastIndexOf(';', trigger.index) + 1,
        content.lastIndexOf('\n', trigger.index) + 1
      );
      const statementEnd = content.indexOf(';', trigger.index);
      const statement = content.slice(
        statementStart,
        statementEnd === -1 ? content.length : statementEnd
      );

      const hasIsolation =
        /\b(?:permission|scope|restrict|isolat\w*)\b/i.test(statement);

      return !hasIsolation;
    },
  },
  {
    rule: 'AGENT_TOOL_CALL_NO_ALLOWLIST',
    title: 'Agent: Tool Call Name Executed Without Allowlist',
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'ASI02:2026',
    description: 'LLM-selected tool names are executed without a visible allowlist. A prompt injection can force invocation of unexpected tools.',
    fix: 'Validate every model-selected tool name against an explicit allowlist before dispatching the handler.',
    test(content) {
      const dispatchesModelTool = /(?:tool_calls?|function_call)[\s\S]{0,500}(?:\.name|name\s*\})[\s\S]{0,500}(?:executeTool|callTool|invokeTool|toolRegistry\s*\[|tools\s*\[|handlers\s*\[)/i.test(content)
        || /(?:executeTool|callTool|invokeTool)\s*\(\s*(?:toolCall|tool_call|tool|call|choice)[\w.]*\.name/i.test(content)
        || /(?:toolRegistry|tools|handlers)\s*\[\s*(?:toolCall|tool_call|tool|call|choice)[\w.]*\.(?:function\.)?name\s*\]/i.test(content);
      const hasAllowlist = /(?:allowedTools|toolAllowlist|allowedToolNames|SAFE_TOOLS|ALLOWED_TOOLS)[\s\S]{0,400}(?:includes|has|\[)/i.test(content);
      return dispatchesModelTool && !hasAllowlist;
    },
  },
  {
    rule: 'AGENT_TOOL_CHOICE_REQUIRED_UNTRUSTED',
    title: 'Agent: Forced Tool Choice With Untrusted Input',
    severity: 'medium',
    cwe: 'CWE-862',
    owasp: 'ASI02:2026',
    description: 'The model is forced to call a tool while untrusted user input is included in the same request. This can convert prompt injection into tool execution.',
    fix: 'Avoid forced tool choice for untrusted prompts. Prefer explicit routing, read-only tools, allowlists, and human approval for side-effect tools.',
    test(content) {
      const forcedTool = /tool_choice\s*[:=]\s*(?:['"]required['"]|['"]any['"]|\{\s*type\s*:\s*['"]function['"])/i.test(content);
      const untrustedInput = /(?:req\.|request\.|body\.|params\.|query\.|user|userMessage|input|message|prompt)/i.test(content);
      const hasToolRequest = /(?:chat\.completions|responses\.create|createChatCompletion|messages\.create|generate|completion)[\s\S]{0,1200}(?:tools|functions)/i.test(content);
      return forcedTool && untrustedInput && hasToolRequest;
    },
  },
  {
    rule: 'AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT',
    title: 'Agent: Tool Result Replayed Without Assistant Tool-Call Message',
    severity: 'medium',
    cwe: 'CWE-345',
    owasp: 'ASI02:2026',
    description: 'Tool results are appended to conversation history without preserving the assistant message that requested the tool call. OpenAI-compatible tool-call APIs require this linkage; dropping it can confuse provenance and allow forged tool results.',
    fix: 'Persist the assistant message containing tool_calls before appending role: "tool" messages, and verify tool_call_id links to an issued call.',
    test(content) {
      const appendsToolResult = /(?:role\s*:\s*['"]tool['"]|tool_call_id|toolCallId)[\s\S]{0,500}(?:messages\.push|history\.push|conversation\.push|append)/i.test(content)
        || /(?:messages\.push|history\.push|conversation\.push|append)[\s\S]{0,500}(?:role\s*:\s*['"]tool['"]|tool_call_id|toolCallId)/i.test(content);
      const preservesAssistantToolCalls = /role\s*:\s*['"]assistant['"][\s\S]{0,500}tool_calls/i.test(content);
      return appendsToolResult && !preservesAssistantToolCalls;
    },
  },
  {
    rule: 'AGENT_NO_AUDIT_LOG',
    title: 'Agent: Tool Invocations Not Logged',
    severity: 'medium',
    cwe: 'CWE-778',
    owasp: 'A09:2021',
    description: 'This file dispatches agent tool invocations but has no visible logging, audit, or telemetry call anywhere in it. Without a record of which tool ran with which arguments, incident response and forensics have nothing to work from.',
    fix: 'Log every tool invocation: tool name, arguments, caller identity, timestamp, and result status.',
    test(content) {
      // Dispatch, not mere mention. A file that names `tool_call` while
      // building a request is not the file that runs the tool.
      const dispatchesTool =
        /(?:executeTool|callTool|invokeTool|runTool|dispatchTool|tool\.run|handler\s*\(\s*(?:args|params|input))/i.test(content)
        || /(?:toolRegistry|tools|handlers)\s*\[[^\]]*\]\s*\(/i.test(content);
      if (!dispatchesTool) return false;

      // Any observability call in the file counts. This is deliberately
      // generous: the claim is "nothing here records anything," and one
      // logger is enough to refute it.
      const hasObservability =
        /(?:console\.(?:log|info|warn|error|debug)|logger?\.\w+|logging\.\w+|log\.\w+|audit\w*\s*\(|\btrace\w*\s*\(|telemetry|metrics?\.\w+|emit\s*\(|span\.|structlog|winston|pino|loguru)/i.test(content);

      return !hasObservability;
    },
  },
  {
    rule: 'AGENT_MEMORY_NO_EXPIRY',
    title: 'Agent: Persistent Memory Without Expiration',
    severity: 'medium',
    cwe: 'CWE-404',
    owasp: 'A04:2026',
    description: 'This file writes to agent persistent memory but nothing in it sets a TTL, retention window, or cleanup pass. A poisoned memory written once stays readable for every future session.',
    fix: 'Set a TTL or retention policy on agent memory, and run a periodic prune of stale entries.',
    test(content) {
      const persistsMemory =
        /(?:memory|longTermMemory|persistent_?[Ss]tate|memory_?store|memoryStore)\w*\s*\.\s*(?:save|store|persist|write|insert|upsert|add|append)\s*\(/i.test(content)
        || /(?:save|store|persist|write)_?[Mm]emory\s*\(/i.test(content);
      if (!persistsMemory) return false;

      const hasRetention =
        /\b(?:ttl|expir\w*|max_?age|retention|cleanup|prune|evict\w*|purge|vacuum|gc_\w+)\b/i.test(content);

      return !hasRetention;
    },
  },
  {
    rule: 'AGENT_NO_COST_LIMIT',
    title: 'Agent: No Spending/Token Limit',
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'A04:2021',
    description: 'This file issues LLM completions but sets no token ceiling or cost budget anywhere in it. An agent loop that misbehaves bills the operator until the provider stops it.',
    fix: 'Set max_tokens on every completion call and enforce a per-session cost budget.',
    test(content) {
      const callsModel =
        /(?:chat\.completions\.create|messages\.create|responses\.create|createChatCompletion|\.generate(?:_content)?\s*\(|completion\s*\()/i.test(content);
      if (!callsModel) return false;

      const hasCeiling =
        /\b(?:max_?tokens|max_?output_?tokens|max_?completion_?tokens|budget|cost_?limit|token_?limit|max_?spend|quota)\b/i.test(content);

      return !hasCeiling;
    },
  },
  {
    rule: 'AGENT_NO_OUTPUT_SCHEMA',
    title: 'Agent: Model Output Parsed Without Schema Validation',
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    description: 'This file parses model output as JSON but validates it against no schema. A model that returns a differently shaped object, whether by drift or by injection, flows straight into the code that consumes it.',
    fix: 'Validate parsed model output against an explicit schema (zod, pydantic, jsonschema) before use.',
    test(content) {
      const parsesModelOutput =
        /(?:JSON\.parse|json\.loads)\s*\(\s*(?:completion|response|output|result|generated|llm|ai|gpt|claude)\w*\s*[,)]/i.test(content);
      if (!parsesModelOutput) return false;

      // Deliberately generous. The claim is "nothing here validates the
      // shape"; one validator refutes it. `\w*schema` matters because the
      // common idiom names the schema after the type — `ResultSchema.parse`,
      // `UserSchema.safeParse` — and a bare `\bschema\b` misses all of them.
      const validates =
        /\b(?:zod|yup|joi|ajv|jsonschema|pydantic|BaseModel|TypeAdapter|type_adapter|safeParse|validate\w*\s*\(|\w*schema)\b/i.test(content);

      return !validates;
    },
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
      findings = findings.concat(this.scanToolCallStructure(file));
    }
    return findings;
  }

  scanToolCallStructure(file) {
    const content = this.readFile(file);
    if (!content) return [];

    const findings = [];
    for (const rule of AGENT_STRUCTURAL_RULES) {
      if (!rule.test(content)) continue;
      const line = this.findLine(content, rule);
      const lines = content.split('\n');
      const matched = lines[line - 1] || '';
      if (this.isSuppressed(matched, rule.severity)) continue;

      const finding = createFinding({
        file,
        line,
        column: 1,
        severity: rule.severity,
        category: this.category,
        rule: rule.rule,
        title: rule.title,
        description: rule.description,
        matched: matched.slice(0, 180),
        confidence: 'medium',
        cwe: rule.cwe,
        owasp: rule.owasp,
        fix: rule.fix,
      });

      const start = Math.max(0, line - 4);
      const end = Math.min(lines.length, line + 3);
      finding.codeContext = lines.slice(start, end).map((text, idx) => ({
        line: start + idx + 1,
        text,
        highlight: (start + idx + 1) === line,
      }));
      findings.push(finding);
    }

    return findings;
  }

  findLine(content, rule) {
    const markers = {
      AGENT_DYNAMIC_TOOL_LOADING_FROM_CONTEXT: /(?:system|developer|messages|prompt)/i,
      AGENT_TOOL_CALL_NO_ALLOWLIST: /(?:executeTool|callTool|invokeTool|toolRegistry|tool_calls?|function_call)/i,
      AGENT_TOOL_CHOICE_REQUIRED_UNTRUSTED: /tool_choice/i,
      AGENT_TOOL_CALL_REPLAY_MISSING_ASSISTANT: /(?:role\s*:\s*['"]tool['"]|tool_call_id|toolCallId)/i,
      AGENT_NO_AUDIT_LOG: /(?:executeTool|callTool|invokeTool|runTool|dispatchTool|tool\.run)/i,
      AGENT_MEMORY_NO_EXPIRY: /(?:memory|longTermMemory|persistent_?[Ss]tate)/i,
      AGENT_NO_COST_LIMIT: /(?:completions\.create|messages\.create|responses\.create|createChatCompletion|\.generate)/i,
      AGENT_NO_OUTPUT_SCHEMA: /(?:JSON\.parse|json\.loads)/i,
      AGENT_CHAIN_NO_ISOLATION: /\b(?:pipe|chain|sequence|workflow)\b/i,
    };
    const marker = markers[rule.rule] || /tool/i;
    const lines = content.split('\n');
    const idx = lines.findIndex(line => marker.test(line));
    return idx === -1 ? 1 : idx + 1;
  }
}

export default AgenticSecurityAgent;
