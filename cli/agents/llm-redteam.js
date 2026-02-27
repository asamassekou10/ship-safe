/**
 * LLMRedTeam Agent
 * =================
 *
 * AI/LLM security testing based on OWASP LLM Top 10 2025.
 * Detects prompt injection vulnerabilities, system prompt leakage,
 * unsafe LLM output handling, excessive agency, and more.
 */

import path from 'path';
import { BaseAgent } from './base-agent.js';

const PATTERNS = [
  // ── LLM01: Prompt Injection ────────────────────────────────────────────────
  {
    rule: 'LLM_PROMPT_INJECTION_NO_SANITIZE',
    title: 'Prompt Injection: No Input Sanitization',
    regex: /(?:messages|prompt|content)\s*[:=]\s*(?:`[^`]*\$\{(?:req\.|request\.|body|query|params|input|user)|.*\+\s*(?:req\.|request\.|body|query|params|input|user))/g,
    severity: 'high',
    cwe: 'CWE-77',
    owasp: 'LLM01',
    description: 'User input concatenated directly into LLM prompt without sanitization enables prompt injection.',
    fix: 'Sanitize user input, use structured messages, separate system/user content clearly',
  },
  {
    rule: 'LLM_SYSTEM_USER_CONCAT',
    title: 'Prompt Injection: System + User Concatenation',
    regex: /(?:system|systemPrompt|system_prompt)\s*[:=].*(?:\+\s*(?:user|input|query|message)|`[^`]*\$\{)/g,
    severity: 'critical',
    cwe: 'CWE-77',
    owasp: 'LLM01',
    description: 'System prompt concatenated with user input. User can override system instructions.',
    fix: 'Use separate message roles: [{role:"system", content: systemPrompt}, {role:"user", content: userInput}]',
  },

  // ── LLM02: Sensitive Information Disclosure ────────────────────────────────
  {
    rule: 'LLM_SECRET_IN_PROMPT',
    title: 'Sensitive Data in LLM Prompt',
    regex: /(?:system|prompt|content)\s*[:=].*(?:API_KEY|api_key|SECRET|PASSWORD|TOKEN|PRIVATE_KEY|DATABASE_URL)/g,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'LLM02',
    description: 'Sensitive data (secrets, keys) included in LLM prompt. Data may be logged or leaked.',
    fix: 'Never include real credentials in prompts. Use placeholder references instead.',
  },
  {
    rule: 'LLM_NO_OUTPUT_FILTER',
    title: 'LLM Output Without Filtering',
    regex: /(?:completion|response|result|output)(?:\.\w+)*\.(?:content|text|message)\s*(?:\)|;)/g,
    severity: 'medium',
    cwe: 'CWE-200',
    owasp: 'LLM02',
    confidence: 'low',
    description: 'LLM output used directly without filtering. May contain sensitive info or hallucinations.',
    fix: 'Filter LLM output before displaying: remove PII, validate against expected format',
  },

  // ── LLM05: Improper Output Handling ────────────────────────────────────────
  {
    rule: 'LLM_OUTPUT_TO_EVAL',
    title: 'LLM Output to eval()/Function()',
    regex: /eval\s*\(\s*(?:completion|response|result|output|generated|llm|ai|gpt|claude)/gi,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'LLM05',
    description: 'LLM output passed to eval() enables arbitrary code execution via prompt injection.',
    fix: 'Never eval() LLM output. Parse as JSON with try/catch, or use a sandboxed interpreter.',
  },
  {
    rule: 'LLM_OUTPUT_TO_SQL',
    title: 'LLM Output in SQL Query',
    regex: /(?:query|execute|raw)\s*\(\s*(?:completion|response|result|output|generated|llm|ai|gpt|claude)/gi,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'LLM05',
    description: 'LLM-generated text used in SQL query. Attacker can inject SQL via prompt injection.',
    fix: 'Never use LLM output in raw SQL. Validate against expected query patterns.',
  },
  {
    rule: 'LLM_OUTPUT_TO_HTML',
    title: 'LLM Output Rendered as HTML',
    regex: /(?:innerHTML|dangerouslySetInnerHTML|v-html)\s*=\s*(?:.*(?:completion|response|result|output|generated|llm|ai|gpt|claude))/gi,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'LLM05',
    description: 'LLM output rendered as unescaped HTML enables XSS via prompt injection.',
    fix: 'Render LLM output as text, or sanitize with DOMPurify before HTML rendering.',
  },
  {
    rule: 'LLM_OUTPUT_TO_SHELL',
    title: 'LLM Output in Shell Command',
    regex: /(?:exec|spawn|system|popen)\s*\(\s*(?:completion|response|result|output|generated|llm|ai|gpt|claude)/gi,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'LLM05',
    description: 'LLM output used in shell command enables RCE via prompt injection.',
    fix: 'Never pass LLM output to shell. Use a strict allowlist of allowed commands.',
  },

  // ── LLM06: Excessive Agency ────────────────────────────────────────────────
  {
    rule: 'LLM_TOOL_NO_CONFIRM',
    title: 'LLM Tool Use Without Confirmation',
    regex: /(?:tools|functions|function_call)\s*[:=]\s*\[.*(?:write|delete|update|create|send|execute|deploy|modify)/gi,
    severity: 'high',
    cwe: 'CWE-862',
    owasp: 'LLM06',
    confidence: 'medium',
    description: 'LLM given tools with side effects (write/delete/send) without human confirmation.',
    fix: 'Require human approval for destructive actions. Implement an approval workflow.',
  },
  {
    rule: 'LLM_DB_WRITE_ACCESS',
    title: 'LLM Has Database Write Access',
    regex: /(?:tool|function).*(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*(?:sql|query|database|db)/gi,
    severity: 'critical',
    cwe: 'CWE-862',
    owasp: 'LLM06',
    description: 'LLM can write to database. Prompt injection could corrupt or destroy data.',
    fix: 'Give LLM read-only database access. Require human approval for writes.',
  },
  {
    rule: 'LLM_FILE_WRITE',
    title: 'LLM Has File System Write Access',
    regex: /(?:tool|function).*(?:writeFile|fs\.write|unlink|rmdir|mkdir)/gi,
    severity: 'critical',
    cwe: 'CWE-862',
    owasp: 'LLM06',
    description: 'LLM can write/delete files. Prompt injection could modify or destroy files.',
    fix: 'Restrict LLM file access to a sandboxed directory with read-only permissions.',
  },

  // ── LLM07: System Prompt Leakage ───────────────────────────────────────────
  {
    rule: 'LLM_SYSTEM_PROMPT_CLIENT',
    title: 'System Prompt Exposed to Client',
    regex: /(?:systemPrompt|system_prompt|SYSTEM_PROMPT)\s*[:=]\s*["'`]/g,
    severity: 'high',
    cwe: 'CWE-200',
    owasp: 'LLM07',
    confidence: 'medium',
    description: 'System prompt hardcoded in code. If client-side, users can extract it.',
    fix: 'Keep system prompts server-side only. Load from environment variables or config.',
  },

  // ── LLM10: Unbounded Consumption ───────────────────────────────────────────
  {
    rule: 'LLM_NO_TOKEN_LIMIT',
    title: 'LLM Call Without Token Limit',
    regex: /(?:openai|anthropic|ai)\.\w+\.create\s*\(\s*\{(?![\s\S]*max_tokens)[\s\S]*?\}/g,
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'LLM10',
    confidence: 'low',
    description: 'LLM API call without max_tokens limit. Could generate excessive output and costs.',
    fix: 'Set max_tokens in API call to limit response size and costs',
  },
  {
    rule: 'LLM_NO_RATE_LIMIT',
    title: 'LLM Endpoint Without Rate Limiting',
    regex: /(?:\/api\/.*(?:chat|complete|generate|ai|llm|gpt|claude)|\/chat|\/generate)\s*['"]/gi,
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'LLM10',
    confidence: 'low',
    description: 'AI endpoint without rate limiting. Users could rack up API costs.',
    fix: 'Add rate limiting per user: express-rate-limit, @upstash/ratelimit, etc.',
  },
  {
    rule: 'LLM_NO_COST_LIMIT',
    title: 'LLM Usage Without Cost Controls',
    regex: /(?:OPENAI|ANTHROPIC|AI)_(?:API_KEY|KEY).*(?!(?:budget|limit|cap|max_cost|spending))/gi,
    severity: 'medium',
    cwe: 'CWE-770',
    owasp: 'LLM10',
    confidence: 'low',
    description: 'AI API usage without cost controls. Set spending limits on your provider dashboard.',
    fix: 'Configure spending limits in OpenAI/Anthropic dashboard. Add per-user token budgets.',
  },

  // ── LLM03: Supply Chain ────────────────────────────────────────────────────
  {
    rule: 'LLM_UNVERIFIED_MODEL',
    title: 'Unverified Model Download',
    regex: /(?:from_pretrained|AutoModel|pipeline)\s*\(\s*["'][^"']+\/[^"']+["']/g,
    severity: 'medium',
    cwe: 'CWE-829',
    owasp: 'LLM03',
    confidence: 'low',
    description: 'Loading model from Hugging Face without verification. Model could contain backdoors.',
    fix: 'Verify model hash, use models from trusted organizations, scan for malicious code',
  },

  // ── LLM08: Vector/Embedding Weaknesses ─────────────────────────────────────
  {
    rule: 'LLM_RAG_NO_VALIDATION',
    title: 'RAG Pipeline Without Input Validation',
    regex: /(?:embed|embedding|vector|similarity_search|query)\s*\(\s*(?:req\.|request\.|body|query|params|input|user)/g,
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'LLM08',
    description: 'User input passed directly to vector search/embedding without validation.',
    fix: 'Validate and sanitize input before embedding. Limit query length.',
  },
  {
    rule: 'LLM_RAG_NO_ACCESS_CONTROL',
    title: 'RAG Without Access Control',
    regex: /(?:pinecone|chroma|weaviate|qdrant|milvus).*(?:query|search|similarity)\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-862',
    owasp: 'LLM08',
    confidence: 'low',
    description: 'Vector database query without access control. Users may access other users\' data.',
    fix: 'Add namespace/tenant filtering: filter by userId in vector DB queries',
  },

  // ── Prompt Injection Patterns (content-level detection) ────────────────────
  {
    rule: 'PROMPT_INJECTION_PATTERN',
    title: 'Known Prompt Injection Pattern',
    regex: /(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)|you\s+are\s+now\s+DAN|system\s*prompt|jailbreak|bypass\s+(?:your|the)\s+(?:rules|instructions|guidelines))/gi,
    severity: 'high',
    cwe: 'CWE-77',
    owasp: 'LLM01',
    description: 'Known prompt injection pattern detected in code. Ensure this is for testing only.',
    fix: 'If in test data, add # ship-safe-ignore. If in user-facing code, add input filtering.',
  },
];

export class LLMRedTeam extends BaseAgent {
  constructor() {
    super('LLMRedTeam', 'AI/LLM security audit based on OWASP LLM Top 10', 'llm');
  }

  async analyze(context) {
    const { files } = context;
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default LLMRedTeam;
