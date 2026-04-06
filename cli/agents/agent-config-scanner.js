/**
 * Agent Config Scanner
 * =====================
 *
 * Detects security vulnerabilities in AI agent configuration and
 * instruction files — the new control plane for AI-powered development.
 *
 * OpenClaw had 7 CVEs in 60 days (ClawJacked, CVE-2026-25253).
 * ClawHavoc campaign injected 1,184 malicious skills into ClawHub.
 * Check Point disclosed RCE via malicious Claude Code hooks.
 * OWASP Agentic Top 10 (ASI01–ASI10) treats agent configs as code.
 *
 * Scans: .cursorrules, CLAUDE.md, AGENTS.md, .windsurfrules,
 *        copilot-instructions.md, OpenClaw configs, Claude Code hooks,
 *        agent memory files. Detects prompt injection, data exfiltration,
 *        encoded payloads, excessive permissions, unsafe OpenClaw settings.
 *
 * Maps to: OWASP Agentic AI ASI01 (Goal Hijacking), ASI02 (Tool Misuse),
 *          ASI03 (Privilege Abuse), ASI04 (Supply Chain)
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import fg from 'fast-glob';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// TARGET FILES
// =============================================================================

const AGENT_RULES_FILES = [
  '.cursorrules',
  '.windsurfrules',
  'CLAUDE.md',
  'AGENTS.md',
  '.github/copilot-instructions.md',
  '.aider.conf.yml',
  '.continue/config.json',
  // Gemini CLI
  '.gemini/settings.json',
  '.gemini/rules.md',
  // Cody (Sourcegraph)
  '.cody/config.json',
  '.cody/context.json',
  // Augment Code
  '.augment/config.json',
];

const AGENT_RULES_GLOBS = [
  '.cursor/rules/*.mdc',
  '.claude/commands/*.md',
  // Gemini CLI commands
  '.gemini/commands/*.md',
  // Cody custom commands
  '.cody/commands/*.md',
  '.cody/rules/*.md',
];

const OPENCLAW_FILES = [
  'openclaw.json',
  'openclaw.config.json',
  'clawhub.json',
];

const OPENCLAW_GLOBS = [
  '.openclaw/**/*.json',
];

// openclaude (github.com/Gitlawb/openclaude) — Claude Code fork with
// OpenAI-compatible provider shim. Config is purely via environment variables
// (CLAUDE_CODE_USE_OPENAI, OPENAI_BASE_URL, OPENAI_MODEL, OPENAI_API_KEY).
// The only persistent file artifact is .openclaude-profile.json, which stores
// named profiles as { name, env: { OPENAI_BASE_URL, OPENAI_API_KEY, ... } }.
const OPENCLAUDE_PROFILE_FILES = [
  '.openclaude-profile.json',
];

// claw-code (github.com/instructkr/claw-code, now ultraworkers/claw-code) —
// Rust + Python clean-room rewrite of Claude Code's agent harness.
// CLI tool (`claw` binary). NOT a server — no port binding outside tests.
// Config files: .claw.json (project root), .claw/settings.json,
//   .claw/settings.local.json, ~/.claw.json, ~/.claw/settings.json
// Auth: ANTHROPIC_API_KEY, OPENAI_API_KEY, or XAI_API_KEY env vars.
// Permission modes: read-only, workspace-write, danger-full-access, prompt, allow.
// --dangerously-skip-permissions flag disables all permission checks.
// Sandbox: SandboxConfig with FilesystemIsolationMode (workspace-only default).
// Hooks: preToolUse / postToolUse arrays in settings JSON.
// MCP: mcpServers in settings JSON (stdio, sse, http, ws transports).
const CLAW_CODE_FILES = [
  '.claw.json',
  '.claw/settings.json',
  '.claw/settings.local.json',
];

const MEMORY_GLOBS = [
  '.claude/memory/**',
  '.cursor/memory/**',
  '.continue/memory/**',
  '.gemini/memory/**',
  '.cody/memory/**',
];

// =============================================================================
// PATTERNS — Prompt Injection & Malicious Instructions in Agent Config Files
// =============================================================================

const PATTERNS = [
  // ── Prompt Override Injection (ASI01) ────────────────────────────────────
  {
    rule: 'AGENT_CFG_PROMPT_OVERRIDE',
    title: 'Agent Config: Prompt Injection — Override Instructions',
    regex: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?(?:above|prior|previous)|you\s+are\s+now\s+(?:a|an)\s|new\s+(?:instructions|role|persona)\s*:|override\s+(?:system|previous|all)\s+(?:instructions|prompt|rules)|forget\s+(?:everything|all\s+(?:previous|prior)))/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI01',
    description: 'Agent config file contains prompt injection phrasing that attempts to override system instructions. This is a goal hijacking attack.',
    fix: 'Remove the injected instruction. If this file is from a third party or untrusted source, treat the entire file as compromised.',
  },
  {
    rule: 'AGENT_CFG_ROLE_HIJACK',
    title: 'Agent Config: Role/Identity Hijacking',
    regex: /(?:act\s+as\s+(?:a\s+)?(?:hacker|attacker|malicious|evil|unfiltered)|pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new|unrestricted)|your\s+(?:new|real|true|actual)\s+(?:role|purpose|goal|identity)\s+is)/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI01',
    description: 'Agent config attempts to hijack the AI agent\'s role or identity. Attacker can repurpose the agent for malicious actions.',
    fix: 'Remove the role hijacking instruction. Review the file\'s origin and git blame for the change.',
  },
  {
    rule: 'AGENT_CFG_HIDDEN_INSTRUCTION',
    title: 'Agent Config: Hidden Instructions in Comments',
    regex: /<!--[\s\S]{0,500}?(?:ignore|override|execute|fetch|curl|wget|send\s+to|exfiltrate|upload)[\s\S]{0,500}?-->/gi,
    severity: 'critical',
    cwe: 'CWE-74',
    owasp: 'ASI01',
    description: 'Malicious instructions hidden inside HTML comments in agent config file. These are invisible to casual review but processed by some AI agents.',
    fix: 'Remove the HTML comment containing suspicious instructions. Audit all comments in agent config files.',
  },

  // ── Data Exfiltration (ASI02) ───────────────────────────────────────────
  {
    rule: 'AGENT_CFG_EXFIL_URL',
    title: 'Agent Config: Data Exfiltration Instructions',
    regex: /(?:send\s+(?:all\s+)?(?:data|code|content|files|source|secrets|tokens|keys)\s+to|POST\s+(?:all\s+)?(?:data|code|content)\s+to|exfiltrate\s+to|upload\s+(?:all\s+)?(?:data|code|files)\s+to|forward\s+(?:all\s+)?(?:data|code|output)\s+to)\s+https?:\/\//gi,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'ASI02',
    description: 'Agent config instructs the AI to send data to an external URL. This is a data exfiltration attack.',
    fix: 'Remove the exfiltration instruction immediately. Investigate who added it and what data may have been exposed.',
  },
  {
    rule: 'AGENT_CFG_WEBHOOK',
    title: 'Agent Config: Known Exfiltration Service Domain',
    regex: /(?:webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io|ngrok\.app|burpcollaborator\.net|interact\.sh|oastify\.com|canarytokens\.com)/gi,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'ASI02',
    description: 'Agent config references a known data interception/exfiltration service. These are commonly used in prompt injection attacks to steal data.',
    fix: 'Remove the reference to the exfiltration service. These domains have no legitimate use in agent configuration files.',
  },
  {
    rule: 'AGENT_CFG_CURL_FETCH',
    title: 'Agent Config: Outbound HTTP Request Instructions',
    regex: /(?:(?:curl|wget|fetch|http\.get|requests\.get|requests\.post|axios\.(?:get|post))\s+https?:\/\/(?!(?:localhost|127\.0\.0\.1|::1)))/gi,
    severity: 'high',
    cwe: 'CWE-918',
    owasp: 'ASI02',
    confidence: 'medium',
    description: 'Agent config instructs outbound HTTP requests to an external host. Could be used for data exfiltration or command-and-control.',
    fix: 'Verify this URL is legitimate and necessary. Agent config files should not contain outbound request instructions.',
  },

  // ── Code Execution Injection (ASI02) ────────────────────────────────────
  {
    rule: 'AGENT_CFG_SHELL_EXEC',
    title: 'Agent Config: Shell Command Execution',
    regex: /(?:run\s+(?:this\s+)?(?:command|shell|bash|terminal)|execute\s+(?:this\s+)?(?:command|script|code|shell)|(?:^|\s)eval\s*\(|(?:^|\s)exec\s*\(|(?:^|\s)system\s*\(|subprocess\.(?:run|call|Popen))/gim,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'ASI02',
    confidence: 'medium',
    description: 'Agent config contains instructions to execute shell commands. If injected, this enables remote code execution via the AI agent.',
    fix: 'Remove command execution instructions from agent config. If needed, use explicit allowlisted commands in a dedicated hook system.',
  },
  {
    rule: 'AGENT_CFG_DOWNLOAD_EXEC',
    title: 'Agent Config: Download-and-Execute Pattern',
    regex: /(?:download\s+and\s+(?:run|execute)|curl.*\|\s*(?:bash|sh|zsh|node|python)|wget.*\|\s*(?:bash|sh|zsh|node|python)|pipe\s+to\s+(?:bash|sh|interpreter))/gi,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'ASI02',
    description: 'Agent config contains a download-and-execute pattern (e.g., curl | bash). This is a classic remote code execution vector.',
    fix: 'Remove the download-and-execute instruction. Never pipe untrusted content to an interpreter.',
  },

  // ── Encoded / Obfuscated Payloads ───────────────────────────────────────
  {
    rule: 'AGENT_CFG_UNICODE_TAGS',
    title: 'Agent Config: Invisible Unicode Tag Characters',
    regex: /[\u{E0001}-\u{E007F}]/gu,
    severity: 'critical',
    cwe: 'CWE-116',
    owasp: 'ASI01',
    description: 'Agent config contains Unicode Tag characters (U+E0001–U+E007F) used for invisible prompt injection. These are invisible to humans but processed by LLMs.',
    fix: 'Strip all Unicode Tag characters. This is almost certainly a prompt injection attack.',
  },
  {
    rule: 'AGENT_CFG_ZERO_WIDTH',
    title: 'Agent Config: Zero-Width Character Cluster',
    regex: /[\u200B\u200C\u200D\uFEFF\u2060]{4,}/g,
    severity: 'high',
    cwe: 'CWE-116',
    owasp: 'ASI01',
    description: 'Agent config contains a cluster of zero-width characters that may hide encoded instructions.',
    fix: 'Remove zero-width character clusters. Inspect the content for hidden payloads.',
  },

  // ── Excessive Permissions (ASI03) ───────────────────────────────────────
  {
    rule: 'AGENT_CFG_ALLOW_ALL',
    title: 'Agent Config: Overly Permissive Instructions',
    regex: /(?:allow\s+all\s+(?:tools|commands|actions|operations|requests)|no\s+(?:restrictions|limits|boundaries|safeguards)\s+(?:on|for|when)|bypass\s+(?:all\s+)?(?:security|safety|confirmation|approval)|auto[_-]?approve\s+(?:all|everything|any)|skip\s+(?:all\s+)?(?:confirmation|approval|verification|validation))/gi,
    severity: 'high',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    description: 'Agent config grants overly broad permissions or disables safety checks. A prompt injection attack inherits these elevated privileges.',
    fix: 'Apply principle of least privilege. Remove blanket permission grants and configure specific, scoped allowlists.',
  },
  {
    rule: 'AGENT_CFG_DISABLE_SAFETY',
    title: 'Agent Config: Safety Mechanism Disabled',
    regex: /(?:disable\s+(?:all\s+)?(?:safety|security|guardrails|filters|protections)|turn\s+off\s+(?:all\s+)?(?:safety|security|protection|filtering)|remove\s+(?:all\s+)?(?:restrictions|limits|guards|safeguards|filters))/gi,
    severity: 'high',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    description: 'Agent config explicitly disables safety mechanisms. This removes guardrails that protect against prompt injection and misuse.',
    fix: 'Re-enable safety mechanisms. If specific overrides are needed, configure them granularly rather than disabling all protections.',
  },
];

// =============================================================================
// AGENT CONFIG SCANNER
// =============================================================================

export class AgentConfigScanner extends BaseAgent {
  constructor() {
    super(
      'AgentConfigScanner',
      'Detect security risks in AI agent config files — prompt injection in .cursorrules/CLAUDE.md, malicious hooks, OpenClaw misconfigs, encoded payloads',
      'llm'
    );
  }

  async analyze(context) {
    const { rootPath } = context;
    let findings = [];

    // ── 1. Discover all agent config files ─────────────────────────────────
    const discovered = await this._findAgentConfigFiles(rootPath);

    // ── 2. Scan rules/instruction files with prompt injection patterns ─────
    for (const file of discovered.rulesFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._checkEncodedPayloads(file));
    }

    // ── 3. Scan OpenClaw configs (structural + patterns) ───────────────────
    for (const file of discovered.openclawFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._scanOpenClawConfig(file));
    }

    // ── 3b. Scan openclaude profile files ─────────────────────────────────
    for (const file of discovered.openclaudeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._scanOpenClaudeProfile(file));
    }

    // ── 3c. Scan claw-code config files ────────────────────────────────────
    for (const file of discovered.clawCodeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      findings = findings.concat(this._scanClawCodeConfig(file));
    }

    // ── 4. Scan Claude Code hooks ──────────────────────────────────────────
    for (const file of discovered.claudeSettingsFiles) {
      findings = findings.concat(this._scanClaudeHooks(file));
    }

    // ── 5. Scan agent memory directories for poisoning ─────────────────────
    for (const file of discovered.memoryFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }

    return findings;
  }

  // ===========================================================================
  // FILE DISCOVERY
  // ===========================================================================

  async _findAgentConfigFiles(rootPath) {
    const rulesFiles = [];
    const openclawFiles = [];
    const claudeSettingsFiles = [];
    const memoryFiles = [];

    // ── Static rules files ──────────────────────────────────────────────────
    for (const rel of AGENT_RULES_FILES) {
      const full = path.join(rootPath, rel);
      if (fs.existsSync(full)) rulesFiles.push(full);
    }

    // ── Glob-based rules files ──────────────────────────────────────────────
    try {
      const globbed = await fg(AGENT_RULES_GLOBS, {
        cwd: rootPath, absolute: true, dot: true,
      });
      rulesFiles.push(...globbed);
    } catch { /* skip */ }

    // ── OpenClaw files ──────────────────────────────────────────────────────
    for (const rel of OPENCLAW_FILES) {
      const full = path.join(rootPath, rel);
      if (fs.existsSync(full)) openclawFiles.push(full);
    }
    try {
      const globbed = await fg(OPENCLAW_GLOBS, {
        cwd: rootPath, absolute: true, dot: true,
      });
      openclawFiles.push(...globbed);
    } catch { /* skip */ }

    // ── Claude settings (project + shadow) ──────────────────────────────────
    const projectClaudeSettings = path.join(rootPath, '.claude', 'settings.json');
    if (fs.existsSync(projectClaudeSettings)) claudeSettingsFiles.push(projectClaudeSettings);

    const home = os.homedir();
    const shadowClaudeSettings = path.join(home, '.claude', 'settings.json');
    if (fs.existsSync(shadowClaudeSettings) && shadowClaudeSettings !== projectClaudeSettings) {
      claudeSettingsFiles.push(shadowClaudeSettings);
    }

    // ── Memory files ────────────────────────────────────────────────────────
    try {
      const globbed = await fg(MEMORY_GLOBS, {
        cwd: rootPath, absolute: true, dot: true,
      });
      memoryFiles.push(...globbed);
    } catch { /* skip */ }

    // ── openclaude profile files ─────────────────────────────────────────────
    const openclaudeFiles = [];
    for (const rel of OPENCLAUDE_PROFILE_FILES) {
      const full = path.join(rootPath, rel);
      if (fs.existsSync(full)) openclaudeFiles.push(full);
    }

    // ── claw-code config files ────────────────────────────────────────────────
    const clawCodeFiles = [];
    for (const rel of CLAW_CODE_FILES) {
      const full = path.join(rootPath, rel);
      if (fs.existsSync(full)) clawCodeFiles.push(full);
    }

    return { rulesFiles, openclawFiles, openclaudeFiles, clawCodeFiles, claudeSettingsFiles, memoryFiles };
  }

  // ===========================================================================
  // STRUCTURAL CHECKS
  // ===========================================================================

  /**
   * Scan OpenClaw configuration files for unsafe settings.
   * Covers CVE-2026-25253 (0.0.0.0 binding), missing auth, untrusted skills.
   */
  _scanOpenClawConfig(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    let config;
    try { config = JSON.parse(content); } catch { return []; }

    // ── Public bind (CVE-2026-25253) ──────────────────────────────────────
    const host = config.host || config.bind || config.gateway?.host || config.gateway?.bind || '';
    if (host === '0.0.0.0') {
      findings.push({
        file: filePath, line: 1, column: 0,
        severity: 'critical',
        category: this.category,
        rule: 'OPENCLAW_PUBLIC_BIND',
        title: 'OpenClaw: Gateway Bound to 0.0.0.0 (Public)',
        description: 'OpenClaw gateway is bound to all network interfaces (0.0.0.0), exposing the agent to the public internet. This is the CVE-2026-25253 pattern — the default that exposed 135,000+ instances.',
        matched: `host: "${host}"`,
        confidence: 'high',
        cwe: 'CWE-668',
        owasp: 'A05:2021',
        fix: 'Bind to 127.0.0.1 (localhost) unless you explicitly need remote access with proper authentication.',
      });
    }

    // ── No authentication ─────────────────────────────────────────────────
    const hasAuth = config.auth || config.authentication || config.apiKey ||
                    config.gateway?.auth || config.gateway?.apiKey || config.gateway?.password;
    if (!hasAuth) {
      findings.push({
        file: filePath, line: 1, column: 0,
        severity: 'critical',
        category: this.category,
        rule: 'OPENCLAW_NO_AUTH',
        title: 'OpenClaw: No Authentication Configured',
        description: 'OpenClaw gateway has no authentication. Any client can connect and control the agent — execute commands, read files, send messages.',
        matched: 'No auth/apiKey/password field found',
        confidence: 'high',
        cwe: 'CWE-306',
        owasp: 'A07:2021',
        fix: 'Configure authentication: set an API key, password, or OAuth. Never run OpenClaw unauthenticated.',
      });
    }

    // ── No TLS (ws:// instead of wss://) ──────────────────────────────────
    const url = config.url || config.gateway?.url || config.websocket || '';
    if (/^ws:\/\/(?!localhost|127\.0\.0\.1|::1)/i.test(url)) {
      findings.push({
        file: filePath, line: 1, column: 0,
        severity: 'high',
        category: this.category,
        rule: 'OPENCLAW_NO_TLS',
        title: 'OpenClaw: WebSocket Without TLS',
        description: 'OpenClaw uses ws:// (unencrypted WebSocket) for a non-localhost connection. Agent commands and data are sent in plaintext.',
        matched: url,
        confidence: 'high',
        cwe: 'CWE-319',
        owasp: 'A02:2021',
        fix: 'Use wss:// (WebSocket Secure) for all non-localhost connections.',
      });
    }

    // ── safeBins disabled ─────────────────────────────────────────────────
    if (config.safeBins === false || (config.safeBins && Array.isArray(config.safeBins) && config.safeBins.length === 0)) {
      findings.push({
        file: filePath, line: 1, column: 0,
        severity: 'high',
        category: this.category,
        rule: 'OPENCLAW_SAFEBINS_BYPASS',
        title: 'OpenClaw: safeBins Protection Disabled',
        description: 'OpenClaw safeBins is disabled or empty. The agent can execute any binary on the system without restriction (CVE-2026-28363 pattern).',
        matched: `safeBins: ${JSON.stringify(config.safeBins)}`,
        confidence: 'high',
        cwe: 'CWE-269',
        owasp: 'ASI03',
        fix: 'Enable safeBins with an explicit allowlist of permitted binaries.',
      });
    }

    // ── Skills with shell/exec capabilities ───────────────────────────────
    const skills = config.skills || config.agentSkills || [];
    if (Array.isArray(skills)) {
      for (const skill of skills) {
        const name = typeof skill === 'string' ? skill : (skill.name || skill.id || '');
        const caps = typeof skill === 'object' ? JSON.stringify(skill) : '';
        if (/(?:shell|exec|command|terminal|bash|subprocess|system)/i.test(caps)) {
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'high',
            category: this.category,
            rule: 'OPENCLAW_SKILL_SHELL',
            title: `OpenClaw: Skill "${name}" Has Shell Access`,
            description: `OpenClaw skill "${name}" has shell/command execution capabilities. Prompt injection can achieve RCE through this skill.`,
            matched: name,
            confidence: 'medium',
            cwe: 'CWE-78',
            owasp: 'ASI02',
            fix: 'Remove shell execution skills unless absolutely necessary. Use scoped, validated alternatives.',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Scan .openclaude-profile.json for security issues.
   *
   * openclaude (github.com/Gitlawb/openclaude) is a CLI tool, not a server.
   * There is no config file, no host/port binding, no auth mechanism.
   * All configuration is via environment variables:
   *   CLAUDE_CODE_USE_OPENAI=1, OPENAI_BASE_URL, OPENAI_MODEL, OPENAI_API_KEY
   *
   * The only persistent file artifact is .openclaude-profile.json, which stores
   * named profiles as { name: string, env: { OPENAI_BASE_URL, OPENAI_API_KEY, ... } }.
   * openclaude ships with this file in its default .gitignore.
   *
   * Security risk: if OPENAI_BASE_URL is an http:// (non-TLS) endpoint, all
   * LLM traffic (prompts, code context, responses) is sent unencrypted.
   */
  _scanOpenClaudeProfile(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    let profile;
    try { profile = JSON.parse(content); } catch { return []; }

    const env = profile.env || {};

    // ── Insecure provider URL (http:// for non-localhost) ─────────────────
    const baseUrl = env.OPENAI_BASE_URL || '';
    if (baseUrl && /^http:\/\/(?!localhost|127\.0\.0\.1|::1)/i.test(baseUrl)) {
      findings.push(createFinding({
        file: filePath, line: 1,
        severity: 'high',
        category: this.category,
        rule: 'OPENCLAUDE_INSECURE_PROVIDER_URL',
        title: 'openclaude: LLM Provider URL Without TLS',
        description:
          `openclaude routes model calls to ${baseUrl} over plain HTTP. ` +
          'Prompts, code context, and model responses are sent unencrypted. ' +
          'A network attacker can read or modify all LLM interactions in transit.',
        matched: `OPENAI_BASE_URL: "${baseUrl}"`,
        confidence: 'high',
        cwe: 'CWE-319',
        owasp: 'A02:2021',
        fix: 'Use an https:// provider URL. Never route LLM traffic over plaintext HTTP on untrusted networks.',
      }));
    }

    return findings;
  }

  /**
   * Scan claw-code config files (.claw.json, .claw/settings.json, .claw/settings.local.json)
   * for insecure settings.
   *
   * claw-code (ultraworkers/claw-code) is a Rust + Python clean-room rewrite of Claude Code.
   * It is a CLI tool — no server port binding. Config lives in JSON settings files.
   *
   * Checked settings:
   *   - hooks.preToolUse / hooks.postToolUse: shell hook commands (RCE vector)
   *   - permissions.dangerouslySkipPermissions / permissionMode: "danger-full-access"
   *   - sandbox.enabled: false (filesystem isolation disabled)
   *   - mcpServers with insecure ws:// or http:// remote URLs (MiTM risk)
   *   - mcpServers using env vars that could expose credentials
   */
  _scanClawCodeConfig(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    let config;
    try { config = JSON.parse(content); } catch { return []; }

    // ── Dangerous permission mode ─────────────────────────────────────────
    const permMode = config.permissionMode ?? config.permissions?.mode ?? '';
    const skipPerms = config.dangerouslySkipPermissions ??
      config.permissions?.dangerouslySkipPermissions ?? false;

    if (skipPerms === true || permMode === 'danger-full-access') {
      findings.push(createFinding({
        file: filePath, line: 1,
        severity: 'high',
        category: this.category,
        rule: 'CLAW_CODE_SKIP_PERMISSIONS',
        title: 'claw-code: All Permission Checks Disabled',
        description:
          'claw-code is configured with dangerously-skip-permissions or permissionMode: danger-full-access. ' +
          'Every tool call executes without asking for user confirmation. ' +
          'A single prompt injection in any file the agent reads can trigger unrestricted shell execution or file writes.',
        matched: skipPerms ? 'dangerouslySkipPermissions: true' : `permissionMode: "${permMode}"`,
        confidence: 'high',
        cwe: 'CWE-269',
        owasp: 'ASI03',
        fix: 'Set permissionMode to "workspace-write" or "prompt". Only use danger-full-access in fully isolated environments.',
      }));
    }

    // ── Sandbox disabled ──────────────────────────────────────────────────
    if (config.sandbox?.enabled === false) {
      findings.push(createFinding({
        file: filePath, line: 1,
        severity: 'medium',
        category: this.category,
        rule: 'CLAW_CODE_SANDBOX_DISABLED',
        title: 'claw-code: Filesystem Sandbox Disabled',
        description:
          'claw-code sandbox is explicitly disabled. By default claw-code restricts ' +
          'filesystem access to the workspace directory. With sandbox off, tools can ' +
          'read and write anywhere on the system.',
        matched: 'sandbox.enabled: false',
        confidence: 'high',
        cwe: 'CWE-732',
        owasp: 'ASI03',
        fix: 'Remove sandbox.enabled: false or set filesystem-mode to workspace-only.',
      }));
    }

    // ── Hooks with shell commands ──────────────────────────────────────────
    const hookLists = [
      ...(config.hooks?.preToolUse || []),
      ...(config.hooks?.postToolUse || []),
    ];
    for (const hook of hookLists) {
      const cmd = typeof hook === 'string' ? hook : (hook.command || hook.cmd || hook.run || '');
      if (!cmd) continue;
      if (/(?:bash\s+-c|sh\s+-c|cmd\s+\/c|powershell\s+-|pwsh\s+-)/i.test(cmd) ||
          /\|\s*(?:bash|sh|zsh|node|python)/i.test(cmd) ||
          /(?:curl|wget)\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i.test(cmd)) {
        findings.push(createFinding({
          file: filePath, line: 1,
          severity: 'critical',
          category: this.category,
          rule: 'CLAW_CODE_HOOK_SHELL',
          title: 'claw-code: Dangerous Hook Command',
          description:
            'claw-code hook contains a shell execution or remote download command. ' +
            'A malicious .claw.json in a repository can achieve RCE when anyone ' +
            'opens the project with claw.',
          matched: cmd.substring(0, 150),
          confidence: 'high',
          cwe: 'CWE-94',
          owasp: 'ASI04',
          fix: 'Remove shell execution hooks. Use only safe, scoped commands in claw hooks.',
        }));
      }
    }

    // ── MCP servers with insecure remote URLs ─────────────────────────────
    const mcpServers = config.mcpServers || {};
    for (const [name, srv] of Object.entries(mcpServers)) {
      const url = typeof srv === 'object' ? (srv.url || '') : '';
      if (/^(?:ws|http):\/\/(?!localhost|127\.0\.0\.1|::1)/i.test(url)) {
        findings.push(createFinding({
          file: filePath, line: 1,
          severity: 'high',
          category: this.category,
          rule: 'CLAW_CODE_MCP_INSECURE_URL',
          title: `claw-code: MCP Server "${name}" Uses Unencrypted Transport`,
          description:
            `MCP server "${name}" connects to ${url} over an unencrypted channel (ws:// or http://). ` +
            'All MCP messages — tool calls, results, and any code context — are sent in plaintext. ' +
            'A network attacker can intercept or inject MCP responses to hijack the agent.',
          matched: url,
          confidence: 'high',
          cwe: 'CWE-319',
          owasp: 'A02:2021',
          fix: 'Use wss:// or https:// for all non-localhost MCP server connections.',
        }));
      }
    }

    return findings;
  }

  /**
   * Scan .claude/settings.json for malicious hooks.
   * Based on Check Point Research disclosure: hooks in settings.json
   * execute arbitrary commands when developers open a project.
   */
  _scanClaudeHooks(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    let config;
    try { config = JSON.parse(content); } catch { return []; }

    const hooks = config.hooks || {};
    const hookEntries = Object.entries(hooks);

    for (const [event, hookList] of hookEntries) {
      const items = Array.isArray(hookList) ? hookList : [hookList];
      for (const hook of items) {
        const cmd = typeof hook === 'string' ? hook : (hook.command || hook.cmd || hook.run || '');
        if (!cmd) continue;

        // ── Shell command execution ─────────────────────────────────────
        if (/(?:bash\s+-c|sh\s+-c|cmd\s+\/c|powershell\s+-|pwsh\s+-)/i.test(cmd)) {
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'critical',
            category: this.category,
            rule: 'CLAUDE_HOOK_SHELL_CMD',
            title: `Claude Hook: Shell Execution on "${event}"`,
            description: `Claude Code hook on "${event}" event executes a shell command. A malicious .claude/settings.json in a repo can achieve RCE when a developer opens the project.`,
            matched: cmd.substring(0, 200),
            confidence: 'high',
            cwe: 'CWE-94',
            owasp: 'ASI04',
            fix: 'Remove the shell execution hook. If automation is needed, use Claude Code\'s built-in hook system with explicit user approval.',
          });
        }

        // ── Download from external URL ──────────────────────────────────
        if (/(?:curl|wget|fetch|http\.get|Invoke-WebRequest)\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i.test(cmd)) {
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'critical',
            category: this.category,
            rule: 'CLAUDE_HOOK_DOWNLOAD',
            title: `Claude Hook: External Download on "${event}"`,
            description: `Claude Code hook on "${event}" event downloads content from an external URL. This could fetch and execute malicious payloads.`,
            matched: cmd.substring(0, 200),
            confidence: 'high',
            cwe: 'CWE-494',
            owasp: 'ASI04',
            fix: 'Remove the download hook. Agent hooks should not fetch content from external URLs.',
          });
        }

        // ── Pipe to interpreter ─────────────────────────────────────────
        if (/\|\s*(?:bash|sh|zsh|node|python|ruby|perl|php)/i.test(cmd)) {
          findings.push({
            file: filePath, line: 1, column: 0,
            severity: 'critical',
            category: this.category,
            rule: 'CLAUDE_HOOK_PIPE_EXEC',
            title: `Claude Hook: Pipe-to-Interpreter on "${event}"`,
            description: `Claude Code hook on "${event}" pipes output to an interpreter (bash, node, python). Classic download-and-execute RCE vector.`,
            matched: cmd.substring(0, 200),
            confidence: 'high',
            cwe: 'CWE-78',
            owasp: 'ASI04',
            fix: 'Remove the pipe-to-interpreter pattern. Never pipe untrusted content to a language interpreter.',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Check for encoded/obfuscated payloads in agent config files.
   * Detects large base64 blocks that may hide prompt injection.
   */
  _checkEncodedPayloads(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];
    const findings = [];

    // Check for large base64 blocks (60+ chars, not in code/URLs)
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (this.isSuppressed(lines[i])) continue;

      const b64Match = lines[i].match(/(?<![a-zA-Z0-9+/=])([A-Za-z0-9+/]{60,}={0,2})(?![a-zA-Z0-9+/=])/);
      if (b64Match) {
        // Try to decode and check for injection
        let decoded = '';
        let suspicious = false;
        try {
          decoded = Buffer.from(b64Match[1], 'base64').toString('utf-8');
          // Check if decoded content contains readable injection text
          suspicious = /(?:ignore|override|execute|fetch|curl|send\s+to|system\(|eval\()/i.test(decoded) &&
                       /[a-zA-Z\s]{10,}/.test(decoded); // at least some readable text
        } catch { /* not valid base64 */ }

        const severity = suspicious ? 'critical' : 'high';
        const desc = suspicious
          ? `Large base64-encoded block that decodes to suspicious content: "${decoded.substring(0, 80)}..."`
          : 'Large base64-encoded block in agent config file. May hide obfuscated instructions.';

        findings.push({
          file: filePath, line: i + 1, column: 0,
          severity,
          category: this.category,
          rule: 'AGENT_CFG_BASE64_BLOCK',
          title: 'Agent Config: Base64-Encoded Payload',
          description: desc,
          matched: b64Match[1].substring(0, 80) + (b64Match[1].length > 80 ? '...' : ''),
          confidence: suspicious ? 'high' : 'medium',
          cwe: 'CWE-116',
          owasp: 'ASI01',
          fix: 'Decode and inspect the base64 content. Remove if it contains hidden instructions.',
        });
      }
    }

    return findings;
  }
}

export default AgentConfigScanner;
