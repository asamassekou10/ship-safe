/**
 * Ship Safe CLI - Module Entry Point
 * ===================================
 *
 * This file exports the CLI commands and agents for programmatic use.
 * For normal CLI usage, run: npx ship-safe
 */

// ── Core Commands ─────────────────────────────────────────────────────────────
export { scanCommand } from './commands/scan.js';
export { checklistCommand } from './commands/checklist.js';
export { initCommand } from './commands/init.js';
export { agentCommand } from './commands/agent.js';
export { depsCommand, runDepsAudit } from './commands/deps.js';
export { scoreCommand } from './commands/score.js';

// ── v4.0 Commands ─────────────────────────────────────────────────────────────
export { auditCommand } from './commands/audit.js';
export { redTeamCommand } from './commands/red-team.js';
export { watchCommand } from './commands/watch.js';

// ── v4.2 Commands ─────────────────────────────────────────────────────────────
export { doctorCommand } from './commands/doctor.js';

// ── v4.3 Commands ─────────────────────────────────────────────────────────────
export { baselineCommand } from './commands/baseline.js';

// ── v6.0 Commands ─────────────────────────────────────────────────────────────
export { diffCommand } from './commands/diff.js';
export { vibeCheckCommand } from './commands/vibe-check.js';
export { benchmarkCommand } from './commands/benchmark.js';
export { openclawCommand } from './commands/openclaw.js';
export { scanSkillCommand } from './commands/scan-skill.js';
export { abomCommand } from './commands/abom.js';
export { updateIntelCommand } from './commands/update-intel.js';

// ── Patterns ──────────────────────────────────────────────────────────────────
export { SECRET_PATTERNS, SECURITY_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS, SKIP_FILENAMES } from './utils/patterns.js';

// ── Agent Framework ───────────────────────────────────────────────────────────
export { BaseAgent, createFinding } from './agents/base-agent.js';
export { Orchestrator } from './agents/orchestrator.js';
export { buildOrchestrator } from './agents/index.js';

// ── Individual Agents ─────────────────────────────────────────────────────────
export { ReconAgent } from './agents/recon-agent.js';
export { InjectionTester } from './agents/injection-tester.js';
export { AuthBypassAgent } from './agents/auth-bypass-agent.js';
export { SSRFProber } from './agents/ssrf-prober.js';
export { SupplyChainAudit } from './agents/supply-chain-agent.js';
export { ConfigAuditor } from './agents/config-auditor.js';
export { LLMRedTeam } from './agents/llm-redteam.js';
export { MobileScanner } from './agents/mobile-scanner.js';
export { GitHistoryScanner } from './agents/git-history-scanner.js';
export { CICDScanner } from './agents/cicd-scanner.js';
export { APIFuzzer } from './agents/api-fuzzer.js';
export { SupabaseRLSAgent } from './agents/supabase-rls-agent.js';
export { VibeCodingAgent } from './agents/vibe-coding-agent.js';
export { ExceptionHandlerAgent } from './agents/exception-handler-agent.js';
export { AgentConfigScanner } from './agents/agent-config-scanner.js';
export { ABOMGenerator } from './agents/abom-generator.js';

// ── Supporting Modules ────────────────────────────────────────────────────────
export { ScoringEngine, GRADES, CATEGORIES } from './agents/scoring-engine.js';
export { SBOMGenerator } from './agents/sbom-generator.js';
export { PolicyEngine } from './agents/policy-engine.js';
export { HTMLReporter } from './agents/html-reporter.js';

// ── Caching ──────────────────────────────────────────────────────────────────
export { CacheManager } from './utils/cache-manager.js';

// ── LLM Providers ─────────────────────────────────────────────────────────────
export { createProvider, autoDetectProvider } from './providers/llm-provider.js';

// ── v8.0.0 — Ship Safe × Hermes Agent ────────────────────────────────────────
export { HermesSecurityAgent } from './agents/hermes-security-agent.js';
export { AgentAttestationAgent } from './agents/agent-attestation-agent.js';
export { HERMES_TOOLS, registerWithHermes, verifyIntegrity } from './utils/hermes-tool-registry.js';
