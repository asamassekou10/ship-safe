/**
 * Agent Registry
 * ===============
 *
 * Central export of all agents and supporting classes.
 */

export { BaseAgent, createFinding } from './base-agent.js';
export { Orchestrator } from './orchestrator.js';
export { ReconAgent } from './recon-agent.js';
export { InjectionTester } from './injection-tester.js';
export { AuthBypassAgent } from './auth-bypass-agent.js';
export { SSRFProber } from './ssrf-prober.js';
export { SupplyChainAudit } from './supply-chain-agent.js';
export { ConfigAuditor } from './config-auditor.js';
export { LLMRedTeam } from './llm-redteam.js';
export { MobileScanner } from './mobile-scanner.js';
export { GitHistoryScanner } from './git-history-scanner.js';
export { CICDScanner } from './cicd-scanner.js';
export { APIFuzzer } from './api-fuzzer.js';
export { SupabaseRLSAgent } from './supabase-rls-agent.js';
export { MCPSecurityAgent } from './mcp-security-agent.js';
export { AgenticSecurityAgent } from './agentic-security-agent.js';
export { RAGSecurityAgent } from './rag-security-agent.js';
export { PIIComplianceAgent } from './pii-compliance-agent.js';
export { VibeCodingAgent } from './vibe-coding-agent.js';
export { ExceptionHandlerAgent } from './exception-handler-agent.js';
export { AgentConfigScanner } from './agent-config-scanner.js';
export { MemoryPoisoningAgent } from './memory-poisoning-agent.js';
export { LegalRiskAgent, LEGALLY_RISKY_PACKAGES } from './legal-risk-agent.js';
export { ManagedAgentScanner } from './managed-agent-scanner.js';
export { HermesSecurityAgent } from './hermes-security-agent.js';
export { AgentAttestationAgent } from './agent-attestation-agent.js';
export { ABOMGenerator } from './abom-generator.js';
export { VerifierAgent } from './verifier-agent.js';
export { DeepAnalyzer } from './deep-analyzer.js';
export { ScoringEngine, GRADES, CATEGORIES } from './scoring-engine.js';
export { SBOMGenerator } from './sbom-generator.js';
export { PolicyEngine } from './policy-engine.js';
export { HTMLReporter } from './html-reporter.js';

/**
 * Create a fully configured orchestrator with all 22 scanning agents.
 * (VerifierAgent and DeepAnalyzer run as post-processors, not in the agent pool.)
 *
 * Plugin system: if rootPath is provided, custom agents from
 * .ship-safe/agents/*.js are loaded and registered automatically.
 * Use buildOrchestratorAsync(rootPath) to get plugin support.
 */
import { Orchestrator as OrchestratorClass } from './orchestrator.js';
import { InjectionTester as InjectionTesterClass } from './injection-tester.js';
import { AuthBypassAgent as AuthBypassAgentClass } from './auth-bypass-agent.js';
import { SSRFProber as SSRFProberClass } from './ssrf-prober.js';
import { SupplyChainAudit as SupplyChainAuditClass } from './supply-chain-agent.js';
import { ConfigAuditor as ConfigAuditorClass } from './config-auditor.js';
import { LLMRedTeam as LLMRedTeamClass } from './llm-redteam.js';
import { MobileScanner as MobileScannerClass } from './mobile-scanner.js';
import { GitHistoryScanner as GitHistoryScannerClass } from './git-history-scanner.js';
import { CICDScanner as CICDScannerClass } from './cicd-scanner.js';
import { APIFuzzer as APIFuzzerClass } from './api-fuzzer.js';
import { SupabaseRLSAgent as SupabaseRLSAgentClass } from './supabase-rls-agent.js';
import { MCPSecurityAgent as MCPSecurityAgentClass } from './mcp-security-agent.js';
import { AgenticSecurityAgent as AgenticSecurityAgentClass } from './agentic-security-agent.js';
import { RAGSecurityAgent as RAGSecurityAgentClass } from './rag-security-agent.js';
import { PIIComplianceAgent as PIIComplianceAgentClass } from './pii-compliance-agent.js';
import { VibeCodingAgent as VibeCodingAgentClass } from './vibe-coding-agent.js';
import { ExceptionHandlerAgent as ExceptionHandlerAgentClass } from './exception-handler-agent.js';
import { AgentConfigScanner as AgentConfigScannerClass } from './agent-config-scanner.js';
import { MemoryPoisoningAgent as MemoryPoisoningAgentClass } from './memory-poisoning-agent.js';
import { ManagedAgentScanner as ManagedAgentScannerClass } from './managed-agent-scanner.js';
import { HermesSecurityAgent as HermesSecurityAgentClass } from './hermes-security-agent.js';
import { AgentAttestationAgent as AgentAttestationAgentClass } from './agent-attestation-agent.js';
import { loadPlugins } from '../utils/plugin-loader.js';

const BUILT_IN_AGENTS = () => [
  new InjectionTesterClass(),
  new AuthBypassAgentClass(),
  new SSRFProberClass(),
  new SupplyChainAuditClass(),
  new ConfigAuditorClass(),
  new LLMRedTeamClass(),
  new MobileScannerClass(),
  new GitHistoryScannerClass(),
  new CICDScannerClass(),
  new APIFuzzerClass(),
  new SupabaseRLSAgentClass(),
  new MCPSecurityAgentClass(),
  new AgenticSecurityAgentClass(),
  new RAGSecurityAgentClass(),
  new PIIComplianceAgentClass(),
  new VibeCodingAgentClass(),
  new ExceptionHandlerAgentClass(),
  new AgentConfigScannerClass(),
  new MemoryPoisoningAgentClass(),
  new ManagedAgentScannerClass(),
  new HermesSecurityAgentClass(),
  new AgentAttestationAgentClass(),
];

/** Synchronous build — no plugin support. Used by legacy callers. */
export function buildOrchestrator() {
  const orchestrator = new OrchestratorClass();
  orchestrator.registerAll(BUILT_IN_AGENTS());
  return orchestrator;
}

/**
 * Async build — loads built-in agents + any plugins from .ship-safe/agents/.
 * Preferred over buildOrchestrator() when rootPath is available.
 *
 * @param {string} rootPath — project root (for plugin discovery)
 * @param {object} options  — { verbose, quiet }
 */
export async function buildOrchestratorAsync(rootPath, options = {}) {
  const orchestrator = new OrchestratorClass();
  orchestrator.registerAll(BUILT_IN_AGENTS());

  if (rootPath) {
    const plugins = await loadPlugins(rootPath, options);
    if (plugins.length > 0) {
      orchestrator.registerAll(plugins);
      if (!options.quiet) {
        console.log(`  Registered ${plugins.length} custom plugin(s)`);
      }
    }
  }

  return orchestrator;
}
