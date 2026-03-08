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
export { ScoringEngine, GRADES, CATEGORIES } from './scoring-engine.js';
export { SBOMGenerator } from './sbom-generator.js';
export { PolicyEngine } from './policy-engine.js';
export { HTMLReporter } from './html-reporter.js';

/**
 * Create a fully configured orchestrator with all 12 agents.
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

export function buildOrchestrator() {
  const orchestrator = new OrchestratorClass();
  orchestrator.registerAll([
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
  ]);
  return orchestrator;
}
