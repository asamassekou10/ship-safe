import styles from './Agents.module.css';

const agents = [
  { name: 'InjectionTester', category: 'Code Vulns', desc: 'SQL/NoSQL injection, XSS, command injection, eval, path traversal, XXE, ReDoS, prototype pollution' },
  { name: 'AuthBypassAgent', category: 'Auth', desc: 'JWT alg:none, weak secrets, CSRF, OAuth misconfig, BOLA/IDOR, timing attacks' },
  { name: 'SSRFProber', category: 'SSRF', desc: 'User input in fetch/axios, cloud metadata endpoints, internal IPs, redirect following' },
  { name: 'SupplyChainAudit', category: 'Supply Chain', desc: 'Typosquatting, dependency confusion, git/URL deps, wildcard versions, suspicious install scripts' },
  { name: 'ConfigAuditor', category: 'Config', desc: 'Dockerfile, Terraform (RDS, CloudFront, Lambda, S3), Kubernetes, CORS, CSP, Firebase, Nginx misconfigs' },
  { name: 'SupabaseRLSAgent', category: 'Auth', desc: 'Row Level Security — service_role key in client code, CREATE TABLE without RLS, anon inserts, unprotected storage' },
  { name: 'LLMRedTeam', category: 'AI/LLM', desc: 'OWASP LLM Top 10 — prompt injection, excessive agency, system prompt leakage, RAG poisoning' },
  { name: 'MCPSecurityAgent', category: 'AI/LLM', desc: 'MCP server security — unvalidated tool inputs, missing auth, excessive permissions, tool poisoning' },
  { name: 'AgenticSecurityAgent', category: 'AI/LLM', desc: 'OWASP Agentic AI Top 10 — agent hijacking, privilege escalation, unsafe code execution, memory poisoning' },
  { name: 'RAGSecurityAgent', category: 'AI/LLM', desc: 'RAG pipeline security — unvalidated embeddings, context injection, document poisoning, vector DB access control' },
  { name: 'PIIComplianceAgent', category: 'Compliance', desc: 'PII detection — SSNs, credit cards, emails, phone numbers in source code, logs, and configs' },
  { name: 'MobileScanner', category: 'Mobile', desc: 'Insecure storage, WebView injection, HTTP endpoints, debug mode, permissions' },
  { name: 'GitHistoryScanner', category: 'Secrets', desc: 'Leaked secrets in git history — checks if still active in working tree' },
  { name: 'CICDScanner', category: 'CI/CD', desc: 'Pipeline poisoning, unpinned actions, secret logging, self-hosted runners' },
  { name: 'APIFuzzer', category: 'API', desc: 'Routes without auth, missing validation, mass assignment, GraphQL introspection, rate limiting, OpenAPI spec issues' },
  { name: 'ReconAgent', category: 'Recon', desc: 'Attack surface mapping — frameworks, auth patterns, databases, cloud providers' },
];

export default function Agents() {
  return (
    <section className={styles.agents} id="agents">
      <div className="container">
        <span className="section-label">16 Agents</span>
        <h2>A specialist for every attack surface.</h2>
        <p className="section-sub">Each agent is purpose-built to find what general scanners miss.</p>

        <div className={styles.agentGrid}>
          {agents.map((a, i) => (
            <div key={a.name} className={`${styles.agentCard} card`} data-animate data-delay={String(Math.min(i * 40, 300))}>
              <div className={styles.agentHeader}>
                <span className={styles.agentName}>{a.name}</span>
                <span className={styles.agentCat}>{a.category}</span>
              </div>
              <p>{a.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
