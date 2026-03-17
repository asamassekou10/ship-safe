import styles from './Pillars.module.css';

export default function Pillars() {
  return (
    <section className={styles.pillars}>
      <div className="container">
        <span className="section-label">Coverage</span>
        <h2>Everything that can get you hacked.</h2>
        <p className="section-sub">16 agents. 5 OWASP standards. One tool.</p>

        <div className={styles.pillarGrid}>
          <div className={`${styles.pillar} card`} data-animate data-delay="0">
            <div className={styles.pillarIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h3>Secrets &amp; Injection</h3>
            <p>50+ secret patterns plus injection testing — SQL, NoSQL, XSS, command injection, path traversal, XXE, ReDoS, prototype pollution.</p>
            <ul>
              <li>API keys, database URLs, private keys, JWTs</li>
              <li>SQL injection, XSS, <code>{'ev' + 'al()'}</code>, <code>pickle.loads</code></li>
              <li>Entropy scoring to catch random-looking secrets</li>
              <li>Smart <code>.gitignore</code> — always scans <code>.env</code> files</li>
            </ul>
          </div>

          <div className={`${styles.pillar} card`} data-animate data-delay="100">
            <div className={styles.pillarIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
            </div>
            <h3>Auth, SSRF &amp; Supply Chain</h3>
            <p>Dedicated agents for auth bypass, SSRF, and supply chain attacks — the hardest vulns to catch manually.</p>
            <ul>
              <li>JWT alg:none, weak secrets, CSRF, OAuth misconfig</li>
              <li>SSRF via fetch/axios, cloud metadata endpoints</li>
              <li>Typosquatting detection (Levenshtein distance)</li>
              <li>Suspicious install scripts, wildcard versions</li>
            </ul>
          </div>

          <div className={`${styles.pillar} card`} data-animate data-delay="200">
            <div className={styles.pillarIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <line x1="16.5" y1="9.4" x2="7.5" y2="4.21" /><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
              </svg>
            </div>
            <h3>Config, CI/CD &amp; AI/LLM</h3>
            <p>Scans Docker, Terraform, Kubernetes, CI/CD pipelines, LLM integrations, MCP servers, agentic AI, and RAG pipelines.</p>
            <ul>
              <li>Dockerfile root user, <code>:latest</code> tags, open ports</li>
              <li>Pipeline poisoning, unpinned actions, secret logging</li>
              <li>OWASP LLM Top 10 + Agentic AI Top 10 — MCP, RAG, PII</li>
              <li>LLM-powered deep analysis for exploitability verification</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
