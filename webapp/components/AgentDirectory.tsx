import styles from './AgentDirectory.module.css';

const AGENTS = [
  {
    category: 'Secrets & Credentials',
    color: 'var(--sev-critical)',
    items: [
      {
        name: 'Config Auditor',
        owasp: 'A02',
        checks: ['API keys & tokens', 'Hardcoded passwords', '.env misconfig', 'openclaude profile leaks'],
      },
      {
        name: 'Git History Scanner',
        owasp: 'A02',
        checks: ['Secrets in past commits', 'Deleted credentials', 'Force-push bypass', 'CI secret exposure'],
      },
    ],
  },
  {
    category: 'Code Vulnerabilities',
    color: 'var(--sev-high)',
    items: [
      {
        name: 'Injection Tester',
        owasp: 'A03',
        checks: ['SQL injection', 'NoSQL injection', 'Command injection', 'LDAP / XPath injection'],
      },
      {
        name: 'Auth Bypass Agent',
        owasp: 'A07',
        checks: ['JWT misconfiguration', 'Broken access control', 'IDOR patterns', 'Session fixation'],
      },
      {
        name: 'SSRF Prober',
        owasp: 'A10',
        checks: ['Server-side request forgery', 'Internal endpoint access', 'Cloud metadata endpoints', 'DNS rebinding'],
      },
      {
        name: 'Exception Handler Agent',
        owasp: 'A09',
        checks: ['Stack trace leakage', 'Verbose error messages', 'Sensitive data in logs', 'Unhandled rejections'],
      },
    ],
  },
  {
    category: 'AI / LLM Security',
    color: 'var(--cyan)',
    items: [
      {
        name: 'LLM Red Team',
        owasp: 'LLM01',
        checks: ['Prompt injection', 'Jailbreak patterns', 'System prompt leakage', 'Indirect injection'],
      },
      {
        name: 'RAG Security Agent',
        owasp: 'LLM06',
        checks: ['Vector store injection', 'Poisoned retrieval', 'Embedding extraction', 'Context stuffing'],
      },
      {
        name: 'MCP Security Agent',
        owasp: 'LLM08',
        checks: ['Malicious tool definitions', 'Credential harvesting', 'ToxicSkills payloads', 'Unencrypted transport'],
      },
      {
        name: 'Agentic Security Agent',
        owasp: 'LLM09',
        checks: ['Unsafe tool use', 'Permission escalation', 'Silent exfiltration', 'Output suppression'],
      },
      {
        name: 'Agent Config Scanner',
        owasp: 'LLM08',
        checks: ['openclaude / claw-code risks', 'Hook-based RCE', '.claude.json exposure', 'Proactive mode detection'],
      },
      {
        name: 'Memory Poisoning Agent',
        owasp: 'ASI05',
        checks: ['Instruction injection in agent memory', 'Hidden Unicode payloads', 'Persona hijacking', 'Persistent trigger detection'],
      },
    ],
  },
  {
    category: 'Supply Chain & Compliance',
    color: 'var(--sev-medium)',
    items: [
      {
        name: 'Supply Chain Agent',
        owasp: 'A06',
        checks: ['Dependency CVEs', 'Typosquatting packages', 'Malicious npm scripts', 'Lockfile tampering'],
      },
      {
        name: 'Agentic Supply Chain Agent',
        owasp: 'ASI09',
        checks: ['Over-privileged AI CI actions', 'OAuth scope abuse in AI integrations', 'Unsigned AI webhook receivers', 'MCP/Hermes cross-boundary token forwarding'],
      },
      {
        name: 'Legal Risk Agent',
        owasp: 'A06',
        checks: ['GPL copyleft contamination', 'DMCA-flagged packages', 'License incompatibilities', 'AI-generated code risk'],
      },
      {
        name: 'PII Compliance Agent',
        owasp: 'A02',
        checks: ['GDPR data handling', 'CCPA violations', 'PII in logs/storage', 'Consent gaps'],
      },
      {
        name: 'Vibe Coding Agent',
        owasp: 'A05',
        checks: ['AI-generated insecure patterns', 'Placeholder credentials', 'Debug code in prod', 'Over-permissive defaults'],
      },
    ],
  },
  {
    category: 'Infrastructure & Pipeline',
    color: 'var(--sev-low)',
    items: [
      {
        name: 'CI/CD Scanner',
        owasp: 'A05',
        checks: ['Workflow injection', 'Secret exposure in logs', 'Unsafe pipeline steps', 'Pinned action bypass'],
      },
      {
        name: 'Mobile Scanner',
        owasp: 'M01',
        checks: ['Insecure data storage', 'Cleartext traffic', 'Weak crypto', 'Exported components'],
      },
      {
        name: 'Supabase RLS Agent',
        owasp: 'A01',
        checks: ['Missing RLS policies', 'Overly permissive rules', 'Auth.uid() bypasses', 'Public table exposure'],
      },
      {
        name: 'Deep Analyzer',
        owasp: 'A03',
        checks: ['Cross-function taint flows', 'Sanitization gaps', 'Reachability analysis', 'Exploitability scoring'],
      },
    ],
  },
];

export default function AgentDirectory() {
  return (
    <section className={styles.section} id="agents">
      <div className="container">
        <span className="section-label">Under the hood</span>
        <h2>24 agents. Every attack surface covered.</h2>
        <p className="section-sub">
          Not wrappers — each agent has its own detection logic, rule set, and OWASP mapping.
          Here&rsquo;s exactly what runs when you type <code>ship-safe audit .</code>
        </p>

        <div className={styles.grid}>
          {AGENTS.map((group) => (
            <div key={group.category} className={styles.group}>
              <div className={styles.groupHeader}>
                <span className={styles.groupDot} style={{ background: group.color }} />
                <span className={styles.groupName}>{group.category}</span>
              </div>
              <div className={styles.cards}>
                {group.items.map((agent) => (
                  <div key={agent.name} className={styles.card}>
                    <div className={styles.cardTop}>
                      <span className={styles.agentName}>{agent.name}</span>
                      <span className={styles.owaspBadge} style={{ borderColor: group.color, color: group.color }}>
                        {agent.owasp}
                      </span>
                    </div>
                    <ul className={styles.checks}>
                      {agent.checks.map((c) => (
                        <li key={c} className={styles.check}>
                          <span className={styles.checkDot} style={{ background: group.color }} />
                          {c}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <p className={styles.footer}>
          All agents run locally. AI-assisted taint analysis is opt-in via <code>--provider</code>.
          Suppress false positives inline with <code>// ship-safe-ignore</code>.
        </p>
      </div>
    </section>
  );
}
