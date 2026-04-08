'use client';
import styles from './FAQ.module.css';

const faqs = [
  {
    q: 'Does it work without an API key?',
    a: 'Yes. audit, scan, red-team, ci, score, deps, diff, vibe-check, benchmark, and guard all work fully offline with no API key. AI classification and deep analysis are optional — pass --no-ai to skip it. If you want AI without a cloud key, run Gemma 4 locally via Ollama (ollama pull gemma4:e4b) and pass --provider gemma4. ship-safe also supports Anthropic, OpenAI, Google Gemini, and any Ollama model.',
  },
  {
    q: 'Is my code sent to an LLM?',
    a: 'Only if you use the agent command or omit --no-ai. When AI is used, only matched snippets (±2 lines) are sent. Secret values are masked — the LLM sees sk-proj-***Q3f5, not your actual key. The audit command with --no-ai is fully local.',
  },
  {
    q: 'How is this different from Semgrep or Snyk?',
    a: "Ship Safe is purpose-built for indie devs and small teams. One command covers secrets, code vulns, deps, config, CI/CD, LLM security, and mobile — no account, no config files, no dashboard to log into. It's free, open-source, and runs in under 5 seconds.",
  },
  {
    q: 'What about false positives?',
    a: 'v6.0 has context-aware confidence tuning that automatically downgrades findings in test files, documentation, comments, and example code — reducing false positives by up to 70%. Use --deep for LLM-powered exploitability verification, ship-safe baseline . to accept current findings and only see new regressions, or add # ship-safe-ignore to suppress individual lines.',
  },
  {
    q: 'Is the CLI always free?',
    a: 'Yes. The CLI is MIT open-source and will always be free. You can run unlimited scans locally on any repo. The paid plans are for the hosted web dashboard — cloud scans, scan history, team features, and PDF reports. AI features use your own API key (Anthropic, OpenAI, Gemini, or local Ollama).',
  },
  {
    q: 'Is it safe to run in CI?',
    a: "Yes. Use ship-safe ci . for pipeline-optimized output with threshold gating (--threshold 80), severity-based failure (--fail-on critical), and --github-pr to auto-post results as a PR comment. Use --sarif to upload findings to GitHub's Security tab. Exit code 0 = pass, 1 = fail.",
  },
  {
    q: 'Does Ship Safe work with Stripe Projects?',
    a: "Yes — they're complementary. Stripe Projects provisions your stack and syncs real credentials into your environment with stripe projects env --pull. Ship Safe is the security layer on top: it scans your codebase to ensure those credentials haven't leaked into source code, checks that every .env file is covered by .gitignore, and with ship-safe hooks install, intercepts any AI-assisted write that would embed a live key in your code before it hits disk. Run npx ship-safe audit . immediately after a credentials sync.",
  },
  {
    q: 'Does Ship Safe detect Docker CVE-2026-34040?',
    a: "Yes. Ship Safe's ConfigAuditor flags Docker Engine versions before 29.3.1, which are vulnerable to CVE-2026-34040 (CVSS 8.8) — an AuthZ bypass that lets attackers create privileged containers via oversized API requests. It also detects the conditions that amplify the impact: privileged mode, host network, writable root filesystems, SYS_ADMIN capability, and missing seccomp profiles. Run npx ship-safe audit . to check your Docker and container configurations.",
  },
  {
    q: 'Does Ship Safe scan Claude Managed Agents configs?',
    a: "Yes. Ship Safe's ManagedAgentScanner detects misconfigurations in Claude Managed Agents definitions — unrestricted networking, always_allow permission policies, bash without human confirmation, MCP servers over HTTP, hardcoded vault tokens, and unpinned environment packages. All findings map to OWASP Agentic AI Top 10 controls (ASI-03, ASI-04, ASI-05, ASI-07). Run npx ship-safe audit . on any project using the Managed Agents API or SDK.",
  },
  {
    q: "Can Ship Safe detect the attack patterns behind the Anthropic Mythos sandbox escape?",
    a: "Yes. The Mythos escape involved privilege escalation, unrestricted network egress, and autonomous consequential actions without human approval — all of which map directly to the OWASP Agentic AI Top 10. Ship Safe's AgenticSecurityAgent flags dangerouslySkipPermissions and danger-full-access in agent configs (ASI-03), the ConfigAuditor checks containers for unrestricted outbound networking (ASI-04), and the MCPSecurityAgent and MemoryPoisoningAgent cover unconstrained tool access and memory store vulnerabilities (ASI-05). Run npx ship-safe audit . to check your AI pipelines against all 10 OWASP Agentic controls.",
  },
];

export default function FAQ() {
  return (
    <section className={styles.faq}>
      <div className="container">
        <span className="section-label">FAQ</span>
        <h2>Common questions</h2>

        <div className={styles.faqList} data-animate>
          {faqs.map((item, i) => (
            <details key={i} className={styles.faqItem}>
              <summary className={styles.faqQuestion}>
                <span>{item.q}</span>
                <svg className={styles.faqArrow} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </summary>
              <div className={styles.faqAnswer}>{item.a}</div>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
