'use client';
import styles from './FAQ.module.css';

const faqs = [
  {
    q: 'Does it work without an API key?',
    a: 'Yes. audit, scan, red-team, ci, score, deps, and guard all work fully offline with no API key. AI classification and deep analysis are optional — pass --no-ai to skip it. If you want AI, ship-safe supports Anthropic, OpenAI, Google Gemini, and local Ollama models.',
  },
  {
    q: 'Is my code sent to an LLM?',
    a: 'Only if you use the agent command or omit --no-ai. When AI is used, only matched snippets (±2 lines) are sent. Secret values are masked — the LLM sees sk-proj-***Q3f5, not your actual key. The audit command with --no-ai is fully local.',
  },
  {
    q: 'Does it respect my .gitignore?',
    a: 'Yes, with smart filtering. Build output (node_modules, dist, build) is skipped. But security-sensitive files like .env, .pem, .key, and credentials.json are always scanned even if gitignored — because those files are gitignored because they contain secrets.',
  },
  {
    q: 'How fast is it on repeated runs?',
    a: 'Ship Safe caches file hashes and findings in .ship-safe/context.json. On subsequent runs, only changed files are re-scanned — unchanged files reuse cached results. This makes repeated scans ~40% faster. Use --no-cache to force a full rescan.',
  },
  {
    q: 'Can I use it inside Claude Code?',
    a: 'Yes. Install the plugin with claude plugin add github:asamassekou10/ship-safe and use /ship-safe for a full audit, /ship-safe-scan for secrets, /ship-safe-score for your health score, /ship-safe-fix for auto-remediation, or /ship-safe-baseline to manage your baseline. Claude interprets the results and can fix issues directly.',
  },
  {
    q: 'How is this different from Semgrep or Snyk?',
    a: "Ship Safe is purpose-built for indie devs and small teams. One command covers secrets, code vulns, deps, config, CI/CD, LLM security, and mobile — no account, no config files, no dashboard to log into. It's free, open-source, and runs in under 5 seconds.",
  },
  {
    q: 'Is it safe to run in CI?',
    a: "Yes. Use ship-safe ci . for pipeline-optimized output with threshold gating (--threshold 80) and severity-based failure (--fail-on critical). Use --sarif to upload findings to GitHub's Security tab. Exit code 0 = pass, 1 = fail.",
  },
  {
    q: 'What about false positives?',
    a: 'v5.0 has context-aware confidence tuning that automatically downgrades findings in test files, documentation, comments, and example code — reducing false positives by up to 70%. Use --deep for LLM-powered exploitability verification, ship-safe baseline . to accept current findings and only see new regressions, or add # ship-safe-ignore to suppress individual lines.',
  },
];

export default function FAQ() {
  return (
    <section className={styles.faq}>
      <div className="container">
        <span className="section-label">FAQ</span>
        <h2>Common questions</h2>

        <div className={`${styles.faqList}`} data-animate>
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
