import styles from './HowItWorks.module.css';

const steps = [
  {
    num: 1,
    title: 'Scan for secrets',
    body: 'Scans every file for 50+ secret patterns with entropy scoring. Respects .gitignore for build output but always scans .env, .pem, and other security-sensitive files.',
    connector: true,
  },
  {
    num: 2,
    title: 'Run 16 security agents',
    body: 'Deploys specialized agents for injection, auth bypass, SSRF, supply chain, config, Supabase RLS, LLM security, mobile, git history, CI/CD, API fuzzing, and recon. Context-aware confidence tuning reduces false positives.',
    connector: true,
  },
  {
    num: 3,
    title: 'Audit dependencies',
    body: 'Runs your package manager\'s own audit tool — npm, yarn, pnpm, pip, or bundler. Finds known CVEs in your dependency tree and flags vulnerable versions.',
    connector: true,
  },
  {
    num: 4,
    title: 'Score & remediation plan',
    body: 'Computes a 0–100 security score across 8 weighted categories. Generates a prioritized remediation plan — CRITICAL first, then HIGH, then MEDIUM — so you know exactly what to fix first.',
    connector: true,
  },
  {
    num: 5,
    title: 'HTML report',
    body: 'Outputs a standalone dark-themed HTML report with every finding, file location, severity, CWE/OWASP mapping, and suggested fix. Share it with your team or attach it to a PR.',
    connector: false,
  },
];

export default function HowItWorks() {
  return (
    <section className={styles.howItWorks} id="how-it-works">
      <div className="container">
        <span className="section-label">How it works</span>
        <h2>How <span className={styles.monoH}>audit</span> works</h2>
        <p className="section-sub">One command. Four phases. Prioritized fix list.</p>

        <div className={styles.steps}>
          {steps.map((s, i) => (
            <div key={s.num} className={styles.step} data-animate data-delay={String(i * 80)}>
              <div className={styles.stepLeft}>
                <div className={styles.stepNum}>{s.num}</div>
                {s.connector && <div className={styles.stepConnector} />}
              </div>
              <div className={styles.stepBody}>
                <h4>{s.title}</h4>
                <p>{s.body}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
