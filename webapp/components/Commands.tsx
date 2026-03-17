'use client';
import styles from './Commands.module.css';

const commands = [
  {
    name: 'audit',
    cmd: 'npx ship-safe audit .',
    desc: 'Full security audit — secrets + 16 agents + deps + score + deep analysis + remediation plan + HTML report.',
    flags: ['--json', '--sarif', '--html [file]', '--pdf [file]', '--baseline', '--csv', '--md', '--deep', '--verify', '--budget <cents>', '--no-deps', '--no-ai', '--no-cache'],
    featured: true,
  },
  { name: 'red-team', cmd: 'npx ship-safe red-team .', desc: 'Run 16 security agents (80+ attack classes) against your codebase. Targeted deep scan.', flags: ['--agents <list>', '--json', '--html [file]', '--deep', '--local', '--budget <cents>'] },
  { name: 'scan', cmd: 'npx ship-safe scan .', desc: 'Quick secret scan — 50+ patterns with entropy scoring. No API key needed.', flags: ['--json', '--sarif', '--no-cache'] },
  { name: 'score', cmd: 'npx ship-safe score .', desc: '0–100 security health score with A–F grade. 8 weighted categories.', flags: ['--no-deps'] },
  { name: 'deps', cmd: 'npx ship-safe deps .', desc: 'Audit npm, yarn, pnpm, pip, or bundler dependencies for known CVEs.', flags: ['--fix'] },
  { name: 'agent', cmd: 'npx ship-safe agent .', desc: 'AI-powered audit — scan + classify with Claude + auto-fix secrets.', flags: ['--dry-run', '--model <model>'] },
  { name: 'watch', cmd: 'npx ship-safe watch .', desc: 'Continuous monitoring — watches files for changes and re-scans automatically.', flags: [] },
  { name: 'ci', cmd: 'npx ship-safe ci .', desc: 'CI/CD pipeline mode — compact output, threshold gating, exit codes. Optimized for automation.', flags: ['--threshold <score>', '--fail-on <severity>', '--sarif <file>', '--json', '--baseline'] },
  { name: 'baseline', cmd: 'npx ship-safe baseline .', desc: 'Accept current findings as baseline — only report regressions on future scans.', flags: ['--diff', '--clear'] },
  { name: 'remediate', cmd: 'npx ship-safe remediate .', desc: 'Auto-fix secrets and common vulnerabilities — TLS bypass, debug mode, XSS, Docker :latest.', flags: ['--all', '--dry-run', '--yes'] },
  { name: 'guard', cmd: 'npx ship-safe guard', desc: 'Install a git hook that blocks git push if secrets are found.', flags: ['--pre-commit'] },
];

function copyCmd(cmd: string, btn: HTMLElement) {
  navigator.clipboard.writeText(cmd).then(() => {
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.style.color = ''; }, 1500);
  });
}

export default function Commands() {
  return (
    <section className={styles.commands} id="commands">
      <div className="container">
        <span className="section-label">Reference</span>
        <h2>All commands</h2>
        <p className="section-sub">Everything you need. Nothing you don't.</p>

        <div className={styles.cmdGrid}>
          {commands.map((c, i) => (
            <div key={c.name} className={`${styles.cmdCard} card ${c.featured ? styles.featured : ''}`} data-animate data-delay={String(Math.min(i * 50, 300))}>
              <div className={styles.cmdName}>{c.name}</div>
              <div className={styles.cmdLine}>
                <span className={styles.cmdPrompt}>$</span>
                <span className={styles.cmdText}>{c.cmd}</span>
                <button
                  className="copy-btn"
                  title={`Copy: ${c.cmd}`}
                  aria-label={`Copy ${c.name} command`}
                  onClick={e => copyCmd(c.cmd, e.currentTarget as HTMLElement)}
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              </div>
              <p>{c.desc}</p>
              {c.flags.length > 0 && (
                <div className={styles.flags}>
                  {c.flags.map(f => <span key={f} className={styles.flag}>{f}</span>)}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
