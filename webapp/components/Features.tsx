import styles from './Features.module.css';

export default function Features() {
  return (
    <section className={styles.features} id="features">
      <div className="container">
        <span className="section-label">Features</span>
        <h2>Everything you need to ship safely.</h2>
        <p className="section-sub">
          One command covers secrets, code vulnerabilities, dependencies, CI/CD, and more.
        </p>

        <div className={styles.grid}>
          {/* Card 1: Scan Everything */}
          <div className={`${styles.card} card`} data-animate>
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>Scan everything</h3>
            <p className={styles.cardDesc}>
              18 specialized agents scan for secrets, injection, auth bypass, SSRF, supply chain attacks, LLM/MCP security, vibe coding patterns, and more. 80+ attack classes across 5 OWASP standards.
            </p>
            <div className={styles.miniTerminal}>
              <div className={styles.miniHeader}>
                <span className={styles.miniDot} style={{ background: 'var(--red)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--yellow)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--green)' }} />
                <span className={styles.miniTitle}>ship-safe audit .</span>
              </div>
              <div className={styles.miniBody}>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>Secrets: 0 found</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>18 agents: 2 findings</span>
                  <span className={styles.miniTag} data-level="medium">MEDIUM</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>Dependencies: 0 CVEs</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span className={styles.miniDim}>Score: 94/100 — A</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 2: Auto-Remediate */}
          <div className={`${styles.card} card`} data-animate data-delay="80">
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>Auto-remediate</h3>
            <p className={styles.cardDesc}>
              One command fixes findings automatically — moves secrets to environment variables, replaces vulnerable patterns, and generates a clean diff you can review.
            </p>
            <div className={styles.diffBlock}>
              <div className={styles.diffFile}>
                <span className={styles.diffBadge} data-type="before">BEFORE</span>
                <span className={styles.diffName}>config.js</span>
              </div>
              <pre className={styles.diffCode}>
                <code>
                  <span className={styles.diffDel}>- const key = &quot;sk-proj-abc123def&quot;;</span>
                </code>
              </pre>
              <div className={styles.diffFile}>
                <span className={styles.diffBadge} data-type="after">AFTER</span>
                <span className={styles.diffName}>config.js</span>
              </div>
              <pre className={styles.diffCode}>
                <code>
                  <span className={styles.diffAdd}>+ const key = process.env.OPENAI_API_KEY;</span> {/* ship-safe-ignore — example code displayed in UI, not a real API key reference */}
                </code>
              </pre>
            </div>
          </div>

          {/* Card 3: CI/CD Ready */}
          <div className={`${styles.card} card`} data-animate data-delay="160">
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <line x1="6" y1="3" x2="6" y2="15" />
                <circle cx="18" cy="6" r="3" />
                <circle cx="6" cy="18" r="3" />
                <path d="M18 9a9 9 0 0 1-9 9" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>CI/CD ready</h3>
            <p className={styles.cardDesc}>
              Drop a one-liner into GitHub Actions. Threshold gating, SARIF output, PR comments, and exit codes for pipeline control.
            </p>
            <div className={styles.yamlBlock}>
              <div className={styles.yamlHeader}>
                <span className={styles.yamlFile}>.github/workflows/security.yml</span>
              </div>
              <pre className={styles.yamlCode}>
                <code>{`- name: Ship Safe Audit
  run: npx ship-safe ci .
    --threshold 75
    --sarif results.sarif
    --github-pr`}</code>
              </pre>
            </div>
          </div>

          {/* Card 4: Diff Scanning */}
          <div className={`${styles.card} card`} data-animate data-delay="240">
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 20h9" />
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>Diff scanning</h3>
            <p className={styles.cardDesc}>
              Scan only changed files — perfect for pre-commit hooks and PR reviews. Runs in seconds, not minutes.
            </p>
            <div className={styles.miniTerminal}>
              <div className={styles.miniHeader}>
                <span className={styles.miniDot} style={{ background: 'var(--red)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--yellow)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--green)' }} />
                <span className={styles.miniTitle}>ship-safe diff --staged</span>
              </div>
              <div className={styles.miniBody}>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>4 changed file(s) to scan</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>18 agents: 0 findings</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span className={styles.miniDim}>Diff Score: 98/100 A</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 5: Claude Code Hooks */}
          <div className={`${styles.card} card`} data-animate data-delay="320">
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>Claude Code hooks</h3>
            <p className={styles.cardDesc}>
              Block secrets before they ever touch disk. One command installs real-time hooks into Claude Code — critical secrets are caught at write time, not after.
            </p>
            <div className={styles.miniTerminal}>
              <div className={styles.miniHeader}>
                <span className={styles.miniDot} style={{ background: 'var(--red)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--yellow)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--green)' }} />
                <span className={styles.miniTitle}>ship-safe hooks install</span>
              </div>
              <div className={styles.miniBody}>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>PreToolUse installed</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniOk}>✔</span>
                  <span>PostToolUse installed</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniDim}>Secrets blocked before disk write</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 6: Benchmark */}
          <div className={`${styles.card} card`} data-animate data-delay="400">
            <div className={styles.cardIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="20" x2="18" y2="10" />
                <line x1="12" y1="20" x2="12" y2="4" />
                <line x1="6" y1="20" x2="6" y2="14" />
              </svg>
            </div>
            <h3 className={styles.cardTitle}>Industry benchmark</h3>
            <p className={styles.cardDesc}>
              Compare your security score against industry averages from OWASP, Synopsys, and Snyk. See where you rank and what to improve.
            </p>
            <div className={styles.miniTerminal}>
              <div className={styles.miniHeader}>
                <span className={styles.miniDot} style={{ background: 'var(--red)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--yellow)' }} />
                <span className={styles.miniDot} style={{ background: 'var(--green)' }} />
                <span className={styles.miniTitle}>ship-safe benchmark .</span>
              </div>
              <div className={styles.miniBody}>
                <div className={styles.miniLine}>
                  <span>You: 78/100</span>
                  <span className={styles.miniTag} data-level="low">+26 vs avg</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniDim}>Industry median: 52/100</span>
                </div>
                <div className={styles.miniLine}>
                  <span className={styles.miniDim}>Top 25%: 78/100</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
