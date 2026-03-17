import styles from './BeforeAfter.module.css';

export default function BeforeAfter() {
  return (
    <section className={styles.beforeAfter}>
      <div className="container">
        <span className="section-label">Auto-remediation</span>
        <h2>From vulnerable to secure,<br />automatically.</h2>
        <p className="section-sub">
          <code>npx ship-safe remediate . --all</code> rewrites your code, writes the <code>.env</code> file, updates <code>.gitignore</code>, and fixes common vulnerabilities — all in one shot.
        </p>

        <div className={styles.diffGrid}>
          <div className={`${styles.diffPanel} card`} data-animate="left">
            <div className={styles.panelHeader}>
              <span className={styles.panelFilename}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                config.js
              </span>
              <span className={`${styles.panelBadge} ${styles.badgeBefore}`}>BEFORE</span>
            </div>
            <pre className={styles.codePre}>
              <span className={styles.cDim}>{'// config.js'}</span>{'\n'}
              <span className={styles.cDim}>{"import OpenAI from 'openai';"}</span>{'\n\n'}
              <span className={styles.cDim}>{'const openai = new OpenAI({'}</span>{'\n'}
              <span className={`${styles.cRed} ${styles.lineHl}`}>{'  apiKey: '}<span className={styles.cString}>{'"sk-proj-xK9mN2pL8qR3f5..."'}</span><span className={styles.cComment}>{'  ← exposed'}</span></span>{'\n'}
              <span className={styles.cDim}>{'});'}</span>
            </pre>
          </div>

          <div className={styles.diffArrow} aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2.5"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
          </div>

          <div className={`${styles.diffPanel} card`} data-animate="right">
            <div className={styles.panelHeader}>
              <span className={styles.panelFilename}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                config.js
              </span>
              <span className={`${styles.panelBadge} ${styles.badgeAfter}`}>AFTER</span>
            </div>
            <pre className={styles.codePre}>
              <span className={styles.cDim}>{'// config.js'}</span>{'\n'}
              <span className={styles.cDim}>{"import OpenAI from 'openai';"}</span>{'\n\n'}
              <span className={styles.cDim}>{'const openai = new OpenAI({'}</span>{'\n'}
              <span className={`${styles.cGreen} ${styles.lineHl}`}>{'  apiKey: process.env.'}<span className={styles.cVar}>{'OPENAI_API_KEY'}</span><span className={styles.cComment}>{'  ← ✓ safe'}</span></span>{'\n'}
              <span className={styles.cDim}>{'});'}</span>
            </pre>
            <div className={styles.envBlock}>
              <div className={styles.envHeader}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                .env <span className={styles.envBadge}>auto-generated · git-ignored</span>
              </div>
              <pre className={styles.envPre}><span className={styles.cVar}>OPENAI_API_KEY</span>=sk-proj-xK9mN2pL8qR3f5...</pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
