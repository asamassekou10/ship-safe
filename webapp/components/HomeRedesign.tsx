import Image from 'next/image';
import Link from 'next/link';
import Hero from './Hero';
import LazyVideo from './LazyVideo';
import { CommandType, StatusSequence } from './HomepageMotion';
import SocialProof from './SocialProof';
import TrackedLink from './TrackedLink';
import styles from './HomeRedesign.module.css';

type HomeRedesignProps = {
  stars: number;
  downloads: number;
};

const faqs = [
  {
    q: 'Does Ship Safe work without an API key?',
    a: 'Yes. Core scans run locally without an API key. AI-backed analysis is optional and can be skipped with --no-ai.',
  },
  {
    q: 'Is my code sent to an LLM?',
    a: <>Only in provider-backed modes. Use <code>--no-ai</code> to keep scanning fully local. See the <Link href="/security">security and data-flow details</Link>.</>,
  },
  {
    q: 'Is the CLI free?',
    a: 'Yes. The CLI is MIT open-source and free for local scans. Paid plans add hosted history, private repositories, PR checks, and reports.',
  },
];

export default function HomeRedesign({ stars, downloads }: HomeRedesignProps) {
  return (
    <main className={styles.page}>
      <Hero stars={stars} downloads={downloads} />

      <section id="features" className={styles.productJourney}>
        <header className={styles.journeyIntro} data-animate>
          <span className={styles.sectionLabel}>// from scan to fix</span>
          <h2>One security workflow.<br />Four clear steps.</h2>
          <p>Start with a local scan. Add deeper context and automation only when you need it.</p>
        </header>

        <article id="workflow-scan" className={styles.storyRow} data-workflow-step>
          <div className={styles.storyCopy} data-animate="left">
            <span className={styles.storyNumber}>01</span>
            <h3>Run it where you work.</h3>
            <p>Scan any repository from the terminal without creating an account or uploading the entire codebase.</p>
            <div className={styles.storyCommand}>
              <span>$</span>
              <CommandType command="npx ship-safe scan" />
            </div>
            <StatusSequence items={['Scanning repository', 'Classifying findings', 'Report ready']} />
            <ul className={styles.storyPoints}>
              <li>One-command setup</li>
              <li>Local-first scanning</li>
              <li>CI-ready output</li>
            </ul>
            <Link href="#get-started" className={styles.textLink}>Run your first scan <span aria-hidden="true">→</span></Link>
          </div>
          <figure className={styles.storyMedia} data-animate="right">
            <Image
              src="/demo-cli.gif"
              alt="Ship Safe CLI scanning a repository"
              width={1028}
              height={725}
              sizes="(max-width: 900px) 100vw, 680px"
              unoptimized
            />
          </figure>
        </article>

        <article id="workflow-rank" className={`${styles.storyRow} ${styles.storyReverse}`} data-workflow-step>
          <div className={styles.storyCopy} data-animate="right">
            <span className={styles.storyNumber}>02</span>
            <h3>See what matters first.</h3>
            <p>Move past a flat list of warnings. Ship Safe groups findings by severity, confidence, and real exploitability.</p>
            <StatusSequence items={['Finding detected', 'Context verified', 'Exploitability ranked']} tone="risk" />
            <ul className={styles.storyPoints}>
              <li>Prioritized findings</li>
              <li>Security score</li>
              <li>Clear remediation context</li>
            </ul>
          </div>
          <figure className={`${styles.storyMedia} ${styles.riskMedia}`} data-animate="left">
            <Image
              src="/scan%20result.png"
              alt="Ship Safe scan results ranked by risk"
              width={2862}
              height={1386}
              sizes="(max-width: 900px) 100vw, 680px"
            />
          </figure>
        </article>

        <article id="workflow-guard" className={styles.storyRow} data-workflow-step>
          <div className={styles.storyCopy} data-animate="left">
            <span className={styles.storyNumber}>03</span>
            <h3>Stop risky changes before merge.</h3>
            <p>PR Guardian puts the finding, affected code, and fix guidance inside the review your team is already reading.</p>
            <StatusSequence items={['Change inspected', 'Risk blocked', 'Fix verified']} tone="success" />
            <ul className={styles.storyPoints}>
              <li>Pull-request checks</li>
              <li>Inline fix guidance</li>
              <li>Configurable release gates</li>
            </ul>
            <Link href="/docs" className={styles.textLink}>Explore PR Guardian <span aria-hidden="true">→</span></Link>
          </div>
          <figure className={`${styles.storyMedia} ${styles.guardMedia}`} data-animate="right">
            <Image
              src="/PR%20Guardian.png"
              alt="Ship Safe PR Guardian configuration"
              width={2700}
              height={1298}
              sizes="(max-width: 900px) 100vw, 680px"
            />
          </figure>
        </article>

        <article id="workflow-intelligence" className={`${styles.storyRow} ${styles.storyReverse}`} data-workflow-step>
          <div className={styles.storyCopy} data-animate="right">
            <span className={styles.storyNumber}>04</span>
            <h3>Turn new threats into checks.</h3>
            <p>Security Intelligence connects advisories and exploit context to the technologies inside your stack.</p>
            <StatusSequence items={['Threat signal received', 'Stack matched', 'Check generated']} />
            <ul className={styles.storyPoints}>
              <li>Threat-informed coverage</li>
              <li>Stack-aware relevance</li>
              <li>Actionable checks</li>
            </ul>
          </div>
          <figure className={styles.storyMedia} data-animate="left">
            <LazyVideo
              src="/demo-app-intelligence-web.mp4"
              poster="/app%20intelligence.png"
              ariaLabel="Ship Safe Security Intelligence demo"
            />
          </figure>
        </article>
      </section>

      <section id="hermes-workflows" className={styles.hermesSection} aria-labelledby="hermes-title">
        <div className={styles.hermesInner}>
          <div className={styles.hermesCopy} data-animate="left">
            <span className={styles.sectionLabel}>// hermes agent teams</span>
            <div className={styles.hermesStatus}>
              <i aria-hidden="true" />
              <span>Agent team active</span>
            </div>
            <h2 id="hermes-title">Give every security workflow its own team.</h2>
            <p>
              Compose specialized Hermes agents for deploy checks, investigation, monitoring,
              and incident response. You define the playbook; Ship Safe coordinates the work.
            </p>
            <ol className={styles.agentSequence} aria-label="Hermes agent workflow">
              <li data-animate data-delay="80"><span>01</span><strong>Delegate</strong><small>Route work to the right specialist.</small></li>
              <li data-animate data-delay="160"><span>02</span><strong>Investigate</strong><small>Share context without losing control.</small></li>
              <li data-animate data-delay="240"><span>03</span><strong>Respond</strong><small>Return one prioritized action plan.</small></li>
            </ol>
            <Link href="/hermes" className={styles.textLink}>Explore Hermes agent teams <span aria-hidden="true">→</span></Link>
          </div>

          <figure className={styles.hermesMedia} data-animate="right">
            <div className={styles.hermesChrome} aria-hidden="true">
              <span /><span /><span />
              <strong>Hermes orchestration</strong>
              <em>live</em>
            </div>
            <LazyVideo
              src="/demo-hermes-agents-web.mp4"
              poster="/Agent%20Team.png"
              ariaLabel="Ship Safe Hermes agent team demo"
            />
          </figure>
        </div>
      </section>

      <section className={styles.redTeamBand} aria-labelledby="red-team-title">
        <div className={styles.redTeamInner}>
          <div className={styles.redTeamCopy} data-animate="left">
            <span className={styles.sectionLabel}>// ai red team</span>
            <h2 id="red-team-title">Test your AI agents like an attacker.</h2>
            <p>Use Kimi K3-powered adversarial analysis to probe tool calls, long-context behavior, and agent boundaries.</p>
            <div className={styles.commandLine}>
              <span>$</span>
              <CommandType command="npx ship-safe red-team . --gpt-red --provider kimi --model kimi-k3 --k3-long-context" />
            </div>
            <StatusSequence items={['Attack surface mapped', 'Scenarios generated', 'Exploitability ranked']} tone="risk" />
            <Link href="/blog/kimi-k3-agent-tool-call-security-ship-safe" className={styles.textLink}>See how Kimi K3 works <span aria-hidden="true">→</span></Link>
          </div>
          <figure className={styles.redTeamMedia} data-animate="right">
            <Image
              src="/ship-safe-kimi-k3-linkedin-v3.gif"
              alt="Ship Safe and Kimi K3 AI red-team workflow"
              width={800}
              height={960}
              sizes="(max-width: 900px) 100vw, 500px"
              unoptimized
            />
          </figure>
        </div>
      </section>

      <section className={styles.quickStart} id="get-started">
        <div className={styles.quickStartInner} data-animate>
          <span className={styles.sectionLabel}>// get started</span>
          <h2>Your first report is one command away.</h2>
          <div className={styles.commandLine}>
            <span>$</span>
            <CommandType command="npx ship-safe scan" />
          </div>
          <p>No account required for local scans.</p>
          <div className={styles.heroActions}>
            <TrackedLink href="/docs" event="Homepage CTA Clicked" payload={{ item: 'open_setup_docs', section: 'quick_start' }} className={styles.primaryCta}>Open setup docs <span aria-hidden="true">→</span></TrackedLink>
            <TrackedLink href="/signup" event="Homepage CTA Clicked" payload={{ item: 'save_scan_history', section: 'quick_start' }} className={styles.secondaryCta}>Save scan history</TrackedLink>
          </div>
        </div>
      </section>

      <section id="pricing" className={styles.simplePricing}>
        <div className={styles.pricingHeading} data-animate>
          <span className={styles.sectionLabel}>// pricing</span>
          <h2>Start free. Upgrade when the workflow grows.</h2>
          <p>The scanner stays free. Pro adds the hosted tools that help teams keep moving.</p>
        </div>
        <div className={styles.planGrid}>
          <article className={styles.plan} data-animate data-delay="80">
            <div><span>Free CLI</span><strong>$0</strong></div>
            <p>Unlimited local scans and CI-ready security output.</p>
            <TrackedLink href="/docs" event="Homepage CTA Clicked" payload={{ item: 'run_locally', section: 'pricing_teaser' }} className={styles.secondaryCta}>Run locally</TrackedLink>
          </article>
          <article className={`${styles.plan} ${styles.planFeatured}`} data-animate data-delay="180">
            <div><span>Pro</span><strong>$9<small>/month</small></strong></div>
            <p>Hosted history, private repos, reports, and PR Guardian.</p>
            <TrackedLink href="/signup" event="Homepage CTA Clicked" payload={{ item: 'start_pro', section: 'pricing_teaser' }} className={styles.primaryCta}>Start Pro <span aria-hidden="true">→</span></TrackedLink>
          </article>
        </div>
        <TrackedLink href="/pricing" event="Homepage CTA Clicked" payload={{ item: 'compare_plans', section: 'pricing_teaser' }} className={styles.pricingLink}>Compare every plan and feature <span aria-hidden="true">→</span></TrackedLink>
      </section>

      <section className={styles.faqSection}>
        <div className={styles.faqInner}>
          <div className={styles.faqHead} data-animate>
            <span className={styles.sectionLabel}>// common questions</span>
            <h2>Know before you scan.</h2>
          </div>
          <div className={styles.faqList}>
            {faqs.map((item) => (
              <details key={item.q} className={styles.faqItem}>
                <summary>
                  <span>{item.q}</span>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6" /></svg>
                </summary>
                <div className={styles.faqAnswer}>{item.a}</div>
              </details>
            ))}
          </div>
        </div>
      </section>

      <SocialProof />

      <section className={styles.contributorSection} aria-labelledby="contributor-title">
        <div className={styles.contributorInner} data-animate>
          <div className={styles.contributorCopy}>
            <span className={styles.sectionLabel}>// open source builders</span>
            <h2 id="contributor-title">Help build security for AI-assisted development.</h2>
            <p>
              Ship Safe is MIT open source. Add agents, MCP rules, fixtures, docs,
              CI examples, and dashboard improvements with a focused contributor path.
            </p>
          </div>
          <div className={styles.contributorActions}>
            <TrackedLink
              href="https://github.com/asamassekou10/ship-safe/contribute"
              target="_blank"
              rel="noopener noreferrer"
              event="Contributor CTA Clicked"
              payload={{ item: 'good_first_issue', section: 'homepage' }}
              className={styles.primaryCta}
            >
              Pick a good first issue <span aria-hidden="true">→</span>
            </TrackedLink>
            <TrackedLink
              href="https://github.com/asamassekou10/ship-safe/blob/main/CONTRIBUTING.md"
              target="_blank"
              rel="noopener noreferrer"
              event="Contributor CTA Clicked"
              payload={{ item: 'contributor_guide', section: 'homepage' }}
              className={styles.secondaryCta}
            >
              Read contributor guide
            </TrackedLink>
          </div>
        </div>
      </section>

      <section className={styles.finalCta} data-animate>
        <div className={styles.finalInner}>
          <span className={styles.sectionLabel}>// ready when you are</span>
          <h2>Find the risk before users do.</h2>
          <p>Run locally for free, then add the cloud when your team needs history and automation.</p>
          <div className={styles.commandLine}>
            <span>$</span>
            <CommandType command="npx ship-safe scan" delay={240} />
          </div>
          <div className={styles.heroActions}>
            <TrackedLink href="/signup" event="Homepage CTA Clicked" payload={{ item: 'start_free_scan', section: 'final' }} className={styles.primaryCta}>Start free scan <span aria-hidden="true">→</span></TrackedLink>
            <TrackedLink href="/pricing" event="Homepage CTA Clicked" payload={{ item: 'view_pricing', section: 'final' }} className={styles.secondaryCta}>View pricing</TrackedLink>
            <TrackedLink href="/app/guide" event="Homepage CTA Clicked" payload={{ item: 'read_guide', section: 'final' }} className={styles.secondaryCta}>Read the guide</TrackedLink>
          </div>
          <nav className={styles.socialLinks} aria-label="Ship Safe social profiles">
            <TrackedLink href="https://www.linkedin.com/company/ship-safe" target="_blank" rel="noopener noreferrer" event="Social CTA Clicked" payload={{ item: 'linkedin', section: 'final' }}>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5.2 3.5A2.2 2.2 0 1 1 5.2 8a2.2 2.2 0 0 1 0-4.5ZM3.3 9.6h3.8V21H3.3V9.6Zm6.2 0h3.6v1.6h.1c.5-.9 1.7-2 3.6-2 3.9 0 4.6 2.5 4.6 5.9V21h-3.8v-5.2c0-1.3 0-2.9-1.8-2.9s-2.1 1.4-2.1 2.8V21H9.5V9.6Z" /></svg>
              LinkedIn
            </TrackedLink>
            <span aria-hidden="true" />
            <TrackedLink href="https://x.com/shipsafeAI" target="_blank" rel="noopener noreferrer" event="Social CTA Clicked" payload={{ item: 'x', section: 'final' }}>
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18.9 3H22l-6.8 7.8L23.2 21H17l-4.9-6.4L6.5 21H3.4l7.2-8.2L2.8 3h6.4l4.4 5.8L18.9 3Zm-1.1 16h1.7L8.3 4.9H6.5L17.8 19Z" /></svg>
              X
            </TrackedLink>
          </nav>
        </div>
      </section>
    </main>
  );
}
