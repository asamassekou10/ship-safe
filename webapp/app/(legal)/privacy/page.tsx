import type { Metadata } from 'next';
import Link from 'next/link';
import styles from '../legal.module.css';

export const metadata: Metadata = {
  title: 'Privacy Policy',
  description: 'Ship Safe privacy policy covering account data, scan data, connected providers, and security workflows.',
  alternates: {
    canonical: 'https://www.shipsafecli.com/privacy',
  },
};

export default function PrivacyPage() {
  return (
    <main className={styles.legalPage}>
      <div className={styles.legalShell}>
        <Link href="/signup" className={styles.backLink}>Back to signup</Link>
        <article className={styles.legalCard}>
          <span className={styles.eyebrow}>Legal</span>
          <h1>Privacy Policy</h1>
          <p className={styles.updated}>Last updated July 17, 2026</p>
          <p className={styles.notice}>
            Ship Safe is built for security workflows. This policy explains what we collect, why we collect it,
            and how we handle account, repository, and scan information.
          </p>

          <section className={styles.section}>
            <h2>Information We Collect</h2>
            <ul>
              <li>Account details such as name, email address, avatar, and authentication provider identifiers.</li>
              <li>Repository and scan metadata needed to show dashboards, history, findings, scores, and reports.</li>
              <li>Billing and subscription information handled by our payment provider.</li>
              <li>Usage, device, log, and diagnostic data used to operate and secure the service.</li>
            </ul>
          </section>

          <section className={styles.section}>
            <h2>How We Use Information</h2>
            <p>
              We use information to provide scans and reports, authenticate users, manage subscriptions, prevent abuse,
              debug issues, improve product quality, and communicate about important service updates.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Connected Providers</h2>
            <p>
              If you connect GitHub, Google, or another provider, we receive the information needed for sign-in and the
              permissions you approve. You can revoke provider access through that provider or through Ship Safe settings when available.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Code and Scan Data</h2>
            <p>
              Local CLI scans can run without sending repository content to Ship Safe. Provider-backed AI modes send bounded
              context directly to the provider selected by the user, while hosted workflows process repository metadata,
              findings, and reports as needed to provide those services. The current technical boundaries are documented on
              the <Link href="/security">Security and Data Flow</Link> page.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Sharing</h2>
            <p>
              We do not sell personal information. We may share information with vendors that help operate the service,
              comply with legal obligations, protect users, or complete transactions you request.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Retention and Security</h2>
            <p>
              We keep information for as long as needed to provide the service, meet legal obligations, resolve disputes,
              and maintain security. We use technical and organizational safeguards, but no system is perfectly secure.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Your Choices</h2>
            <p>
              You may request access, correction, deletion, or export of personal information, subject to legal and security
              requirements. You can also manage provider permissions and billing settings through the connected services.
            </p>
          </section>

          <section className={styles.section}>
            <h2>Contact</h2>
            <p>
              Privacy questions can be sent to <span className={styles.contact}>hello@shipsafecli.com</span>.
            </p>
          </section>
        </article>
      </div>
    </main>
  );
}
