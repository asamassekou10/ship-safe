import Image from 'next/image';
import styles from './SocialProof.module.css';

const signals = [
  {
    column: 0,
    name: 'Saeed Anwar',
    handle: '@saen_dev',
    role: 'Builder',
    avatar: '/social-proof/saeed-anwar.jpg',
    quote:
      "scanning agent configs for vulnerabilities before deploy is exactly the gap in the current toolchain. most teams don't even audit their MCP tool permissions until something breaks in prod. security-left for agents is a real market.",
    href: 'https://x.com/saen_dev/status/2044848686878843170',
  },
  {
    column: 0,
    name: 'Teknium',
    handle: '@Teknium',
    role: 'Cofounder and Lead Engineer, Hermes Agent at Nous Research',
    avatar: '/social-proof/teknium.jpg',
    quote: 'Interesting!',
    href: 'https://x.com/Teknium/status/2044478500028248401',
  },
  {
    column: 1,
    name: 'Prismor',
    handle: '@prismor_dev',
    role: 'AI agent security platform',
    avatar: '/social-proof/prismor.jpg',
    quote: 'This is awesome Abbaas! finding vulns ahead of attackers is the real muscle for today',
    href: 'https://x.com/prismor_dev/status/2044443872227721334',
  },
  {
    column: 1,
    name: 'Nicolas Krassas',
    handle: '@Dinosn',
    role: 'Head of Threat & Vulnerability Management, Henkel',
    avatar: '/social-proof/nicolas-krassas.jpg',
    quote: 'How regex pattern recognition powers a 13-agent SAST scanner (and where it breaks down)',
    href: 'https://x.com/Dinosn/status/2033124936412205356',
  },
  {
    column: 2,
    name: 'validate.qa',
    handle: '@Validate_QA',
    role: 'AI-generated end-to-end testing',
    avatar: '/social-proof/validate-qa.jpg',
    quote:
      'shipping a dep scanner right after the claude leak? timely af. integrating that into ci gates would save so many headaches down the line',
    href: 'https://x.com/Validate_QA/status/2039463717872525571',
  },
];

const columns = [0, 1, 2] as const;

export default function SocialProof() {
  return (
    <section className={styles.section} aria-labelledby="social-proof-title">
      <div className={styles.inner}>
        <header className={styles.heading} data-animate>
          <span>Public feedback</span>
          <h2 id="social-proof-title">What builders are saying</h2>
        </header>

        <div className={styles.wall}>
          {columns.map((column) => (
            <div key={column} className={styles.column}>
              {signals
                .filter((signal) => signal.column === column)
                .map((signal, index) => (
                  <a
                    key={signal.href}
                    href={signal.href}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.signal}
                    data-animate
                    data-delay={String(90 + column * 90 + index * 80)}
                    aria-label={`Read ${signal.name}'s post on X`}
                  >
                    <div className={styles.signalTop}>
                      <Image
                        src={signal.avatar}
                        alt=""
                        width={48}
                        height={48}
                        className={styles.avatar}
                      />
                      <span className={styles.identity}>
                        <strong>{signal.name}</strong>
                        <small>{signal.handle}</small>
                      </span>
                      <span className={styles.xMark} aria-hidden="true">X</span>
                    </div>
                    <blockquote>{signal.quote}</blockquote>
                    <span className={styles.role}>{signal.role}</span>
                  </a>
                ))}
            </div>
          ))}
        </div>

        <p className={styles.disclaimer}>Public posts shown with attribution. Select a card to view the original post on X.</p>
      </div>
    </section>
  );
}
