import VideoEmbed from './VideoEmbed';
import styles from './DemoVideos.module.css';

export default function DemoVideos() {
  return (
    <section className={styles.section}>
      <div className="container">
        <div className={styles.header}>
          <h2 className={styles.title}>See Ship Safe in action</h2>
          <p className={styles.sub}>Watch a full vulnerability scan and see how agents deploy from anywhere.</p>
        </div>

        <div className={styles.grid}>
          <div className={styles.main}>
            <VideoEmbed
              videoId="pcL5a4O6Psg"
              title="Scan your apps for vulnerabilities for free - Ship Safe"
              format="landscape"
              caption="Full vulnerability scan — secrets, injection, CVEs, and OWASP Agentic AI findings in one command"
            />
          </div>

          <div className={styles.side}>
            <VideoEmbed
              videoId="8DuIlJomkQ0"
              title="Deploy agents anywhere from your phone - Ship Safe"
              format="short"
              caption="Deploy agents from anywhere, even your phone"
            />
          </div>
        </div>
      </div>
    </section>
  );
}
