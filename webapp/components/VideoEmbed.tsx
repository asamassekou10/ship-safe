import styles from './VideoEmbed.module.css';

interface VideoEmbedProps {
  videoId: string;
  title: string;
  /** 'landscape' = 16:9 (default), 'short' = 9:16 vertical */
  format?: 'landscape' | 'short';
  caption?: string;
}

export default function VideoEmbed({ videoId, title, format = 'landscape', caption }: VideoEmbedProps) {
  return (
    <figure className={`${styles.figure} ${format === 'short' ? styles.short : styles.landscape}`}>
      <div className={styles.frameWrap}>
        <iframe
          src={`https://www.youtube.com/embed/${videoId}?rel=0&modestbranding=1`}
          title={title}
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
          allowFullScreen
          loading="lazy"
          className={styles.frame}
        />
      </div>
      {caption && <figcaption className={styles.caption}>{caption}</figcaption>}
    </figure>
  );
}
