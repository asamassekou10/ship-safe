import styles from '../dashboard.module.css';
import skeletonStyles from '../skeleton.module.css';

export default function HistoryLoading() {
  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <div className={`${skeletonStyles.bone} ${skeletonStyles.h6} ${skeletonStyles.w32}`} />
          <div className={`${skeletonStyles.bone} ${skeletonStyles.h4} ${skeletonStyles.w20} ${skeletonStyles.mt1}`} />
        </div>
        <div className={`${skeletonStyles.bone} ${skeletonStyles.btn}`} />
      </div>

      {/* Filter bar skeleton */}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        {[...Array(4)].map((_, i) => (
          <div key={i} className={`${skeletonStyles.bone}`} style={{ width: 72, height: 32, borderRadius: 8 }} />
        ))}
      </div>

      <div className={styles.scanList}>
        {[...Array(10)].map((_, i) => (
          <div key={i} className={styles.scanRow} style={{ pointerEvents: 'none' }}>
            <div className={styles.scanLeft}>
              <div className={`${skeletonStyles.bone} ${skeletonStyles.icon}`} />
              <div>
                <div className={`${skeletonStyles.bone} ${skeletonStyles.h4} ${skeletonStyles.w48}`} />
                <div className={`${skeletonStyles.bone} ${skeletonStyles.h3} ${skeletonStyles.w24} ${skeletonStyles.mt1}`} />
              </div>
            </div>
            <div className={`${skeletonStyles.bone} ${skeletonStyles.chip}`} />
          </div>
        ))}
      </div>
    </div>
  );
}
