import styles from './dashboard.module.css';
import skeletonStyles from './skeleton.module.css';

export default function DashboardLoading() {
  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <div className={`${skeletonStyles.bone} ${skeletonStyles.h6} ${skeletonStyles.w32}`} />
          <div className={`${skeletonStyles.bone} ${skeletonStyles.h4} ${skeletonStyles.w20} ${skeletonStyles.mt1}`} />
        </div>
        <div className={`${skeletonStyles.bone} ${skeletonStyles.btn}`} />
      </div>

      {/* Stat cards */}
      <div className={styles.statsRow}>
        {[...Array(4)].map((_, i) => (
          <div key={i} className={styles.statCard}>
            <div className={`${skeletonStyles.bone} ${skeletonStyles.h8} ${skeletonStyles.w16}`} />
            <div className={`${skeletonStyles.bone} ${skeletonStyles.h3} ${skeletonStyles.w20} ${skeletonStyles.mt1}`} />
          </div>
        ))}
      </div>

      {/* Scan list */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <div className={`${skeletonStyles.bone} ${skeletonStyles.h5} ${skeletonStyles.w24}`} />
        </div>
        <div className={styles.scanList}>
          {[...Array(6)].map((_, i) => (
            <div key={i} className={styles.scanRow} style={{ pointerEvents: 'none' }}>
              <div className={styles.scanLeft}>
                <div className={`${skeletonStyles.bone} ${skeletonStyles.icon}`} />
                <div>
                  <div className={`${skeletonStyles.bone} ${skeletonStyles.h4} ${skeletonStyles.w40}`} />
                  <div className={`${skeletonStyles.bone} ${skeletonStyles.h3} ${skeletonStyles.w24} ${skeletonStyles.mt1}`} />
                </div>
              </div>
              <div className={`${skeletonStyles.bone} ${skeletonStyles.chip}`} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
