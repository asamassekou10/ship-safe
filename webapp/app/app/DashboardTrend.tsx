'use client';

import { useMemo, useState } from 'react';
import { track } from '@vercel/analytics/react';
import {
  Area,
  Bar,
  CartesianGrid,
  ComposedChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import styles from './dashboard.module.css';

type TrendScan = {
  createdAt: string;
  status: string;
  score: number | null;
  findings: number;
};

type Range = 30 | 90 | 'all';

export default function DashboardTrend({ scans }: { scans: TrendScan[] }) {
  const defaultRange = useMemo<Range>(() => {
    const now = Date.now();
    if (scans.some(scan => new Date(scan.createdAt).getTime() >= now - 30 * 86400000)) return 30;
    if (scans.some(scan => new Date(scan.createdAt).getTime() >= now - 90 * 86400000)) return 90;
    return 'all';
  }, [scans]);
  const [range, setRange] = useState<Range>(defaultRange);

  const data = useMemo(() => {
    const cutoff = range === 'all' ? null : Date.now() - range * 24 * 60 * 60 * 1000;
    const days = new Map<string, { date: string; label: string; scores: number[]; findings: number; failed: number }>();

    for (const scan of scans) {
      const timestamp = new Date(scan.createdAt).getTime();
      if (cutoff !== null && timestamp < cutoff) continue;
      const date = new Date(scan.createdAt).toISOString().slice(0, 10);
      const entry = days.get(date) ?? {
        date,
        label: new Date(`${date}T00:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }),
        scores: [],
        findings: 0,
        failed: 0,
      };
      if (scan.status === 'done' && scan.score !== null) entry.scores.push(scan.score);
      if (scan.status === 'done') entry.findings += scan.findings;
      if (scan.status === 'failed') entry.failed += 1;
      days.set(date, entry);
    }

    return [...days.values()]
      .sort((a, b) => a.date.localeCompare(b.date))
      .map(day => ({
        date: day.label,
        score: day.scores.length ? Math.round(day.scores.reduce((sum, score) => sum + score, 0) / day.scores.length) : null,
        findings: day.findings,
        failed: day.failed,
      }));
  }, [range, scans]);

  function selectRange(value: Range) {
    setRange(value);
    track('Dashboard Trend Range Changed', { days: String(value) });
  }

  return (
    <section className={styles.trendPanel} aria-labelledby="security-trend-title">
      <div className={styles.panelHeader}>
        <div>
          <span className={styles.panelEyebrow}>Security signal</span>
          <h2 id="security-trend-title">Security trend</h2>
        </div>
        <div className={styles.rangeControl} aria-label="Trend range">
          {([30, 90, 'all'] as Range[]).map(value => (
            <button
              key={value}
              type="button"
              className={range === value ? styles.rangeActive : ''}
              onClick={() => selectRange(value)}
              aria-pressed={range === value}
            >
              {value === 'all' ? 'All' : `${value}d`}
            </button>
          ))}
        </div>
      </div>

      <div className={styles.chartLegend}>
        <span><i className={styles.legendScore} />Security score</span>
        <span><i className={styles.legendFindings} />Findings</span>
        <span><i className={styles.legendFailed} />Failed scans</span>
      </div>

      {data.length === 0 ? (
        <div className={styles.chartEmpty}>
          <strong>No scan activity in this period</strong>
          <span>Run a scan to start building your security trend.</span>
        </div>
      ) : (
        <div className={styles.chartWrap}>
          <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
            <ComposedChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }}>
              <defs>
                <linearGradient id="dashboardScoreFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.24} />
                  <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
              <XAxis dataKey="date" axisLine={false} tickLine={false} minTickGap={28} tick={{ fill: '#7c8798', fontSize: 11 }} />
              <YAxis yAxisId="score" domain={[0, 100]} axisLine={false} tickLine={false} ticks={[0, 25, 50, 75, 100]} tick={{ fill: '#7c8798', fontSize: 11 }} />
              <YAxis yAxisId="activity" orientation="right" axisLine={false} tickLine={false} allowDecimals={false} width={24} tick={{ fill: '#7c8798', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#111418', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 7, fontSize: 12 }}
                labelStyle={{ color: '#f8fafc', fontWeight: 700 }}
                itemStyle={{ color: '#a8b3c4' }}
              />
              <Area yAxisId="score" type="monotone" dataKey="score" name="Security score" stroke="#22d3ee" strokeWidth={2} fill="url(#dashboardScoreFill)" connectNulls />
              <Bar yAxisId="activity" dataKey="findings" name="Findings" fill="#f59e0b" fillOpacity={0.55} radius={[3, 3, 0, 0]} maxBarSize={16} />
              <Bar yAxisId="activity" dataKey="failed" name="Failed scans" fill="#ef4444" fillOpacity={0.7} radius={[3, 3, 0, 0]} maxBarSize={9} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}
