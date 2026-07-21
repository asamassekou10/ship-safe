'use client';

import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import Link from 'next/link';
import styles from './dashboard.module.css';

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#38bdf8',
};

const outcomeColors: Record<string, string> = {
  done: '#22c55e',
  failed: '#ef4444',
  running: '#22d3ee',
  pending: '#eab308',
};

type SeveritySummary = Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
type Outcome = { status: string; count: number };
type RiskSignals = { label: string; value: number; color: string; href: string }[];

export function SeverityOverview({ severity, outcomes }: { severity: SeveritySummary; outcomes: Outcome[] }) {
  const severityData = Object.entries(severity)
    .map(([name, value]) => ({ name, value, color: severityColors[name] }))
    .filter(item => item.value > 0);
  const total = severityData.reduce((sum, item) => sum + item.value, 0);
  const outcomeTotal = outcomes.reduce((sum, item) => sum + item.count, 0);

  return (
    <section className={styles.riskPanel} aria-labelledby="risk-distribution-title">
      <div className={styles.panelHeader}>
        <div>
          <span className={styles.panelEyebrow}>Exposure</span>
          <h2 id="risk-distribution-title">Risk distribution</h2>
        </div>
        <span className={styles.riskTotal}>{total} open</span>
      </div>

      <div className={styles.donutArea}>
        <div className={styles.donutChart}>
          {total > 0 ? (
            <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={69} paddingAngle={2} stroke="none">
                  {severityData.map(item => <Cell key={item.name} fill={item.color} />)}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#111418', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 7, fontSize: 12 }}
                  itemStyle={{ color: '#d7dee8', textTransform: 'capitalize' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className={styles.emptyDonut} />}
          <div className={styles.donutValue}><strong>{total}</strong><span>open risks</span></div>
        </div>

        <div className={styles.severityLegend}>
          {Object.entries(severity).map(([name, value]) => (
            <Link key={name} href={`/app/findings?severity=${name}&status=open`} className={styles.severityLink}>
              <i style={{ background: severityColors[name] }} />
              <span>{name}</span>
              <strong>{value}</strong>
            </Link>
          ))}
        </div>
      </div>

      <div className={styles.outcomeBlock}>
        <div className={styles.outcomeTitle}><span>All-time scan outcomes</span><strong>{outcomeTotal}</strong></div>
        <div className={styles.outcomeBar} aria-label={`${outcomeTotal} total scans`}>
          {outcomes.filter(item => item.count > 0).map(item => (
            <Link
              key={item.status}
              href={`/app/history?filter=${item.status === 'running' || item.status === 'pending' ? 'active' : item.status}`}
              style={{ width: `${outcomeTotal ? (item.count / outcomeTotal) * 100 : 0}%`, background: outcomeColors[item.status] ?? '#64748b' }}
              title={`${item.status}: ${item.count}`}
            />
          ))}
        </div>
        <div className={styles.outcomeLegend}>
          {outcomes.map(item => (
            <Link key={item.status} href={`/app/history?filter=${item.status === 'running' || item.status === 'pending' ? 'active' : item.status}`}>
              <i style={{ background: outcomeColors[item.status] ?? '#64748b' }} />{item.status} <strong>{item.count}</strong>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

export function RiskSignalChart({ signals }: { signals: RiskSignals }) {
  const hasSignals = signals.some(signal => signal.value > 0);

  return (
    <section className={styles.signalPanel} aria-labelledby="risk-signals-title">
      <div className={styles.panelHeader}>
        <div>
          <span className={styles.panelEyebrow}>Detection mix</span>
          <h2 id="risk-signals-title">Risk signals detected</h2>
        </div>
        <span className={styles.chartUnit}>All time</span>
      </div>

      {hasSignals ? (
        <div className={styles.signalChart}>
          <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
            <BarChart data={signals} layout="vertical" margin={{ top: 8, right: 28, bottom: 0, left: 14 }}>
              <XAxis type="number" axisLine={false} tickLine={false} allowDecimals={false} tick={{ fill: '#7c8798', fontSize: 11 }} />
              <YAxis type="category" dataKey="label" axisLine={false} tickLine={false} width={112} tick={{ fill: '#a8b3c4', fontSize: 11 }} />
              <Tooltip
                cursor={{ fill: 'rgba(148,163,184,0.05)' }}
                contentStyle={{ background: '#111418', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 7, fontSize: 12 }}
                labelStyle={{ color: '#f8fafc', fontWeight: 700 }}
              />
              <Bar dataKey="value" name="Signals" radius={[0, 4, 4, 0]} maxBarSize={22}>
                {signals.map(signal => <Cell key={signal.label} fill={signal.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className={styles.signalEmpty}>No risk signals have been recorded yet.</div>
      )}
      <div className={styles.signalSummary}>
        {signals.map(signal => (
          <Link key={signal.label} href={signal.href}><i style={{ background: signal.color }} /><span>{signal.label}</span><strong>{signal.value}</strong></Link>
        ))}
      </div>
    </section>
  );
}
