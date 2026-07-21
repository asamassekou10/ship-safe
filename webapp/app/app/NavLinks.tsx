'use client';

import { useEffect, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import styles from './app.layout.module.css';

type NavItem = { href: string; label: string; icon: ReactNode; exact?: boolean };
type NavGroup = { id: string; label: string; icon: ReactNode; items: NavItem[] };

const icon = {
  home: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>,
  scan: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
  shield: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>,
  agent: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="7" width="16" height="13" rx="3"/><path d="M9 3h6M12 3v4M8 12h.01M16 12h.01M8 16h8"/></svg>,
  finding: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>,
  repo: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3h7a2 2 0 0 1 2 2v16a3 3 0 0 0-3-3H3zM21 3h-7a2 2 0 0 0-2 2v16a3 3 0 0 1 3-3h6z"/></svg>,
  team: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="9" cy="7" r="3"/><circle cx="18" cy="7" r="3"/><path d="M3 20c0-3.3 2.7-6 6-6h1M12 20c0-3.3 2.7-6 6-6h1"/></svg>,
  chart: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3v18h18M7 14l3-3 3 2 5-7"/></svg>,
  history: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5M12 7v5l3 2"/></svg>,
  policy: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 3h12v18H6zM9 8h6M9 12h6M9 16h4"/></svg>,
  bolt: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  doc: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h8"/></svg>,
  more: <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/></svg>,
  settings: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9 7 7M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"/></svg>,
};

const primary: NavItem[] = [
  { href: '/app', label: 'Home', exact: true, icon: icon.home },
  { href: '/app/scan', label: 'New scan', icon: icon.scan },
];

const groups: NavGroup[] = [
  { id: 'security', label: 'Security', icon: icon.shield, items: [
    { href: '/app/findings', label: 'Findings', icon: icon.finding },
    { href: '/app/repos', label: 'Repositories', icon: icon.repo },
    { href: '/app/guardian', label: 'PR Guardian', icon: icon.shield },
  ] },
  { id: 'agents', label: 'Agents', icon: icon.agent, items: [
    { href: '/app/agents', label: 'My agents', icon: icon.agent },
    { href: '/app/agent-teams', label: 'Agent teams', icon: icon.team },
    { href: '/app/intelligence', label: 'Intelligence', icon: icon.chart },
  ] },
  { id: 'more', label: 'More', icon: icon.more, items: [
    { href: '/app/history', label: 'Scan history', icon: icon.history },
    { href: '/app/compare', label: 'Compare scans', icon: icon.chart },
    { href: '/app/policies', label: 'Policies', icon: icon.policy },
    { href: '/app/deploy', label: 'Hermes setup', icon: icon.bolt },
    { href: '/app/content-agent', label: 'Content agent', icon: icon.doc },
  ] },
];

const footer: NavItem[] = [
  { href: '/app/team', label: 'Team', icon: icon.team },
  { href: '/app/settings', label: 'Settings', icon: icon.settings },
];

function isActive(pathname: string, item: NavItem) {
  return item.exact ? pathname === item.href : pathname.startsWith(item.href);
}

export default function NavLinks({ isAdmin, onNavigate }: { isAdmin: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  const activeGroup = groups.find(group => group.items.some(item => isActive(pathname, item)))?.id;
  const [openGroup, setOpenGroup] = useState<string | null>(activeGroup ?? null);

  useEffect(() => {
    if (activeGroup) setOpenGroup(activeGroup);
  }, [activeGroup]);

  const renderItem = (item: NavItem, nested = false) => (
    <Link
      key={item.href}
      href={item.href}
      onClick={onNavigate}
      className={`${styles.navItem} ${nested ? styles.navItemNested : ''} ${isActive(pathname, item) ? styles.active : ''}`}
    >
      {item.icon}<span>{item.label}</span>
    </Link>
  );

  return (
    <nav className={styles.nav} aria-label="Product navigation">
      <div className={styles.navSection}>{primary.map(item => renderItem(item))}</div>
      <div className={styles.navGroups}>
        {groups.map(group => {
          const open = openGroup === group.id;
          return (
            <div key={group.id} className={styles.navGroup}>
              <button
                type="button"
                className={`${styles.navGroupButton} ${activeGroup === group.id ? styles.navGroupActive : ''}`}
                aria-expanded={open}
                onClick={() => setOpenGroup(current => current === group.id ? null : group.id)}
              >
                {group.icon}<span>{group.label}</span>
                <svg className={`${styles.navChevron} ${open ? styles.navChevronOpen : ''}`} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6"/></svg>
              </button>
              {open && <div className={styles.navChildren}>{group.items.map(item => renderItem(item, true))}</div>}
            </div>
          );
        })}
      </div>
      <div className={styles.navFooterLinks}>
        {footer.map(item => renderItem(item))}
        {isAdmin && renderItem({ href: '/app/admin', label: 'Admin', icon: icon.shield })}
      </div>
    </nav>
  );
}
