'use client';
import { useEffect, useState } from 'react';
import styles from './team.module.css';

interface Org {
  id: string;
  name: string;
  slug: string;
  plan: string;
  role: string;
  memberCount: number;
  scanCount: number;
}

interface Member {
  id: string;
  role: string;
  user: { id: string; name: string | null; email: string | null; image: string | null };
}

export default function TeamPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  const [newOrgName, setNewOrgName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/orgs').then(r => r.json()).then(d => {
      setOrgs(d.orgs || []);
      if (d.orgs?.length > 0) setSelectedOrg(d.orgs[0].id);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    if (!selectedOrg) return;
    fetch(`/api/orgs/${selectedOrg}/members`).then(r => r.json()).then(d => setMembers(d.members || []));
  }, [selectedOrg]);

  async function createOrg() {
    setError('');
    const res = await fetch('/api/orgs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newOrgName }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    setOrgs(prev => [...prev, { ...data, role: 'owner', memberCount: 1, scanCount: 0 }]);
    setSelectedOrg(data.id);
    setNewOrgName('');
  }

  async function invite() {
    setError('');
    const res = await fetch(`/api/orgs/${selectedOrg}/invite`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    // Refresh members
    const r = await fetch(`/api/orgs/${selectedOrg}/members`);
    const d = await r.json();
    setMembers(d.members || []);
    setInviteEmail('');
  }

  async function removeMember(memberId: string) {
    await fetch(`/api/orgs/${selectedOrg}/members`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ memberId }),
    });
    setMembers(prev => prev.filter(m => m.id !== memberId));
  }

  const currentOrg = orgs.find(o => o.id === selectedOrg);
  const isAdmin = currentOrg?.role === 'owner' || currentOrg?.role === 'admin';

  if (loading) return <div className={styles.page}><p style={{ color: 'var(--text-dim)' }}>Loading...</p></div>;

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Team</h1>
          <p className={styles.subtitle}>Manage your organization and team members</p>
        </div>
      </div>

      {orgs.length === 0 ? (
        <div className={styles.emptyState}>
          <h3>Create your first organization</h3>
          <p>Organizations let you share scans, set policies, and collaborate with your team.</p>
          <div className={styles.createRow}>
            <input
              type="text"
              placeholder="Organization name"
              value={newOrgName}
              onChange={e => setNewOrgName(e.target.value)}
              className={styles.input}
            />
            <button onClick={createOrg} className="btn btn-primary" disabled={!newOrgName.trim()}>
              Create Organization
            </button>
          </div>
          {error && <p className={styles.error}>{error}</p>}
        </div>
      ) : (
        <>
          {/* Org selector */}
          {orgs.length > 1 && (
            <div className={styles.orgTabs}>
              {orgs.map(o => (
                <button
                  key={o.id}
                  className={`${styles.orgTab} ${selectedOrg === o.id ? styles.active : ''}`}
                  onClick={() => setSelectedOrg(o.id)}
                >
                  {o.name}
                  <span className={styles.badge}>{o.role}</span>
                </button>
              ))}
            </div>
          )}

          {/* Org info */}
          {currentOrg && (
            <div className={styles.statsRow}>
              <div className={styles.statCard}>
                <span className={styles.statValue}>{currentOrg.memberCount}</span>
                <span className={styles.statLabel}>Members</span>
              </div>
              <div className={styles.statCard}>
                <span className={styles.statValue}>{currentOrg.scanCount}</span>
                <span className={styles.statLabel}>Scans</span>
              </div>
              <div className={styles.statCard}>
                <span className={styles.statValue} style={{ textTransform: 'capitalize' }}>{currentOrg.plan}</span>
                <span className={styles.statLabel}>Plan</span>
              </div>
            </div>
          )}

          {/* Invite */}
          {isAdmin && (
            <div className={styles.section}>
              <h2>Invite Members</h2>
              <div className={styles.inviteRow}>
                <input
                  type="email"
                  placeholder="Email address"
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  className={styles.input}
                />
                <select value={inviteRole} onChange={e => setInviteRole(e.target.value)} className={styles.select}>
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                  <option value="viewer">Viewer</option>
                </select>
                <button onClick={invite} className="btn btn-primary" disabled={!inviteEmail.trim()}>
                  Invite
                </button>
              </div>
            </div>
          )}

          {error && <p className={styles.error}>{error}</p>}

          {/* Members list */}
          <div className={styles.section}>
            <h2>Members</h2>
            <div className={styles.memberList}>
              {members.map(m => (
                <div key={m.id} className={styles.memberRow}>
                  <div className={styles.memberInfo}>
                    {m.user.image && (
                      <img src={m.user.image} alt="" width={32} height={32} className={styles.avatar} />
                    )}
                    <div>
                      <div className={styles.memberName}>{m.user.name || m.user.email}</div>
                      {m.user.name && <div className={styles.memberEmail}>{m.user.email}</div>}
                    </div>
                  </div>
                  <div className={styles.memberActions}>
                    <span className={`${styles.roleBadge} ${styles[`role${m.role.charAt(0).toUpperCase() + m.role.slice(1)}`] || ''}`}>
                      {m.role}
                    </span>
                    {isAdmin && m.role !== 'owner' && (
                      <button onClick={() => removeMember(m.id)} className={styles.removeBtn}>Remove</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Create another org */}
          {isAdmin && (
            <div className={styles.section}>
              <h2>New Organization</h2>
              <div className={styles.createRow}>
                <input
                  type="text"
                  placeholder="Organization name"
                  value={newOrgName}
                  onChange={e => setNewOrgName(e.target.value)}
                  className={styles.input}
                />
                <button onClick={createOrg} className="btn btn-ghost" disabled={!newOrgName.trim()}>
                  Create
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
