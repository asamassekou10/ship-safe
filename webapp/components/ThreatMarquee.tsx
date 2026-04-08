import styles from './ThreatMarquee.module.css';

const THREATS = [
  { name: 'Hardcoded Secret',           sev: 'critical' },
  { name: 'Prompt Injection',           sev: 'critical' },
  { name: 'Unpinned GitHub Action',     sev: 'high'     },
  { name: 'SQL Injection',              sev: 'critical' },
  { name: 'MCP ToxicSkill',             sev: 'high'     },
  { name: 'OIDC Wildcard Condition',    sev: 'critical' },
  { name: 'JWT None Algorithm',         sev: 'critical' },
  { name: 'curl | bash in CI',          sev: 'high'     },
  { name: 'eval() Injection',           sev: 'high'     }, // ship-safe-ignore — display label, not executable code
  { name: 'Leaked Token in Commit',     sev: 'critical' },
  { name: 'SSRF via Redirect',          sev: 'high'     },
  { name: 'Prototype Pollution',        sev: 'medium'   },
  { name: 'Supply Chain Attack',        sev: 'critical' },
  { name: 'KAIROS Autonomous Mode',     sev: 'high'     },
  { name: 'Missing Rate Limit',         sev: 'medium'   },
  { name: 'ReDoS Pattern',              sev: 'medium'   },
  { name: 'Exposed Debug Endpoint',     sev: 'high'     },
  { name: 'claw-code danger-full-access', sev: 'critical' },
  { name: 'dangerouslySkipPermissions', sev: 'critical' },
  { name: 'PII in Logs',               sev: 'medium'   },
  { name: 'Insecure Direct Object Ref', sev: 'high'     },
  { name: 'Hardcoded DB Password',      sev: 'critical' },
  { name: 'Shell Injection in Hook',    sev: 'critical' },
  { name: 'Weak Cryptography',         sev: 'medium'   },
  { name: 'AI Sandbox Escape',         sev: 'critical' },
  { name: 'Agent Privilege Escalation', sev: 'critical' },
  { name: 'Unrestricted Network Egress', sev: 'high'   },
  { name: 'Missing Human-in-the-Loop', sev: 'high'     },
  { name: 'Docker AuthZ Bypass',       sev: 'critical' },
  { name: 'DNS Tunneling Exfiltration', sev: 'critical' },
  { name: 'Branch Name Injection',     sev: 'critical' },
  { name: 'S3 NFS Mount Unrestricted', sev: 'high'     },
  { name: 'Managed Agent always_allow', sev: 'critical' },
  { name: 'Unrestricted Agent Network', sev: 'high'     },
  { name: 'Agent Bash No Confirm',     sev: 'critical' },
  { name: 'MCP Server Over HTTP',      sev: 'critical' },
];

const SEV_STYLE: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: '#dc2626', bg: 'rgba(220,38,38,0.07)',  border: 'rgba(220,38,38,0.2)'  },
  high:     { color: '#ea580c', bg: 'rgba(234,88,12,0.07)',  border: 'rgba(234,88,12,0.2)'  },
  medium:   { color: '#d97706', bg: 'rgba(217,119,6,0.07)',  border: 'rgba(217,119,6,0.2)'  },
};

// Double the array so the marquee loops seamlessly
const DOUBLED = [...THREATS, ...THREATS];

export default function ThreatMarquee() {
  return (
    <div className={styles.wrapper}>
      <div className={styles.label}>Threats we catch</div>
      <div className="marquee-wrap">
        <div className="marquee-track">
          {DOUBLED.map((t, i) => {
            const st = SEV_STYLE[t.sev] ?? SEV_STYLE.medium;
            return (
              <div key={i} className={styles.tag}>
                <span
                  className={styles.sevDot}
                  style={{ background: st.color }}
                />
                <span className={styles.tagName}>{t.name}</span>
                <span
                  className={styles.sevBadge}
                  style={{ color: st.color, background: st.bg, borderColor: st.border }}
                >
                  {t.sev}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
