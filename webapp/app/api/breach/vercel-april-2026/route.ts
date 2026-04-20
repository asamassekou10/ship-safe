import { NextRequest, NextResponse } from 'next/server';

/* ── Rate limiting (in-memory, per-IP) ── */
const rateMap = new Map<string, { count: number; resetAt: number }>();
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + 3600_000 });
    return false;
  }
  if (entry.count >= 20) return true;
  entry.count++;
  return false;
}

/* ── IOC: incident window ── */
const INCIDENT_START = new Date('2026-03-28T00:00:00Z').getTime();
const INCIDENT_END   = new Date('2026-04-12T23:59:59Z').getTime();

/* ── IOC: known-bad integration slugs / names ── */
const KNOWN_BAD_INTEGRATIONS = new Set([
  'ai-code-review', 'ai-deploy', 'code-ai', 'gpt-deploy',
  'cursor-vercel', 'copilot-vercel', 'devin-deploy',
]);

/* ── Overly broad scopes that AI integrations should not need ── */
const DANGEROUS_SCOPES = ['env:read', 'env:write', 'deployments:write', 'secrets:read', 'admin'];

/* ── AI action name regex for GitHub workflow scanning ── */
const AI_ACTION_RE = /uses\s*:\s*([\w.\-\/]+(?:ai|llm|copilot|claude|openai|anthropic|gpt|gemini|cursor|codeium|tabnine|hermes|codex|devin|agent|autopilot)[\w.\-\/]*)@([\w.\/\-]+)/gi;
const PINNED_SHA_RE = /^[0-9a-f]{40}$/i;

/* ── Track 4: cross-boundary token patterns (mirrors AgenticSupplyChainAgent) ── */
const TOKEN_PATTERNS = [
  {
    rule: 'MCP_TOKEN_FORWARD',
    title: 'High-value credential set in agent/MCP config',
    // Handles both YAML (KEY: value / KEY: ${{ secrets.X }}) and JSON ("KEY": "value") formats
    regex: /(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|VERCEL_TOKEN|LINEAR_API_KEY|SLACK_BOT_TOKEN|GH_PAT|CI_TOKEN)["']?\s*[:=]\s*["']?(?:\$\{\{|\$\{|\S{8,})/gi,
    severity: 'high',
    fix: 'Never forward production credentials to third-party MCP or agent tool servers.',
  },
  {
    rule: 'MCP_THIRD_PARTY_AUTH',
    title: 'Third-party MCP server URL with auth material',
    // Handles JSON ("url": "https://...") and YAML (url: https://...) formats
    regex: /["']?(?:url|baseUrl|endpoint|server)["']?\s*[:=]\s*["']?https?:\/\/(?!localhost|127\.|0\.0\.0\.0)([^"'\s,}]+)["']?[^}]{0,300}(?:Authorization|Bearer|api[_\-]?key|token)/gi,
    severity: 'critical',
    fix: 'Audit this MCP server. Do not forward credentials to servers you do not control.',
  },
  {
    rule: 'BROAD_OAUTH_SCOPES',
    title: 'Agent config requests 4 or more OAuth scopes',
    regex: /scopes?\s*[:=]\s*[\["](?:[^"\]]*,\s*){3,}[^"\]]*/gi,
    severity: 'high',
    fix: 'Request only the minimum scopes your agent needs for each specific task.',
  },
];

/* ── GitHub helpers ── */
const GH_HEADERS = {
  Accept: 'application/vnd.github.v3+json',
  'User-Agent': 'ship-safe-breach-check',
  ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
};

async function getWorkflowFiles(owner: string, repo: string): Promise<{ path: string; content: string }[]> {
  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`,
    { headers: GH_HEADERS },
  );
  if (!treeRes.ok) throw new Error(`GitHub ${treeRes.status}`);

  const tree = (await treeRes.json()).tree as { path: string; type: string; size?: number }[];
  const workflows = tree.filter(
    f => f.type === 'blob' &&
    f.path.startsWith('.github/workflows/') &&
    /\.ya?ml$/.test(f.path) &&
    (f.size ?? 0) < 200_000,
  );

  const results: { path: string; content: string }[] = [];
  await Promise.all(workflows.map(async wf => {
    const r = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(wf.path)}`,
      { headers: GH_HEADERS },
    );
    if (!r.ok) return;
    const data = await r.json();
    if (data.encoding === 'base64' && data.content) {
      results.push({ path: wf.path, content: Buffer.from(data.content, 'base64').toString('utf-8') });
    }
  }));
  return results;
}

/* ── Vercel API helpers ── */
function vercelHeaders(token: string) {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

async function getVercelIntegrations(token: string, teamId?: string) {
  const qs = teamId ? `?teamId=${encodeURIComponent(teamId)}` : '';
  const r = await fetch(`https://api.vercel.com/v1/integrations/configurations${qs}`, {
    headers: vercelHeaders(token),
  });
  if (r.status === 400) throw new Error('400');
  if (!r.ok) throw new Error(`Vercel API ${r.status}`);
  const data = await r.json();
  return (data.configurations ?? data.integrations ?? data) as Record<string, unknown>[];
}

async function getVercelAuditLog(token: string, teamId?: string) {
  const allEvents: Record<string, unknown>[] = [];
  let nextCursor: string | undefined;
  const MAX_PAGES = 10; // safety cap: 1 000 events max

  for (let page = 0; page < MAX_PAGES; page++) {
    const params = new URLSearchParams({ limit: '100' });
    if (teamId) params.set('teamId', teamId);
    if (nextCursor) params.set('next', nextCursor);

    const r = await fetch(`https://api.vercel.com/v3/events?${params}`, {
      headers: vercelHeaders(token),
    });
    if (!r.ok) throw new Error(`Vercel audit API ${r.status}`);
    const data = await r.json();
    const events = (data.events ?? data) as Record<string, unknown>[];

    if (events.length === 0) break;
    allEvents.push(...events);

    // Find oldest timestamp on this page — events arrive newest-first
    const oldestTs = Math.min(...events.map(e => Number(e.createdAt ?? e.timestamp ?? Infinity)));

    // Gone past the incident window — no need to fetch older pages
    if (oldestTs < INCIDENT_START) break;

    // Fewer than 100 means no more pages
    if (events.length < 100) break;

    nextCursor = data.pagination?.next ? String(data.pagination.next) : undefined;
    if (!nextCursor) break;
  }

  return allEvents;
}

/* ── Check result shape ── */
interface CheckFinding {
  severity: 'critical' | 'high' | 'medium' | 'info';
  title: string;
  detail: string;
  fix: string;
}

interface CheckResult {
  status: 'clean' | 'findings' | 'error';
  summary: string;
  findings: CheckFinding[];
}

/* ══════════════════════════════════════════════════════════
   CHECK 1 — GitHub workflow AI action pinning
══════════════════════════════════════════════════════════ */
async function checkGitHub(owner: string, repo: string): Promise<CheckResult> {
  const findings: CheckFinding[] = [];

  let workflows: { path: string; content: string }[];
  try {
    workflows = await getWorkflowFiles(owner, repo);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('404')) return { status: 'error', summary: 'Repository not found or private.', findings: [] };
    if (msg.includes('403')) return { status: 'error', summary: 'GitHub rate limit reached. Try again in a moment.', findings: [] };
    return { status: 'error', summary: `GitHub API error: ${msg}`, findings: [] };
  }

  if (workflows.length === 0) {
    return { status: 'clean', summary: 'No GitHub Actions workflows found.', findings: [] };
  }

  for (const wf of workflows) {
    const lines = wf.content.split('\n');
    const hasWriteAll = /permissions\s*:\s*write-all/.test(wf.content);

    AI_ACTION_RE.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = AI_ACTION_RE.exec(wf.content)) !== null) {
      const actionName = match[1];
      const ref = match[2];
      const lineNum = wf.content.slice(0, match.index).split('\n').length;
      const lineCtx = lines[lineNum - 1]?.trim() ?? '';

      if (!PINNED_SHA_RE.test(ref)) {
        findings.push({
          severity: 'critical',
          title: `Unpinned AI action: ${actionName}@${ref}`,
          detail: `${wf.path}:${lineNum} — \`${lineCtx}\`\n\nThis action is referenced by a mutable tag. A tag-repointing attack (the vector used in April 2026) can replace it with a credential stealer. Your VERCEL_TOKEN, GITHUB_TOKEN, and any secrets in this workflow would be silently exfiltrated.`,
          fix: `Pin to a full 40-character commit SHA:\nuses: ${actionName}@<sha> # ${ref}`,
        });
      }

      if (hasWriteAll) {
        findings.push({
          severity: 'critical',
          title: `AI action "${actionName}" runs with write-all permissions`,
          detail: `${wf.path} — \`permissions: write-all\` grants every AI action in this workflow unrestricted write access to your repository, secrets, and packages. A compromised action exfiltrates everything.`,
          fix: 'Replace with scoped permissions: `permissions: { contents: read }`',
        });
        break; // one finding per workflow for write-all
      }
    }
    AI_ACTION_RE.lastIndex = 0;
  }

  if (findings.length === 0) {
    return {
      status: 'clean',
      summary: `Checked ${workflows.length} workflow file${workflows.length === 1 ? '' : 's'}. All AI actions are pinned to commit SHAs.`,
      findings: [],
    };
  }

  return {
    status: 'findings',
    summary: `Found ${findings.length} issue${findings.length === 1 ? '' : 's'} across ${workflows.length} workflow file${workflows.length === 1 ? '' : 's'}.`,
    findings,
  };
}

/* ══════════════════════════════════════════════════════════
   CHECK 2 — Vercel integration scopes
══════════════════════════════════════════════════════════ */
async function checkVercelIntegrations(token: string, teamId?: string): Promise<CheckResult> {
  const findings: CheckFinding[] = [];

  let integrations: Record<string, unknown>[];
  try {
    integrations = await getVercelIntegrations(token, teamId);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('401') || msg.includes('403')) {
      return { status: 'error', summary: 'Invalid or expired Vercel token. Check it has read access.', findings: [] };
    }
    if (msg.includes('400')) {
      return { status: 'error', summary: 'Vercel returned 400. If your projects are under a team, add your Team ID (team_xxxxxx) in the field above.', findings: [] };
    }
    return { status: 'error', summary: `Vercel API error: ${msg}`, findings: [] };
  }

  for (const integration of integrations) {
    const slug = String(integration.slug ?? integration.integrationId ?? integration.name ?? '').toLowerCase();
    const scopes: string[] = Array.isArray(integration.scopes) ? integration.scopes.map(String) : [];
    const badScopes = scopes.filter(s => DANGEROUS_SCOPES.some(d => s.toLowerCase().includes(d)));
    const isKnownBad = KNOWN_BAD_INTEGRATIONS.has(slug);

    if (badScopes.length > 0 || isKnownBad) {
      const name = String(integration.slug ?? integration.name ?? 'unknown');
      findings.push({
        severity: badScopes.includes('env:read') || badScopes.includes('secrets:read') ? 'critical' : 'high',
        title: `Integration "${name}" has dangerous scopes: ${badScopes.join(', ') || 'unknown'}`,
        detail: isKnownBad
          ? `"${name}" was one of the integration categories involved in the April 2026 attack pattern. Scopes: ${scopes.join(', ') || 'unknown'}. If this was installed between March 28 and April 12, your deployment tokens may have been exposed.`
          : `"${name}" holds ${badScopes.join(' + ')} access. If this integration received a malicious update during the incident window, it could read your environment variables and deployment tokens without triggering any alerts.`,
        fix: `Revoke and re-install this integration with minimal scopes. Review your Vercel audit log for unexpected env reads or deployments from this integration between March 28 – April 12, 2026.`,
      });
    }
  }

  if (integrations.length === 0) {
    return { status: 'clean', summary: 'No integrations found on this account.', findings: [] };
  }

  if (findings.length === 0) {
    return {
      status: 'clean',
      summary: `Checked ${integrations.length} integration${integrations.length === 1 ? '' : 's'}. None have dangerous scope combinations.`,
      findings: [],
    };
  }

  return {
    status: 'findings',
    summary: `Found ${findings.length} integration${findings.length === 1 ? '' : 's'} with potentially dangerous scopes.`,
    findings,
  };
}

/* ══════════════════════════════════════════════════════════
   CHECK 3 — Vercel audit log
══════════════════════════════════════════════════════════ */
async function checkVercelAuditLog(token: string, teamId?: string): Promise<CheckResult> {
  const findings: CheckFinding[] = [];

  let events: Record<string, unknown>[];
  try {
    events = await getVercelAuditLog(token, teamId);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes('401') || msg.includes('403')) {
      return { status: 'error', summary: 'Invalid token or insufficient permissions to read audit log.', findings: [] };
    }
    if (msg.includes('400')) {
      return { status: 'error', summary: 'Vercel returned 400. If your projects are under a team, add your Team ID (team_xxxxxx) in the field above.', findings: [] };
    }
    return { status: 'error', summary: `Vercel audit API error: ${msg}`, findings: [] };
  }

  const windowEvents = events.filter(e => {
    const ts = Number(e.createdAt ?? e.timestamp ?? 0);
    return ts >= INCIDENT_START && ts <= INCIDENT_END;
  });

  // Suspicious patterns during incident window
  const envReads = windowEvents.filter(e =>
    String(e.type ?? e.action ?? '').toLowerCase().includes('env') &&
    String(e.type ?? e.action ?? '').toLowerCase().includes('read'),
  );
  const unexpectedDeploys = windowEvents.filter(e =>
    String(e.type ?? e.action ?? '').toLowerCase().includes('deployment') &&
    String(e.type ?? e.action ?? '').toLowerCase().includes('creat'),
  );
  const tokenCreations = windowEvents.filter(e =>
    String(e.type ?? e.action ?? '').toLowerCase().includes('token') &&
    String(e.type ?? e.action ?? '').toLowerCase().includes('creat'),
  );

  if (envReads.length > 0) {
    findings.push({
      severity: 'critical',
      title: `${envReads.length} environment variable read event${envReads.length === 1 ? '' : 's'} during incident window`,
      detail: `Between March 28 – April 12, your audit log shows ${envReads.length} env read event${envReads.length === 1 ? '' : 's'}. If these were triggered by a third-party integration rather than your own deploys, your env vars (including VERCEL_TOKEN, database URLs, API keys) may have been exfiltrated.`,
      fix: 'Cross-reference the actor field of each env read event with your known team members. Rotate any secrets that could have been read by an unknown actor.',
    });
  }

  if (unexpectedDeploys.length > 5) {
    findings.push({
      severity: 'high',
      title: `${unexpectedDeploys.length} deployments during incident window`,
      detail: `An elevated number of deployments (${unexpectedDeploys.length}) occurred between March 28 – April 12. Attackers who obtained deployment tokens used them to trigger phantom deploys for token-freshness probing.`,
      fix: 'Review each deployment in your Vercel dashboard for the incident window and verify every one was triggered by a known team member or legitimate CI pipeline.',
    });
  }

  if (tokenCreations.length > 0) {
    findings.push({
      severity: 'critical',
      title: `${tokenCreations.length} new token creation${tokenCreations.length === 1 ? '' : 's'} during incident window`,
      detail: `New API tokens were created during the incident window. Attackers who gained initial access often create long-lived tokens to maintain persistence after the compromised integration is revoked.`,
      fix: 'Revoke all tokens created between March 28 – April 12 that you do not recognize. Audit your active tokens at vercel.com/account/tokens.',
    });
  }

  if (findings.length === 0 && windowEvents.length === 0) {
    return {
      status: 'clean',
      summary: 'No activity found in your audit log during the incident window (Mar 28 – Apr 12, 2026).',
      findings: [],
    };
  }

  if (findings.length === 0) {
    return {
      status: 'clean',
      summary: `Reviewed ${windowEvents.length} event${windowEvents.length === 1 ? '' : 's'} from the incident window. No suspicious patterns detected.`,
      findings: [],
    };
  }

  return {
    status: 'findings',
    summary: `Found ${findings.length} suspicious pattern${findings.length === 1 ? '' : 's'} in ${windowEvents.length} incident-window events.`,
    findings,
  };
}

/* ══════════════════════════════════════════════════════════
   CHECK 4 — Paste config scan
══════════════════════════════════════════════════════════ */
function checkConfig(configText: string): CheckResult {
  const findings: CheckFinding[] = [];

  for (const p of TOKEN_PATTERNS) {
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(configText)) !== null) {
      const lineNum = configText.slice(0, m.index).split('\n').length;
      findings.push({
        severity: p.severity as CheckFinding['severity'],
        title: p.title,
        detail: `Line ${lineNum}: \`${m[0].slice(0, 80)}${m[0].length > 80 ? '…' : ''}\``,
        fix: p.fix,
      });
      if (findings.filter(f => f.title === p.title).length >= 3) break;
    }
  }

  if (findings.length === 0) {
    return { status: 'clean', summary: 'No cross-boundary token forwarding patterns detected.', findings: [] };
  }

  return {
    status: 'findings',
    summary: `Found ${findings.length} issue${findings.length === 1 ? '' : 's'} in your config.`,
    findings,
  };
}

/* ══════════════════════════════════════════════════════════
   Route handler
══════════════════════════════════════════════════════════ */
export async function POST(req: NextRequest) {
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    req.headers.get('x-real-ip') ??
    'unknown';

  if (isRateLimited(ip)) {
    return NextResponse.json({ error: 'Rate limit exceeded. Please try again later.' }, { status: 429 });
  }

  let body: {
    check: string;
    repoUrl?: string;
    vercelToken?: string;
    teamId?: string;
    configText?: string;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const { check } = body;

  if (check === 'github') {
    const { repoUrl } = body;
    if (!repoUrl) return NextResponse.json({ error: 'repoUrl required' }, { status: 400 });
    const m = repoUrl.match(/^https:\/\/github\.com\/([\w.\-]+)\/([\w.\-]+?)(?:\.git)?\/?$/);
    if (!m) return NextResponse.json({ error: 'Invalid GitHub URL' }, { status: 400 });
    const result = await checkGitHub(m[1], m[2]);
    return NextResponse.json(result);
  }

  if (check === 'vercel-integrations') {
    const { vercelToken, teamId } = body;
    if (!vercelToken?.trim()) return NextResponse.json({ error: 'vercelToken required' }, { status: 400 });
    const result = await checkVercelIntegrations(vercelToken.trim(), teamId?.trim() || undefined);
    return NextResponse.json(result);
  }

  if (check === 'vercel-audit') {
    const { vercelToken, teamId } = body;
    if (!vercelToken?.trim()) return NextResponse.json({ error: 'vercelToken required' }, { status: 400 });
    const result = await checkVercelAuditLog(vercelToken.trim(), teamId?.trim() || undefined);
    return NextResponse.json(result);
  }

  if (check === 'config') {
    const { configText } = body;
    if (!configText?.trim()) return NextResponse.json({ error: 'configText required' }, { status: 400 });
    if (configText.length > 50_000) return NextResponse.json({ error: 'Config too large (max 50 KB)' }, { status: 400 });
    const result = checkConfig(configText);
    return NextResponse.json(result);
  }

  return NextResponse.json({ error: `Unknown check: ${check}` }, { status: 400 });
}
