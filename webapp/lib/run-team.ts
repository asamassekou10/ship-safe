/**
 * run-team.ts
 *
 * Team run orchestration engine.
 *
 * Flow:
 *  Phase 1 (planning)    — Lead agent receives the target + team roster.
 *                          It extracts recon (files, endpoints, attack surface)
 *                          and outputs DELEGATE: markers with specific tasks.
 *  Phase 2 (delegating)  — Sub-agents run in parallel. Each receives the Lead's
 *                          recon as a starting point plus a role-specific strategy.
 *  Phase 3 (synthesizing)— Findings are deduplicated and correlated across agents.
 *                          Lead receives structured findings + pre-computed chains
 *                          and writes a final executive report.
 *  Phase 4 (done)        — TeamRun is marked completed with the report.
 */

import { prisma } from '@/lib/prisma';
import { collectAgentRun, FindingEntry, DelegationEntry } from '@/lib/fire-agent-run';
import { saveFindings } from '@/lib/save-findings';

// ── Utilities ─────────────────────────────────────────────────────────────────

function stripAnsi(text: string): string {
  return text.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
}

// Parse FINDING: lines from agent output into structured objects.
function parseFindings(text: string): FindingEntry[] {
  const findings: FindingEntry[] = [];
  for (const line of text.split('\n')) {
    const match = line.match(/^FINDING:\s*(\{.+\})\s*$/);
    if (!match) continue;
    try {
      const f = JSON.parse(match[1]) as FindingEntry;
      if (f.severity && f.title && f.remediation) findings.push(f);
    } catch { /* skip malformed lines */ }
  }
  return findings;
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
type Severity = typeof SEV_ORDER[number];

function sevIndex(s: string): number {
  const i = SEV_ORDER.indexOf(s as Severity);
  return i === -1 ? SEV_ORDER.length : i;
}

// Deduplicate findings across agents: same title + same location = same finding.
// When 2+ agents flag the same asset, escalate to the highest severity seen and
// record it as a confirmed chain.
function deduplicateAndCorrelate(
  allFindings: Array<{ role: string; findings: FindingEntry[] }>,
): { deduped: FindingEntry[]; chains: string[] } {
  const map = new Map<string, { finding: FindingEntry; roles: string[] }>();

  for (const { role, findings } of allFindings) {
    for (const f of findings) {
      const key = [
        f.title.toLowerCase().slice(0, 60),
        (f.location ?? '').toLowerCase().slice(0, 60),
      ].join('|');

      const existing = map.get(key);
      if (existing) {
        existing.roles.push(role);
        if (sevIndex(f.severity) < sevIndex(existing.finding.severity)) {
          existing.finding.severity = f.severity;
        }
      } else {
        map.set(key, { finding: { ...f }, roles: [role] });
      }
    }
  }

  const deduped: FindingEntry[] = [];
  const chains:  string[]       = [];

  for (const { finding, roles } of map.values()) {
    deduped.push(finding);
    if (roles.length >= 2) {
      const agentNames = roles.map(r => ROLE_LABELS[r] ?? r).join(' + ');
      chains.push(
        `• **${finding.title}**${finding.location ? ` at \`${finding.location}\`` : ''} — independently flagged by ${agentNames}. Severity confirmed **${finding.severity}**.`,
      );
    }
  }

  deduped.sort((a, b) => sevIndex(a.severity) - sevIndex(b.severity));
  return { deduped, chains };
}

// Extract the attack surface recon block from the Lead's Phase 1 output.
// We look for the prose section before the first DELEGATE: line.
function extractRecon(text: string): string {
  const clean = stripAnsi(text);
  const delegateIdx = clean.search(/^DELEGATE:/m);
  const reconText   = delegateIdx > 0 ? clean.slice(0, delegateIdx) : clean;
  return reconText.trim().slice(0, 1500); // cap to keep sub-agent prompts lean
}

// ── Role metadata ─────────────────────────────────────────────────────────────

const ROLE_LABELS: Record<string, string> = {
  lead:        'Lead Security Analyst',
  pen_tester:  'Penetration Tester',
  red_team:    'Red Team Operator',
  secrets:     'Secrets & Credentials Scanner',
  cve_analyst: 'CVE & Dependency Analyst',
  custom:      'Security Specialist',
};

// Role-specific search strategies. These front-load the highest-signal work so
// agents don't burn their iteration budget on irrelevant directories.
const ROLE_STRATEGY: Record<string, string> = {
  pen_tester:
    'If the target is a remote repo URL, clone it first. Then focus on: authentication endpoints, input validation, IDOR patterns, SQL injection vectors, insecure direct object references. Prioritize files in routes/, controllers/, api/, middleware/. Do not scan for secrets — that is another agent\'s job.',
  red_team:
    'If the target is a remote repo URL, clone it first. Focus on: attack surface mapping, privilege escalation paths, trust boundary violations, admin interfaces, SSRF vectors, open redirects, exposed debug endpoints, unsafe deserialization.',
  secrets:
    'If the target is a remote repo URL, clone it first. Run targeted searches for: API keys, tokens, passwords, private keys, connection strings. Check .env*, *.yaml, *.json, CI config, Dockerfile. Use grep -r for patterns like SECRET, KEY, TOKEN, PASSWORD, CREDENTIAL. Do not waste iterations on source logic.',
  cve_analyst:
    'If the target is a remote repo URL, clone it first. Read the dependency manifest (package.json, requirements.txt, Gemfile, pom.xml, go.mod, Cargo.toml) and list all dependencies with versions. For each major dependency, check for known CVEs. Focus on packages with a history of vulnerabilities.',
  custom:
    'If the target is a remote repo URL, clone it first. Investigate all areas relevant to your assigned role.',
};

// Per-role timeouts. Kept tight so the full team run completes within Vercel's
// serverless max execution window. Lead runs twice (plan + synthesis).
const ROLE_TIMEOUT_MS: Record<string, number> = {
  pen_tester:  120_000, // 2 min
  red_team:    120_000, // 2 min
  secrets:     120_000, // 2 min
  cve_analyst:  90_000, // 1.5 min
  custom:       90_000, // 1.5 min
  lead:         90_000, // 1.5 min per phase
};

// Total wall-clock budget for the entire team run. If exceeded, mark as error.
const TEAM_RUN_TIMEOUT_MS = parseInt(process.env.TEAM_RUN_TIMEOUT_MS ?? '600000', 10); // 10 min

function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? role;
}

// ── Finding format ─────────────────────────────────────────────────────────────

const FINDING_FORMAT = `EXACTLY this format (valid JSON after 'FINDING:'):
FINDING: {"severity": "critical|high|medium|low|info", "title": "short description", "location": "file:line or component (optional)", "cve": "CVE-XXXX-XXXXX (optional)", "remediation": "how to fix it"}
Output one FINDING line per issue. Do not wrap them in code blocks.`;

// ── Prompt builders ───────────────────────────────────────────────────────────

function buildLeadPlanPrompt(
  target:     string,
  teamRoster: Array<{ role: string; agentName: string; description: string | null }>,
): string {
  const rosterLines = teamRoster
    .filter(m => m.role !== 'lead')
    .map(m => `- **${roleLabel(m.role)}** (${m.agentName}): ${m.description ?? 'No description'}`)
    .join('\n');

  return `You are the **Lead Security Analyst** coordinating a cybersecurity assessment team.

**Target:** ${target}

**Your team:**
${rosterLines || '(No sub-agents assigned — you will perform the full assessment alone)'}

**Phase 1 tasks:**
1. Map the attack surface. Note specific files, endpoints, dependencies, or components that look risky. Your team reads this recon before they start — be concrete.
2. Delegate a focused task to each team member using a DELEGATE line. Reference specific files or areas from your recon so they start with context, not blind.
3. Output preliminary FINDING lines for any obvious issues you can identify without tooling.

Delegation format:
DELEGATE: {"role":"pen_tester","task":"Check routes/auth.js and api/v1/admin for SQLi, IDOR, and privilege escalation. The Lead found an unguarded /admin route — confirm if it requires authentication."}

Delegate one task per team member. Be specific.
────────────────────────────────────────
${FINDING_FORMAT}`;
}

function buildSubAgentPrompt(
  target:  string,
  role:    string,
  task:    string,
  recon:   string,
): string {
  const strategy    = ROLE_STRATEGY[role] ?? ROLE_STRATEGY['custom'];
  const reconSection = recon.trim()
    ? `\n**Lead Analyst recon — use this as your starting point:**\n${recon}\n`
    : '';

  return `You are a **${roleLabel(role)}** on a cybersecurity assessment team.

**Target:** ${target}
${reconSection}
**Your assigned task:** ${task}

**Search strategy for your role:** ${strategy}

Work efficiently. Start with the highest-signal areas first. Output a FINDING line for every issue you confirm.
────────────────────────────────────────
${FINDING_FORMAT}`;
}

function buildLeadSynthesisPrompt(
  target:      string,
  subResults:  Array<{
    role:           string;
    agentName:      string;
    parsedFindings: FindingEntry[];
  }>,
  chains:      string[],
  allFindings: FindingEntry[],
): string {
  const agentSummaries = subResults.map(r => {
    const lines = r.parsedFindings.length > 0
      ? r.parsedFindings.map(f =>
          `  [${f.severity.toUpperCase()}] ${f.title}${f.location ? ` — ${f.location}` : ''}${f.cve ? ` (${f.cve})` : ''}`
        ).join('\n')
      : '  (no structured findings)';
    return `### ${roleLabel(r.role)} (${r.agentName}) — ${r.parsedFindings.length} finding(s)\n${lines}`;
  }).join('\n\n');

  const chainSection = chains.length > 0
    ? `\n**Attack chains confirmed by 2+ agents — these warrant elevated priority:**\n${chains.join('\n')}\n`
    : '\n*(No cross-agent chains detected in this run.)*\n';

  const bySev = SEV_ORDER
    .map(sev => {
      const n = allFindings.filter(f => f.severity === sev).length;
      return n > 0 ? `${n} ${sev}` : null;
    })
    .filter(Boolean)
    .join(', ');

  return `You are the **Lead Security Analyst**. Your team has completed their assessments of **${target}**.

**Total findings across all agents:** ${allFindings.length} (${bySev || 'none'})

${agentSummaries}
${chainSection}
---

**Your synthesis task:**
1. Write a final executive security report. Do NOT just re-list individual agent findings — identify what they mean together.
2. For confirmed chains (where one finding enables another), output a FINDING line with severity reflecting the combined exploit path.
3. State the overall risk posture: Critical / High / Medium / Low — with a one-sentence justification.
4. Write a prioritized remediation roadmap:
   - **Immediate (24–48h):** What must be fixed before next deploy
   - **Short-term (1–2 weeks):** What reduces the most risk with moderate effort
   - **Long-term (1–3 months):** Architectural or process improvements

The individual findings are already recorded. Your value is the synthesis — attack chains, correlated risk, and clear priorities.
────────────────────────────────────────
${FINDING_FORMAT}`;
}

// ── Run a single agent and persist results ────────────────────────────────────

interface SingleRunResult {
  runId:       string;
  fullText:    string;
  findings:    FindingEntry[];
  delegations: DelegationEntry[];
  tokens:      number;
  error?:      string;
}

async function runAgent(opts: {
  deploymentId:   string;
  deploymentPort: number;
  agentId:        string;
  agentName:      string;
  agentUserId:    string;
  teamRunId:      string;
  parentRunId?:   string;
  role:           string;
  message:        string;
  timeoutMs?:     number;
}): Promise<SingleRunResult> {
  const {
    deploymentId, deploymentPort, agentId, agentName, agentUserId,
    teamRunId, parentRunId, role, message, timeoutMs,
  } = opts;

  const run = await prisma.agentRun.create({
    data: { deploymentId, teamRunId, parentRunId: parentRunId ?? null, role, status: 'running' },
  });

  await prisma.chatMessage.create({
    data: { runId: run.id, role: 'user', content: message },
  });

  const result = await collectAgentRun({
    runId: run.id,
    deploymentPort,
    message,
    timeoutMs: timeoutMs ?? ROLE_TIMEOUT_MS[role],
  });

  if (!result.ok) {
    await prisma.agentRun.update({ where: { id: run.id }, data: { status: 'error', completedAt: new Date() } });
    await prisma.chatMessage.create({ data: { runId: run.id, role: 'assistant', content: `Error: ${result.error}` } });
    return { runId: run.id, fullText: '', findings: [], delegations: [], tokens: 0, error: result.error };
  }

  const { fullText, tokens, toolCalls, findings, delegations } = result.data;

  if (findings.length > 0) {
    await saveFindings({ agentId, runId: run.id, findings });
  }

  await prisma.chatMessage.create({
    data: {
      runId:      run.id,
      role:       'assistant',
      content:    fullText,
      toolCalls:  toolCalls.length > 0 ? (toolCalls as object[]) : undefined,
      tokensUsed: tokens,
    },
  });

  await prisma.agentRun.update({
    where: { id: run.id },
    data:  { status: 'completed', completedAt: new Date(), tokensUsed: { increment: tokens } },
  });

  void agentName; void agentUserId;

  return { runId: run.id, fullText, findings, delegations, tokens };
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function fireTeamRun(teamRunId: string): Promise<void> {
  const deadline = setTimeout(async () => {
    await prisma.teamRun.updateMany({
      where: { id: teamRunId, status: 'running' },
      data:  { status: 'error', phase: 'done', completedAt: new Date(), report: 'Team run exceeded the maximum allowed time and was cancelled.' },
    });
  }, TEAM_RUN_TIMEOUT_MS);

  try {
    await _fireTeamRun(teamRunId);
  } finally {
    clearTimeout(deadline);
  }
}

async function _fireTeamRun(teamRunId: string): Promise<void> {
  const teamRun = await prisma.teamRun.findUnique({
    where:   { id: teamRunId },
    include: {
      team: {
        include: {
          members: {
            orderBy: { order: 'asc' },
            include: {
              agent: {
                include: {
                  deployments: {
                    where:   { status: 'running' },
                    orderBy: { createdAt: 'desc' },
                    take:    1,
                  },
                },
              },
            },
          },
        },
      },
    },
  });

  if (!teamRun) return;

  type Member = typeof teamRun.team.members[number];

  const members = teamRun.team.members;
  const lead    = members.find((m: Member) => m.role === 'lead');

  async function failRun(msg: string) {
    await prisma.teamRun.update({
      where: { id: teamRunId },
      data:  { status: 'error', phase: 'done', completedAt: new Date(), report: msg },
    });
  }

  if (!lead) { await failRun('Team has no lead agent assigned.'); return; }

  const leadDeployment = lead.agent.deployments[0];
  if (!leadDeployment?.port) { await failRun('Lead agent is not currently running. Deploy it first.'); return; }

  const subMembers = members.filter((m: Member) => m.role !== 'lead');
  const roster     = members.map((m: Member) => ({
    role:        m.role,
    agentName:   m.agent.name,
    description: m.agent.description,
  }));

  // ── Phase 1: Lead plans, extracts recon, delegates ───────
  await prisma.teamRun.update({ where: { id: teamRunId }, data: { phase: 'planning' } });

  const leadPlanResult = await runAgent({
    deploymentId:   leadDeployment.id,
    deploymentPort: leadDeployment.port,
    agentId:        lead.agent.id,
    agentName:      lead.agent.name,
    agentUserId:    lead.agent.userId,
    teamRunId,
    role:           'lead',
    message:        buildLeadPlanPrompt(teamRun.target, roster),
  });

  const leadPlanRunId = leadPlanResult.runId;

  // Extract the Lead's attack surface recon to hand off to sub-agents.
  const recon = extractRecon(leadPlanResult.fullText);

  // ── Phase 2: Sub-agents run in parallel ──────────────────
  await prisma.teamRun.update({ where: { id: teamRunId }, data: { phase: 'delegating' } });

  const taskMap = new Map<string, string>();
  for (const d of leadPlanResult.delegations) {
    taskMap.set(d.role, d.task);
  }
  for (const m of subMembers) {
    if (!taskMap.has(m.role)) {
      taskMap.set(m.role, `Perform a thorough ${roleLabel(m.role)} assessment on: ${teamRun.target}`);
    }
  }

  type SubResult = {
    role:           string;
    agentName:      string;
    text:           string;
    findingCount:   number;
    parsedFindings: FindingEntry[];
  };
  const subResults: SubResult[] = [];

  await Promise.all(subMembers.map(async (m: Member) => {
    const dep = m.agent.deployments[0];
    if (!dep?.port) {
      subResults.push({
        role:           m.role,
        agentName:      m.agent.name,
        text:           `Agent "${m.agent.name}" is not running (no active deployment).`,
        findingCount:   0,
        parsedFindings: [],
      });
      return;
    }

    const task   = taskMap.get(m.role) ?? `Assess target: ${teamRun.target}`;
    const prompt = buildSubAgentPrompt(teamRun.target, m.role, task, recon);

    const r = await runAgent({
      deploymentId:   dep.id,
      deploymentPort: dep.port,
      agentId:        m.agent.id,
      agentName:      m.agent.name,
      agentUserId:    m.agent.userId,
      teamRunId,
      parentRunId:    leadPlanRunId,
      role:           m.role,
      message:        prompt,
    });

    // Parse FINDING: lines from text in addition to SSE-emitted findings.
    // Some Hermes versions emit findings only in token stream, not as SSE events.
    const textFindings    = parseFindings(stripAnsi(r.fullText));
    const combinedFindings = [
      ...r.findings,
      ...textFindings.filter(tf =>
        !r.findings.some(ef => ef.title === tf.title && ef.location === tf.location)
      ),
    ];

    subResults.push({
      role:           m.role,
      agentName:      m.agent.name,
      text:           stripAnsi(r.fullText),
      findingCount:   combinedFindings.length,
      parsedFindings: combinedFindings,
    });
  }));

  // ── Correlate findings across agents ─────────────────────
  const { deduped: allDeduped, chains } = deduplicateAndCorrelate(
    subResults.map(r => ({ role: r.role, findings: r.parsedFindings })),
  );

  // ── Phase 3: Lead synthesizes ────────────────────────────
  await prisma.teamRun.update({ where: { id: teamRunId }, data: { phase: 'synthesizing' } });

  let finalReport = '';

  if (subResults.length > 0) {
    const freshLead = await prisma.deployment.findFirst({
      where:  { id: leadDeployment.id, status: 'running' },
      select: { id: true, port: true },
    });

    if (!freshLead?.port) {
      // Lead went offline — store sub-agent results + correlation as partial report
      const partialReport = [
        chains.length > 0 ? `## Attack Chains\n${chains.join('\n')}` : '',
        subResults
          .map(r => `### ${roleLabel(r.role)} (${r.agentName})\n\n${r.text || '*(No output)*'}`)
          .join('\n\n---\n\n'),
      ].filter(Boolean).join('\n\n');

      await prisma.teamRun.update({
        where: { id: teamRunId },
        data: {
          status:      'completed',
          phase:       'done',
          report:      `[Lead agent went offline before synthesis. Correlation and sub-agent reports below:]\n\n${partialReport}`,
          completedAt: new Date(),
        },
      });
      return;
    }

    const synthResult = await runAgent({
      deploymentId:   freshLead.id,
      deploymentPort: freshLead.port,
      agentId:        lead.agent.id,
      agentName:      lead.agent.name,
      agentUserId:    lead.agent.userId,
      teamRunId,
      parentRunId:    leadPlanRunId,
      role:           'lead',
      message:        buildLeadSynthesisPrompt(teamRun.target, subResults, chains, allDeduped),
    });

    finalReport = synthResult.fullText;

    // Fallback: if the Lead synthesis produced no FINDING lines and no prose,
    // construct a report directly from the deduplicated sub-agent findings so
    // the user always gets a usable output.
    if (!finalReport.trim()) {
      const fallbackLines = allDeduped
        .map(f => `FINDING: ${JSON.stringify(f)}`)
        .join('\n');
      const chainSection = chains.length > 0
        ? `\n## Attack Chains\n${chains.join('\n')}\n`
        : '';
      finalReport = [
        `## Security Assessment — ${teamRun.target}`,
        chainSection,
        `## Findings (${allDeduped.length} total, deduplicated across all agents)`,
        fallbackLines || '*(No findings recorded)*',
      ].join('\n\n');
    }
  } else {
    finalReport = leadPlanResult.fullText;
  }

  // ── Phase 4: Done ────────────────────────────────────────
  await prisma.teamRun.update({
    where: { id: teamRunId },
    data:  { status: 'completed', phase: 'done', report: finalReport, completedAt: new Date() },
  });
}
