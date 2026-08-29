/**
 * CICDScanner Agent
 * ==================
 *
 * Detect security issues in CI/CD pipeline configurations.
 * Based on OWASP Top 10 CI/CD Security Risks.
 *
 * Scans: GitHub Actions, GitLab CI, Jenkins, CircleCI,
 *        Bitbucket Pipelines, Azure DevOps.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

const PATTERNS = [
  // ── CICD-SEC-4: Poisoned Pipeline Execution ────────────────────────────────
  {
    rule: 'CICD_PR_TARGET_CHECKOUT',
    title: 'CI/CD: pull_request_target with PR Checkout',
    regex: /\bpull_request_target\b/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'CICD-SEC-4',
    confidence: 'medium',
    description: 'pull_request_target trigger detected. Runs with base branch privileges and can be exploited if combined with PR checkout.',
    fix: 'Use pull_request trigger instead, or never checkout PR branch in pull_request_target',
  },
  {
    rule: 'CICD_WORKFLOW_RUN',
    title: 'CI/CD: Unrestricted workflow_run Trigger',
    regex: /workflow_run[\s\S]{0,200}types:\s*\[?\s*completed/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'CICD-SEC-4',
    confidence: 'medium',
    description: 'workflow_run trigger can execute with elevated permissions from a completed workflow.',
    fix: 'Add conditions to check the source workflow and event',
  },

  // ── CICD-SEC-2: Inadequate Identity and Access Management ──────────────────
  {
    rule: 'CICD_EXCESSIVE_PERMISSIONS',
    title: 'CI/CD: Write-All Permissions',
    regex: /permissions\s*:\s*write-all/g,
    severity: 'high',
    cwe: 'CWE-250',
    owasp: 'CICD-SEC-2',
    description: 'Workflow has write-all permissions. Apply least privilege.',
    fix: 'Set granular permissions: permissions: { contents: read, pull-requests: write }',
  },
  {
    rule: 'CICD_PERMISSIVE_TOKEN',
    title: 'CI/CD: Permissive GITHUB_TOKEN',
    regex: /permissions\s*:\s*\n\s*contents\s*:\s*write/g,
    severity: 'medium',
    cwe: 'CWE-250',
    owasp: 'CICD-SEC-2',
    confidence: 'low',
    description: 'GITHUB_TOKEN has contents: write. Consider if read is sufficient.',
    fix: 'Use contents: read unless the workflow needs to push commits',
  },

  // ── CICD-SEC-6: Insufficient Credential Hygiene ────────────────────────────
  {
    rule: 'CICD_SECRET_IN_LOG',
    title: 'CI/CD: Secret Potentially Logged',
    regex: /echo\s+\$\{\{\s*secrets\./g,
    severity: 'critical',
    cwe: 'CWE-532',
    owasp: 'CICD-SEC-6',
    description: 'Secret printed via echo may appear in CI logs. GitHub masks known secrets but not all.',
    fix: 'Never echo secrets. Use them only in environment variables or file writes.',
  },
  {
    rule: 'CICD_HARDCODED_SECRET',
    title: 'CI/CD: Hardcoded Secret in Workflow',
    regex: /(?:api[_-]?key|token|password|secret)\s*[:=]\s*["'][a-zA-Z0-9_-]{20,}["']/gi,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'CICD-SEC-6',
    description: 'Hardcoded secret in CI/CD configuration. Use repository/organization secrets.',
    fix: 'Move to GitHub/GitLab secrets: ${{ secrets.MY_SECRET }}',
  },

  // ── CICD-SEC-8: Ungoverned Usage of 3rd Party Services ────────────────────
  {
    rule: 'CICD_UNPINNED_ACTION',
    title: 'CI/CD: Unpinned GitHub Action (mutable tag)',
    regex: /uses\s*:\s*[\w.-]+\/[\w.-]+@(?![\da-f]{40}\b)[\w./-]+/g,
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'CICD-SEC-8',
    description: 'GitHub Action not pinned to a full commit SHA. Mutable tags (@main, @master, @v1, @v1.2.3) can be force-pushed to malicious commits — the technique used in the 2026 Trivy/TeamPCP attack that compromised 10,000+ pipelines.',
    fix: 'Pin to full 40-char commit SHA: uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2',
  },
  {
    rule: 'CICD_UNVERIFIED_ACTION',
    title: 'CI/CD: Unverified Third-Party Action',
    regex: /uses\s*:\s*(?!actions\/|github\/|docker\/)[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+@/g,
    severity: 'medium',
    cwe: 'CWE-829',
    owasp: 'CICD-SEC-8',
    confidence: 'low',
    description: 'Third-party GitHub Action not from verified publisher. Review source code.',
    fix: 'Pin to commit SHA, review the action source, or use an official alternative',
  },

  // ── CICD-SEC-3: Dependency Chain Abuse ─────────────────────────────────────
  {
    rule: 'CICD_NO_LOCKFILE_INSTALL',
    title: 'CI/CD: Install Without Lockfile',
    regex: /npm\s+install(?!\s+--(?:frozen|ci))|yarn\s+(?!--frozen-lockfile)/g,
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'CICD-SEC-3',
    confidence: 'medium',
    description: 'CI runs npm install without --frozen-lockfile. Builds are non-deterministic.',
    fix: 'Use npm ci (not npm install) or yarn --frozen-lockfile in CI',
  },

  // ── CICD-SEC-7: Insecure System Configuration ─────────────────────────────
  {
    rule: 'CICD_SELF_HOSTED_RUNNER',
    title: 'CI/CD: Self-Hosted Runner',
    regex: /runs-on\s*:\s*self-hosted/g,
    severity: 'medium',
    cwe: 'CWE-250',
    owasp: 'CICD-SEC-7',
    confidence: 'medium',
    description: 'Self-hosted runners may persist state between jobs. Use ephemeral runners.',
    fix: 'Use ephemeral self-hosted runners that are cleaned after each job',
  },

  // ── CICD-SEC-9: Improper Artifact Integrity Validation ────────────────────
  {
    rule: 'CICD_NO_ARTIFACT_VERIFY',
    title: 'CI/CD: Artifact Used Without Verification',
    regex: /download-artifact|cache@|restore-keys/g,
    severity: 'low',
    cwe: 'CWE-345',
    owasp: 'CICD-SEC-9',
    confidence: 'low',
    description: 'Artifacts/caches used without integrity verification. Consider adding checksums.',
    fix: 'Verify artifact integrity with checksums or signatures',
  },

  // ── CICD-SEC-6: Credential Exfiltration via Network ───────────────────────
  {
    rule: 'CICD_ENV_EXFILTRATION',
    title: 'CI/CD: Potential Secret/Env Exfiltration',
    regex: /(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\$\{\{\s*(?:secrets\.|env\.)[^}]+\}\}/g,
    severity: 'critical',
    cwe: 'CWE-200',
    owasp: 'CICD-SEC-6',
    description: 'Network call with a GitHub expression referencing secrets or env vars. This is the exfiltration technique used in the 2026 Trivy/CanisterWorm attack — stolen credentials were encrypted and POSTed to an attacker-controlled endpoint.',
    fix: 'Never pass secrets directly to curl/wget arguments. Use environment variables and verify the destination URL.',
  },

  // ── CICD-SEC-2: OIDC Trust Misconfiguration ────────────────────────────────
  {
    rule: 'CICD_OIDC_BROAD_SUBJECT',
    title: 'CI/CD: Overly Broad OIDC Subject Claim',
    regex: /subject(?:_claim)?\s*[:=]\s*["']repo:[^"']*[*][^"']*["']/gi,
    severity: 'critical',
    cwe: 'CWE-284',
    owasp: 'CICD-SEC-2',
    description: 'OIDC subject claim uses a wildcard. Any repository or branch matching the pattern can assume this cloud role. In 2026, UNC6426 used a wildcard OIDC trust to escalate from a stolen GitHub PAT to AWS administrator in 72 hours.',
    fix: 'Restrict the subject claim to a specific repo and branch: repo:owner/repo:ref:refs/heads/main',
  },
  {
    rule: 'CICD_OIDC_MISSING_SUBJECT',
    title: 'CI/CD: OIDC Token Request Without Subject Restriction',
    regex: /id-token\s*:\s*write/g,
    severity: 'medium',
    cwe: 'CWE-284',
    owasp: 'CICD-SEC-2',
    confidence: 'low',
    description: 'Workflow requests OIDC token (id-token: write). Verify the cloud trust policy restricts the subject claim to specific repos/branches to prevent privilege escalation.',
    fix: 'Ensure the cloud IAM trust policy sets a specific sub condition, not a wildcard.',
  },

  // ── General CI/CD Issues ───────────────────────────────────────────────────
  {
    rule: 'CICD_CURL_PIPE_BASH',
    title: 'CI/CD: curl | bash Anti-Pattern',
    regex: /curl\s+[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)/g,
    severity: 'critical',
    cwe: 'CWE-829',
    description: 'Piping curl to shell is dangerous. Download, verify, then execute.',
    fix: 'Download file first, verify checksum, then execute: curl -o script.sh && sha256sum -c && bash script.sh',
  },
  {
    rule: 'CICD_SCRIPT_INJECTION',
    title: 'CI/CD: Script Injection via Expressions',
    regex: /run\s*:\s*[^\n]*\$\{\{\s*(?:github\.event\.(?:issue|comment|pull_request|review)\.(?:title|body|head\.ref|label))/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'CICD-SEC-4',
    description: 'GitHub expression in run step. Attacker-controlled values can inject shell commands.',
    fix: 'Use environment variables: env: TITLE: ${{ github.event.issue.title }} then run: echo "$TITLE"',
  },

  // ── AI Agent CLI — dangerous flags in CI ──────────────────────────────────
  {
    rule: 'CICD_AGENT_SKIP_PERMISSIONS',
    title: 'CI/CD: AI Agent Running Without Permission Checks',
    regex: /(?:--dangerously-skip-permissions|--skip-permissions|permissionMode\s*[=:]\s*["']?danger-full-access["']?)/g,
    severity: 'critical',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    description: 'AI agent CLI flag disables all permission checks. In CI, this means any prompt injection in workspace files can execute arbitrary commands with no confirmation gate.',
    fix: 'Remove --dangerously-skip-permissions. Use --permission-mode=workspace-write for CI automation or scope tool access with --allowedTools.',
  },
  {
    rule: 'CICD_AGENT_INSECURE_PROVIDER',
    title: 'CI/CD: AI Agent Routing to Non-TLS Provider',
    regex: /(?:OPENAI_BASE_URL|ANTHROPIC_BASE_URL|XAI_BASE_URL|CLAUDE_CODE_USE_OPENAI)\s*=\s*["']?http:\/\/(?!localhost|127\.0\.0\.1|::1)/g,
    severity: 'high',
    cwe: 'CWE-319',
    owasp: 'A02:2021',
    description: 'AI agent provider URL uses plain HTTP for a non-localhost endpoint. All prompts, code context, and model responses are transmitted unencrypted in CI.',
    fix: 'Use https:// for all non-localhost AI provider base URLs.',
  },
  {
    rule: 'CICD_OPENCLAUDE_IN_CI',
    title: 'CI/CD: openclaude Running in CI Pipeline',
    regex: /(?:^|\s)openclaude\s/gm,
    severity: 'medium',
    cwe: 'CWE-1188',
    owasp: 'ASI03',
    description: 'openclaude (Claude Code fork with OpenAI-compatible shim) is invoked in CI. Verify OPENAI_BASE_URL is https://, OPENAI_API_KEY is stored as a secret, and .openclaude-profile.json is not committed.',
    fix: 'Ensure OPENAI_API_KEY is a CI secret, OPENAI_BASE_URL uses https://, and .openclaude-profile.json is gitignored.',
  },
  {
    rule: 'CICD_CLAW_DANGER_MODE',
    title: 'CI/CD: claw-code Running in Danger Mode',
    regex: /(?:^|\s)claw\s[^\n]*--dangerously-skip-permissions/gm,
    severity: 'critical',
    cwe: 'CWE-269',
    owasp: 'ASI03',
    description: 'claw-code (Rust/Python Claude Code rewrite) is invoked with --dangerously-skip-permissions in CI. Any prompt injection in the workspace executes without confirmation.',
    fix: 'Remove --dangerously-skip-permissions. Use --permission-mode=workspace-write for CI automation.',
  },

  // ── Branch Name Injection (Codex-class attack, CVE pending) ──────────────
  {
    rule: 'CICD_BRANCH_NAME_INJECTION',
    title: 'CI/CD: Unsanitized Branch Name in Shell Command',
    regex: /(?:git\s+(?:checkout|switch|clone\s+--branch|fetch\s+origin))\s+(?:\$\{\{[^}]*(?:head\.ref|branch|ref_name)[^}]*\}\}|\$(?:BRANCH|GITHUB_HEAD_REF|CI_COMMIT_BRANCH|BITBUCKET_BRANCH))/gi,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'CICD-SEC-4',
    description: 'Branch name from an external source (PR head ref, environment variable) is passed directly to a git shell command without sanitization. Attackers can create branches with names containing shell metacharacters to inject arbitrary commands. This is the exact attack vector used in the OpenAI Codex GitHub token theft (BeyondTrust Phantom Labs, Mar 2026).',
    fix: 'Sanitize branch names: strip shell metacharacters, use -- to separate git options from arguments, or use actions/checkout which handles this safely.',
  },
  {
    rule: 'CICD_BRANCH_NAME_IN_RUN',
    title: 'CI/CD: Branch Name Interpolated in run Step',
    regex: /run\s*:\s*[^\n]*\$\{\{\s*(?:github\.head_ref|github\.ref_name)\s*\}\}/g,
    severity: 'high',
    cwe: 'CWE-78',
    owasp: 'CICD-SEC-4',
    description: 'GitHub expression for branch name used directly in a run step. An attacker can craft a branch name with shell injection payloads. This pattern was exploited in the OpenAI Codex vulnerability to steal GitHub OAuth tokens.',
    fix: 'Assign to an environment variable first: env: BRANCH: ${{ github.head_ref }}, then reference as "$BRANCH" (quoted) in the run step.',
  },
];

// =============================================================================
// UNGOVERNED CONTINUOUS INGESTION
//
// A pipeline that resolves a mutable third-party reference, builds it, and
// deploys the result to running infrastructure with no human gate hands
// upstream control of your production with under a day of latency.
//
// None of those steps is dangerous alone, which is why the line-by-line rules
// above cannot see it: the finding is the *combination*, spread across a file.
// This section extracts signals per workflow and scores the chain.
// =============================================================================

// (A) Mutable references. `branch` tracks a moving branch — anything upstream
// merges ships. `release` tracks the newest published release, which still
// auto-ingests but has a human publish step upstream, so it scores lower.
// GitHub repo references, from either the API host or the web host, so the
// owner can be identified wherever the URL is assembled.
const GH_REPO_RE = /github\.com[/:](?:repos\/)?([\w.-]+)\/([\w.-]+)/gi;

// Endpoints that name a moving target. Matched independently of the repo URL
// because pipelines routinely build the URL from a variable
// (`API="https://api.github.com/repos/o/r"` … `"$API/releases/latest"`), and a
// regex expecting one contiguous string silently misses every such workflow.
const MUTABLE_ENDPOINT_SIGNALS = [
  { kind: 'branch',  re: /\/commits\/(?:main|master|HEAD)\b/gi },
  { kind: 'release', re: /\/releases\/latest\b/gi },
];

// Mutable references that stand alone, with no GitHub repo URL involved.
const MUTABLE_REF_SIGNALS = [
  { kind: 'branch',  re: /\bgit\s+clone\b(?![^\n]*--branch\s+v?\d)[^\n]*github\.com\/([\w.-]+)\/([\w.-]+)/gi, owner: 1 },
  { kind: 'branch',  re: /\bpip\s+install\b[^\n]*git\+https?:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:@(?:HEAD|main|master))?["'\s]/gi, owner: 1 },
  { kind: 'branch',  re: /^\s*FROM\s+(?!scratch)([\w./-]+):latest\b/gim, owner: null },
  { kind: 'branch',  re: /\bdocker\s+pull\b[^\n]*:latest\b/gi, owner: null },
  { kind: 'branch',  re: /\bnpm\s+(?:i|install)\b[^\n]*@latest\b/gi, owner: null },
];

// (C) The artifact leaves CI and reaches something that serves traffic.
const DEPLOY_SIGNALS = [
  // `push: true`, and also `push: ${{ ... }}` — a push guarded by an
  // expression still pushes on the default path. Only a literal `false` is
  // conclusively not a publish.
  /\bpush:\s*(?!false\b)(?:true\b|\$\{\{)/i,
  /\bdocker\s+push\b/i,
  /\bnpm\s+publish\b/i,
  /\bkubectl\s+(?:apply|rollout|set\s+image)\b/i,
  /\baws\s+ecs\s+update-service\b/i,
  /\b(?:flyctl|fly)\s+deploy\b/i,
  /\bvercel\b[^\n]*--prod\b/i,
  /\b(?:ssh|scp)\s+[^\n]*@/i,
  // A POST to something named like a deploy hook. Deliberately narrow: an
  // arbitrary curl to an arbitrary host is not evidence of a deploy, and
  // guessing costs more in false positives than it buys in coverage.
  /\bcurl\b[^\n]*-X\s*POST[^\n]*(?:deploy|rollout|update-image|restart|release)\b/i,
];

// (D) Signals that a human stands between the build and production.
const GATE_SIGNALS = [
  /^\s*environment:\s*\S/im,          // GitHub environment — where approval rules live
  /\bpeter-evans\/create-pull-request\b/i,
  /\bgh\s+pr\s+create\b/i,
  /\bcreate-pull-request\b/i,
];

// Targets that are not production. Deliberately anchored to places a target is
// actually named — an `environment:`, an image tag, a job id. Matching these
// words anywhere in the file is useless: `2>/dev/null` alone would downgrade a
// genuine production deploy.
const NON_PROD_SIGNALS = [
  /^\s*environment:\s*['"]?(?:staging|dev|development|preview|sandbox|qa)\b/im,
  /:(?:staging|dev|development|preview|sandbox|qa)\b(?![\w/-])/i,
  /^\s*(?:deploy[-_])?(?:staging|dev|preview)\s*:\s*$/im,
];

/** Owner of the repo being scanned, so a workflow tracking its *own* HEAD is
 *  not mistaken for third-party ingestion. Best-effort: absent this we treat
 *  refs as third-party, which is the safe direction for a security check. */
function selfOwner(rootPath) {
  try {
    const cfg = fs.readFileSync(path.join(rootPath, '.git', 'config'), 'utf-8');
    const m = cfg.match(/url\s*=\s*[^\n]*github\.com[/:]([\w.-]+)\//i);
    return m ? m[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Extract the chain signals from one workflow file. */
function extractChainSignals(rawContent, self) {
  // Shell steps wrap long commands across lines with a trailing backslash, so
  // a `curl ... \` and the URL it posts to land on different lines. Join those
  // continuations first: without this, every multi-line deploy command is
  // invisible to a single-line pattern. Line numbers are computed against the
  // original text so findings still point at the real line.
  const content = rawContent.replace(/\\\r?\n\s*/g, ' ');
  const lineOf = (idx) => rawContent.slice(0, Math.min(idx, rawContent.length)).split('\n').length;
  const refs = [];

  // Which third-party repositories does this workflow talk to at all?
  const thirdPartyRepos = [];
  GH_REPO_RE.lastIndex = 0;
  let r;
  while ((r = GH_REPO_RE.exec(content)) !== null) {
    const owner = (r[1] || '').toLowerCase();
    // Tracking your own repository is ordinary; the risk is ingesting
    // someone else's code. `actions/*` are handled by the pinning rules.
    if (!owner || owner === self || owner === 'actions') continue;
    thirdPartyRepos.push({ owner, repo: r[2], line: lineOf(r.index) });
  }

  // Pair a third-party repo with any moving-target endpoint in the same file.
  // File-scoped rather than line-scoped so a URL split across a variable
  // assignment and its use is still seen.
  if (thirdPartyRepos.length > 0) {
    for (const sig of MUTABLE_ENDPOINT_SIGNALS) {
      sig.re.lastIndex = 0;
      let m;
      while ((m = sig.re.exec(content)) !== null) {
        const repo = thirdPartyRepos[0];
        refs.push({
          kind: sig.kind,
          owner: repo.owner,
          line: lineOf(m.index),
          matched: `${repo.owner}/${repo.repo}${m[0].trim()}`.slice(0, 160),
        });
      }
    }
  }

  for (const sig of MUTABLE_REF_SIGNALS) {
    sig.re.lastIndex = 0;
    let m;
    while ((m = sig.re.exec(content)) !== null) {
      const owner = sig.owner ? (m[sig.owner] || '').toLowerCase() : null;
      if (owner && self && owner === self) continue;
      refs.push({ kind: sig.kind, owner, line: lineOf(m.index), matched: m[0].trim().slice(0, 160) });
      if (!sig.re.global) break;
    }
  }

  const deploys = [];
  for (const re of DEPLOY_SIGNALS) {
    const m = re.exec(content);
    if (m) deploys.push({ line: content.slice(0, m.index).split('\n').length, matched: m[0].trim().slice(0, 160) });
  }

  return {
    refs,
    deploys,
    scheduled: /^\s*schedule:/m.test(content) || /^\s*on:\s*\n(?:[^\n]*\n)*?\s*schedule:/m.test(content),
    gated: GATE_SIGNALS.some(re => re.test(content)),
    nonProd: NON_PROD_SIGNALS.some(re => re.test(content)),
  };
}

// =============================================================================
// PRIVILEGED PR / ARTIFACT HANDOFFS
//
// GitHub's dangerous CI/CD cases usually appear as chains: a privileged event
// runs, pulls in code or artifacts influenced by an untrusted PR, then executes
// or deploys them. The line rules above catch many single bad statements; this
// pass catches the handoff.
// =============================================================================

const PR_TARGET_EVENT_RE = /\bpull_request_target\b/;
const UNSAFE_PR_CHECKOUT_RE =
  /uses\s*:\s*actions\/checkout@[^\n]+[\s\S]{0,360}(?:\bref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}|\brepository\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.repo\.full_name\s*\}\})/i;
const UNSAFE_PR_GIT_RE =
  /\bgit\s+(?:checkout|switch|fetch|clone)\b[^\n]*(?:github\.event\.pull_request\.head|github\.head_ref|GITHUB_HEAD_REF)/i;
const TRUSTS_UNSAFE_CHECKOUT_ACTION_RE =
  /\ballow-unsafe-pr-checkout\s*:\s*true\b/i;

const CODE_EXEC_AFTER_CHECKOUT_RE =
  /(?:^|\n)\s*-?\s*run\s*:\s*(?:[>|]\s*)?[\s\S]{0,700}\b(?:npm|pnpm|yarn|bun)\s+(?:ci|install|test|run|exec)|(?:^|\n)\s*-?\s*run\s*:\s*(?:[>|]\s*)?[\s\S]{0,700}\b(?:pip\s+install|pytest|python\s+setup\.py|make\b|bash\b|sh\b|chmod\s+\+x)/i;

const WORKFLOW_RUN_RE = /\bworkflow_run\b[\s\S]{0,240}\bcompleted\b/i;
const ARTIFACT_DOWNLOAD_RE =
  /(?:uses\s*:\s*actions\/download-artifact@|gh\s+run\s+download|download-artifact\b)/i;
const ARTIFACT_EXEC_RE =
  /(?:^|\n)\s*-?\s*run\s*:\s*(?:[>|]\s*)?[\s\S]{0,900}\b(?:chmod\s+\+x|bash\s+\.?\/|sh\s+\.?\/|python\s+\.?\/|node\s+\.?\/|npm\s+(?:ci|install|test|run)|pnpm\s+(?:install|test|run)|yarn\s+(?:install|test|run)|bun\s+(?:install|test|run)|docker\s+load|kubectl\s+apply)\b/i;
const ARTIFACT_VERIFY_RE =
  /\b(?:sha256sum|shasum|openssl\s+dgst|cosign\s+verify|gh\s+attestation\s+verify|slsa-verifier|gitsign|artifact-digest|digest\s*:)\b/i;
const PRIVILEGED_PERMISSION_RE =
  /permissions\s*:\s*(?:write-all|[\s\S]{0,280}\b(?:contents|actions|packages|id-token|pull-requests)\s*:\s*write\b)/i;
const NPM_PUBLISH_RE = /\bnpm\s+publish\b/i;
const NPM_TOKEN_ENV_RE = /\bNPM_TOKEN\b/;
const PROVENANCE_DISABLED_RE = /--provenance(?:=|\s+)false\b|provenance\s*:\s*false\b/i;
const PROVENANCE_INTENDED_RE = /--provenance\b|trusted\s+publish(?:ing)?\b/i;
const ID_TOKEN_WRITE_RE = /id-token\s*:\s*write\b/i;
const AI_ACTION_SIGNAL_RE =
  /(?:^|[/_.\s-])(?:ai|agent|llm|openai|anthropic|claude|gemini|copilot|codex|kimi|mistral|bedrock|autofix|review)(?:$|[/_.@\s-])/i;
const ACTION_USES_RE = /^\s*(?:-\s*)?uses\s*:\s*["']?([^\s"'#]+)["']?/;
const FULL_COMMIT_SHA_RE = /^[a-f0-9]{40}$/i;
const BROAD_AI_ACTION_PERMISSION_RE =
  /permissions\s*:\s*write-all\b|(?:contents|pull-requests|actions)\s*:\s*write\b/i;

function workflowAndJobScopes(lines, lineIndex) {
  const jobsIndex = lines.findIndex(line => /^\s*jobs\s*:\s*(?:#.*)?$/.test(line));
  const workflow = jobsIndex >= 0 ? lines.slice(0, jobsIndex).join('\n') : lines.join('\n');
  if (jobsIndex < 0 || lineIndex <= jobsIndex) return { workflow, job: '' };

  const jobsIndent = lines[jobsIndex].match(/^\s*/)[0].length;
  let jobStart = jobsIndex + 1;
  let jobEnd = lines.length;

  for (let index = jobsIndex + 1; index < lines.length; index += 1) {
    const uncommented = lines[index].replace(/(^|\s)#.*$/, '');
    if (!uncommented.trim()) continue;
    const indent = uncommented.match(/^\s*/)[0].length;
    if (indent <= jobsIndent) break;
    if (indent === jobsIndent + 2 && /^\s*[\w.-]+\s*:/.test(uncommented)) {
      if (index <= lineIndex) jobStart = index;
      else {
        jobEnd = index;
        break;
      }
    }
  }

  return { workflow, job: lines.slice(jobStart, jobEnd).join('\n') };
}

function firstMatchLine(rawContent, patterns) {
  for (const re of patterns) {
    re.lastIndex = 0;
    const m = re.exec(rawContent);
    if (m) {
      return {
        line: rawContent.slice(0, m.index).split('\n').length,
        matched: m[0].trim().slice(0, 180),
      };
    }
  }
  return { line: 0, matched: '' };
}

export class CICDScanner extends BaseAgent {
  constructor() {
    super('CICDScanner', 'Detect CI/CD pipeline security issues (OWASP CI/CD Top 10)', 'cicd');
  }

  /**
   * Score the ingestion chain for one workflow. Severity rises with how much
   * of the chain is present, and drops when a human is in the loop or the
   * target is not production.
   */
  scanIngestionChain(file, rootPath, self) {
    const content = this.readFile(file);
    if (!content) return [];

    const s = extractChainSignals(content, self);
    if (s.refs.length === 0) return [];

    const findings = [];
    const worst = s.refs.some(r => r.kind === 'branch') ? 'branch' : 'release';
    const ref = s.refs.find(r => r.kind === worst);
    const deploying = s.deploys.length > 0;
    const unattended = s.scheduled && !s.gated;

    if (deploying && unattended) {
      // The full chain. A branch ref means any upstream merge reaches
      // production; a release ref means any upstream publish does.
      let severity = worst === 'branch' ? 'critical' : 'high';
      if (s.nonProd) severity = severity === 'critical' ? 'high' : 'medium';

      findings.push(createFinding({
        file,
        line: ref.line,
        severity,
        category: this.category,
        rule: 'CICD_UNATTENDED_UPSTREAM_DEPLOY',
        title: `Unattended deploy of a mutable ${worst === 'branch' ? 'upstream branch' : 'upstream release'}`,
        description:
          `This workflow resolves a mutable third-party reference (${ref.matched}), builds it, and ` +
          `deploys the result on a schedule with no approval gate. Whatever upstream ${worst === 'branch' ? 'merges' : 'publishes'} ` +
          `reaches production within one scheduled interval, with nobody reviewing it. A compromise of the ` +
          `upstream repository is a compromise of your production.`,
        matched: ref.matched,
        confidence: 'medium',
        cwe: 'CWE-1357',
        owasp: 'CICD-SEC-3',
        fix:
          'Pin the upstream reference to a specific version or commit and update it deliberately. ' +
          'If it must stay automatic, put the deploying job behind a GitHub `environment:` with required ' +
          'reviewers so a human approves the rollout.',
      }));
    } else if (!s.gated) {
      // Built but not shipped straight to production: lower stakes, still
      // building code nobody pinned.
      findings.push(createFinding({
        file,
        line: ref.line,
        severity: worst === 'branch' ? 'medium' : 'low',
        category: this.category,
        rule: 'CICD_UNPINNED_UPSTREAM_BUILD',
        title: `CI builds an unpinned third-party ${worst === 'branch' ? 'branch' : 'release'}`,
        description:
          `This workflow builds from a mutable third-party reference (${ref.matched}). The code being built ` +
          `can change without any change on your side, so a passing build today says nothing about what runs tomorrow.`,
        matched: ref.matched,
        confidence: 'medium',
        cwe: 'CWE-1357',
        owasp: 'CICD-SEC-3',
        fix: 'Pin the reference to a specific version or commit SHA and bump it deliberately.',
      }));
    }

    // Independently useful: shipping to production on a schedule with nobody
    // able to stop it, whatever the source of the artifact.
    if (deploying && s.scheduled && !s.gated && !s.nonProd) {
      const d = s.deploys[0];
      findings.push(createFinding({
        file,
        line: d.line,
        severity: 'medium',
        category: this.category,
        rule: 'CICD_NO_DEPLOY_APPROVAL',
        title: 'Scheduled production deploy with no approval gate',
        description:
          'This workflow deploys on a schedule and no job declares a GitHub `environment:`, which is where ' +
          'required reviewers and wait timers are configured. Every rollout is unattended.',
        matched: d.matched,
        confidence: 'medium',
        cwe: 'CWE-284',
        owasp: 'CICD-SEC-1',
        fix: 'Add an `environment:` with required reviewers to the deploying job, or trigger rollout manually.',
      }));
    }

    return findings;
  }

  scanPrivilegedHandoffs(file) {
    const content = this.readFile(file);
    if (!content) return [];

    const findings = [];
    const hasPrTarget = PR_TARGET_EVENT_RE.test(content);
    const unsafeCheckout =
      UNSAFE_PR_CHECKOUT_RE.test(content) ||
      UNSAFE_PR_GIT_RE.test(content) ||
      TRUSTS_UNSAFE_CHECKOUT_ACTION_RE.test(content);

    if (hasPrTarget && unsafeCheckout) {
      const hit = firstMatchLine(content, [
        UNSAFE_PR_CHECKOUT_RE,
        UNSAFE_PR_GIT_RE,
        TRUSTS_UNSAFE_CHECKOUT_ACTION_RE,
      ]);

      findings.push(createFinding({
        file,
        line: hit.line,
        severity: 'critical',
        category: this.category,
        rule: 'CICD_PR_TARGET_UNSAFE_CHECKOUT',
        title: 'pull_request_target checks out untrusted PR code',
        description:
          '`pull_request_target` runs with base-repository privileges. This workflow then checks out code from the pull request head, which lets an external contributor place code inside a privileged job.',
        matched: hit.matched,
        confidence: 'high',
        cwe: 'CWE-829',
        owasp: 'CICD-SEC-4',
        fix:
          'Do not checkout or execute the PR head in `pull_request_target`. Use `pull_request` for untrusted code, or split the workflow so privileged jobs only consume reviewed, verified outputs.',
      }));

      if (CODE_EXEC_AFTER_CHECKOUT_RE.test(content)) {
        const exec = firstMatchLine(content, [CODE_EXEC_AFTER_CHECKOUT_RE]);
        findings.push(createFinding({
          file,
          line: exec.line,
          severity: 'critical',
          category: this.category,
          rule: 'CICD_PR_TARGET_EXECUTES_UNTRUSTED_CODE',
          title: 'Privileged PR workflow executes untrusted code',
          description:
            'This `pull_request_target` workflow checks out PR-controlled code and later runs package scripts, shell commands, or build/test commands. A malicious PR can execute with repository secrets and write-token permissions.',
          matched: exec.matched,
          confidence: 'high',
          cwe: 'CWE-94',
          owasp: 'CICD-SEC-4',
          fix:
            'Move code execution to a `pull_request` workflow with read-only permissions. Keep `pull_request_target` only for metadata actions such as labeling or commenting.',
        }));
      }
    }

    if (WORKFLOW_RUN_RE.test(content) && ARTIFACT_DOWNLOAD_RE.test(content) && ARTIFACT_EXEC_RE.test(content)) {
      const verified = ARTIFACT_VERIFY_RE.test(content);
      const privileged = PRIVILEGED_PERMISSION_RE.test(content);
      if (!verified) {
        const hit = firstMatchLine(content, [ARTIFACT_DOWNLOAD_RE, ARTIFACT_EXEC_RE]);
        findings.push(createFinding({
          file,
          line: hit.line,
          severity: privileged ? 'critical' : 'high',
          category: this.category,
          rule: 'CICD_WORKFLOW_RUN_UNVERIFIED_ARTIFACT_EXEC',
          title: 'workflow_run executes an unverified artifact',
          description:
            '`workflow_run` can be used to hand off from an untrusted PR workflow into a privileged workflow. This job downloads an artifact and executes it without a digest, signature, or attestation check.',
          matched: hit.matched,
          confidence: 'high',
          cwe: 'CWE-345',
          owasp: 'CICD-SEC-9',
          fix:
            'Verify artifacts with a digest, signature, or `gh attestation verify` before execution. Avoid executing artifacts produced by untrusted PR workflows in privileged jobs.',
        }));
      }
    }

    return findings;
  }
/**
   * npm publish workflows should prefer provenance/trusted publishing over
   * a long-lived NPM_TOKEN, and if provenance is intended, id-token: write
   * must actually be present or the publish step will fail (or worse,
   * silently skip provenance depending on npm version).
   *
   * YAML comments are stripped before matching — a comment merely
   * discussing "trusted publishing" or "id-token: write" must not silence
   * a real finding just because the words appear in prose.
   */
  scanNpmPublishProvenance(file) {
    const rawContent = this.readFile(file);
    if (!rawContent) return [];

    // Strip full-line and trailing YAML comments so prose mentions of the
    // trigger phrases can't mask an actual missing configuration.
    const content = rawContent
      .split('\n')
      .map(line => line.replace(/(^|\s)#.*$/, ''))
      .join('\n');

    if (!NPM_PUBLISH_RE.test(content)) return [];

    const findings = [];
    const publishHit = firstMatchLine(rawContent, [NPM_PUBLISH_RE]);

    if (PROVENANCE_DISABLED_RE.test(content)) {
      const hit = firstMatchLine(rawContent, [PROVENANCE_DISABLED_RE]);
      findings.push(createFinding({
        file,
        line: hit.line,
        severity: 'high',
        category: this.category,
        rule: 'CICD_NPM_PUBLISH_PROVENANCE_DISABLED',
        title: 'CI/CD: npm publish with provenance explicitly disabled',
        description:
          'This workflow explicitly disables npm provenance. Provenance links a published package back to the exact workflow run and commit that built it, which is what lets consumers and npm verify supply-chain integrity.',
        matched: hit.matched,
        confidence: 'high',
        cwe: 'CWE-345',
        owasp: 'CICD-SEC-9',
        fix: 'Remove the provenance=false flag/setting and publish with `npm publish --provenance` instead.',
      }));
    } else if (NPM_TOKEN_ENV_RE.test(content) && !PROVENANCE_INTENDED_RE.test(content)) {
      findings.push(createFinding({
        file,
        line: publishHit.line,
        severity: 'medium',
        category: this.category,
        rule: 'CICD_NPM_PUBLISH_NO_PROVENANCE',
        title: 'CI/CD: npm publish uses NPM_TOKEN without provenance',
        description:
          'This workflow publishes to npm using a long-lived NPM_TOKEN secret, with no mention of provenance or trusted publishing. A leaked NPM_TOKEN can be used to publish malicious versions indefinitely, and consumers have no cryptographic way to verify the package actually came from this repository\'s CI.',
        matched: publishHit.matched,
        confidence: 'medium',
        cwe: 'CWE-345',
        owasp: 'CICD-SEC-6',
        fix: 'Publish with `npm publish --provenance` (requires `id-token: write` permission), or migrate to npm trusted publishing to remove the long-lived token entirely.',
      }));
    }

    if (PROVENANCE_INTENDED_RE.test(content) && !ID_TOKEN_WRITE_RE.test(content)) {
      findings.push(createFinding({
        file,
        line: publishHit.line,
        severity: 'medium',
        category: this.category,
        rule: 'CICD_NPM_PUBLISH_MISSING_ID_TOKEN',
        title: 'CI/CD: npm provenance intended but id-token permission missing',
        description:
          'This workflow references provenance or trusted publishing, but no job declares `id-token: write`. Provenance/trusted publishing depends on an OIDC token that this permission grants; without it the publish step cannot generate a valid attestation.',
        matched: publishHit.matched,
        confidence: 'medium',
        cwe: 'CWE-284',
        owasp: 'CICD-SEC-2',
        fix: 'Add `permissions: { id-token: write }` to the publish job.',
      }));
    }

    return findings;
  }

  /**
   * AI review and autofix actions routinely receive repository and PR context.
   * A mutable action ref lets an upstream change turn that access into code
   * execution without any change to the consuming repository.
   */
  scanUnpinnedAiActions(file) {
    const rawContent = this.readFile(file);
    if (!rawContent) return [];

    const lines = rawContent.split('\n');
    const contentWithoutComments = lines
      .map(line => line.replace(/(^|\s)#.*$/, ''))
      .join('\n');
    const privilegedEvent = PR_TARGET_EVENT_RE.test(contentWithoutComments);
    const findings = [];

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index].replace(/(^|\s)#.*$/, '');
      const uses = ACTION_USES_RE.exec(line);
      if (!uses) continue;

      const action = uses[1];
      if (action.startsWith('./') || action.startsWith('docker://')) continue;

      let stepName = '';
      for (let previous = index - 1; previous >= 0; previous -= 1) {
        const candidate = lines[previous].replace(/(^|\s)#.*$/, '');
        const name = /^\s*-\s*name\s*:\s*["']?(.+?)["']?\s*$/.exec(candidate);
        if (name) {
          stepName = name[1];
          break;
        }
        if (/^\s*-\s*(?:uses|run)\s*:/.test(candidate)) break;
      }

      if (!AI_ACTION_SIGNAL_RE.test(action) && !AI_ACTION_SIGNAL_RE.test(stepName)) continue;

      const at = action.lastIndexOf('@');
      const ref = at >= 0 ? action.slice(at + 1) : '';
      if (FULL_COMMIT_SHA_RE.test(ref)) continue;

      const scopes = workflowAndJobScopes(lines, index);
      const broadPermissions =
        BROAD_AI_ACTION_PERMISSION_RE.test(scopes.workflow) ||
        BROAD_AI_ACTION_PERMISSION_RE.test(scopes.job);
      const elevated = broadPermissions || privilegedEvent;
      const riskContext = [
        broadPermissions ? 'broad write permissions' : null,
        privilegedEvent ? '`pull_request_target`' : null,
      ].filter(Boolean).join(' and ');

      findings.push(createFinding({
        file,
        line: index + 1,
        severity: elevated ? 'critical' : 'high',
        category: this.category,
        rule: 'CICD_AI_ACTION_UNPINNED',
        title: 'CI/CD: AI action uses an unpinned reference',
        description:
          `The AI/agent workflow step uses \`${action}\`, which is not pinned to a full commit SHA. ` +
          'These actions can read prompts, repository content, and pull-request diffs; an upstream ref change can therefore alter code that runs inside this workflow without a reviewed repository change.' +
          (riskContext ? ` The exposure is critical because the workflow also has ${riskContext}.` : ''),
        matched: action.slice(0, 180),
        confidence: 'high',
        cwe: 'CWE-829',
        owasp: 'CICD-SEC-8',
        fix:
          'Pin the action to a reviewed 40-character commit SHA. Keep `contents` read-only, grant write permissions only to the job that needs them, and avoid running AI actions with `pull_request_target` on untrusted input.',
      }));
    }

    return findings;
  }

  async analyze(context) {
    const { rootPath, files } = context;

    const ciFiles = files.filter(f => {
      const relPath = path.relative(rootPath, f).replace(/\\/g, '/');
      const basename = path.basename(f);
      return (
        relPath.startsWith('.github/workflows/') ||
        basename === '.gitlab-ci.yml' ||
        basename === 'Jenkinsfile' ||
        relPath.startsWith('.circleci/') ||
        basename === 'bitbucket-pipelines.yml' ||
        basename === 'azure-pipelines.yml' ||
        basename === '.travis.yml'
      );
    });

    if (ciFiles.length === 0) return [];

    const self = selfOwner(rootPath);

    let findings = [];
    for (const file of ciFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
      // Whole-file pass: catches combinations the line rules structurally
      // cannot see (see UNGOVERNED CONTINUOUS INGESTION above).
      findings = findings.concat(this.scanIngestionChain(file, rootPath, self));
      findings = findings.concat(this.scanPrivilegedHandoffs(file));
      findings = findings.concat(this.scanNpmPublishProvenance(file));
      findings = findings.concat(this.scanUnpinnedAiActions(file));
    }
    return findings;
  }
}

export default CICDScanner;
