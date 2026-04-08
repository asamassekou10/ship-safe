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

import path from 'path';
import { BaseAgent } from './base-agent.js';

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
    regex: /(?:api[_-]?key|token|password|secret)\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/gi,
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
    regex: /(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\$\{\{\s*(?:secrets\.|env\.)[^\}]+\}\}/g,
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

export class CICDScanner extends BaseAgent {
  constructor() {
    super('CICDScanner', 'Detect CI/CD pipeline security issues (OWASP CI/CD Top 10)', 'cicd');
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

    let findings = [];
    for (const file of ciFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default CICDScanner;
