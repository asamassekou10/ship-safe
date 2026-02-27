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
    regex: /pull_request_target[\s\S]{0,500}(?:actions\/checkout|checkout@)[\s\S]{0,200}(?:ref:\s*\$\{\{.*github\.event\.pull_request|head\.ref)/g,
    severity: 'critical',
    cwe: 'CWE-94',
    owasp: 'CICD-SEC-4',
    description: 'pull_request_target with checkout of PR branch enables arbitrary code execution from forks.',
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
    title: 'CI/CD: Unpinned GitHub Action (uses @main/master)',
    regex: /uses\s*:\s*[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+@(?:main|master|latest|v\d+)\b/g,
    severity: 'high',
    cwe: 'CWE-829',
    owasp: 'CICD-SEC-8',
    description: 'GitHub Action pinned to mutable tag. Pin to a specific commit SHA.',
    fix: 'Pin to commit SHA: uses: actions/checkout@abcdef1234567890 # v4.1.0',
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
    regex: /run\s*:\s*.*\$\{\{\s*(?:github\.event\.(?:issue|comment|pull_request|review)\.(?:title|body|head\.ref|label))/g,
    severity: 'critical',
    cwe: 'CWE-78',
    owasp: 'CICD-SEC-4',
    description: 'GitHub expression in run step. Attacker-controlled values can inject shell commands.',
    fix: 'Use environment variables: env: TITLE: ${{ github.event.issue.title }} then run: echo "$TITLE"',
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
