/**
 * ConfigAuditor Agent
 * ====================
 *
 * Detects security misconfigurations in:
 * Dockerfile, docker-compose, vercel.json, netlify.toml,
 * next.config.js, Terraform, Kubernetes, nginx, firebase,
 * and security headers.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// DOCKERFILE PATTERNS
// =============================================================================

const DOCKERFILE_PATTERNS = [
  {
    rule: 'DOCKER_RUN_AS_ROOT',
    title: 'Docker: Running as Root',
    regex: /^(?!.*USER\s+\w).*CMD|ENTRYPOINT/gm,
    severity: 'high',
    cwe: 'CWE-250',
    owasp: 'A05:2021',
    confidence: 'medium',
    description: 'No USER instruction found. Container runs as root by default.',
    fix: 'Add USER nonroot before CMD/ENTRYPOINT',
  },
  {
    rule: 'DOCKER_LATEST_TAG',
    title: 'Docker: Using :latest Tag',
    regex: /FROM\s+\S+:latest/gi,
    severity: 'medium',
    cwe: 'CWE-1104',
    description: ':latest tag is mutable and can change unexpectedly. Pin to a specific version.',
    fix: 'Pin to specific version: FROM node:20-alpine instead of FROM node:latest',
  },
  {
    rule: 'DOCKER_ADD_REMOTE',
    title: 'Docker: ADD with Remote URL',
    regex: /ADD\s+https?:\/\//gi,
    severity: 'high',
    cwe: 'CWE-829',
    description: 'ADD with URL downloads without checksum verification. Use COPY + curl with checksum.',
    fix: 'Replace ADD URL with: RUN curl -fsSL url -o file && sha256sum -c <<< "hash file"',
  },
  {
    rule: 'DOCKER_SECRET_ENV',
    title: 'Docker: Secret in ENV/ARG',
    regex: /(?:ENV|ARG)\s+(?:.*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY))\s*=/gi,
    severity: 'critical',
    cwe: 'CWE-798',
    description: 'Secrets in ENV/ARG are baked into image layers. Use Docker secrets or runtime env.',
    fix: 'Use --secret flag in docker build, or pass secrets at runtime via -e',
  },
  {
    rule: 'DOCKER_EXPOSE_ALL',
    title: 'Docker: Exposing Privileged Port',
    regex: /EXPOSE\s+(?:22|23|3389|5432|3306|27017|6379|11211)\b/g,
    severity: 'medium',
    cwe: 'CWE-200',
    description: 'Exposing database/admin ports in container. Only expose application ports.',
    fix: 'Remove EXPOSE for database ports. Use Docker networking for internal communication.',
  },
  {
    rule: 'DOCKER_PRIVILEGED',
    title: 'Docker: Privileged Mode',
    regex: /privileged\s*:\s*true/g,
    severity: 'critical',
    cwe: 'CWE-250',
    description: 'Privileged containers have full host access. This enables container escape.',
    fix: 'Remove privileged: true. Use specific capabilities if needed (cap_add).',
  },
];

// =============================================================================
// CONFIG FILE PATTERNS
// =============================================================================

const CONFIG_PATTERNS = [
  // ── Security Headers ───────────────────────────────────────────────────────
  {
    rule: 'MISSING_CSP',
    title: 'Missing Content-Security-Policy',
    regex: /headers\s*(?::|=)\s*\[/g,
    severity: 'medium',
    cwe: 'CWE-693',
    owasp: 'A05:2021',
    confidence: 'low',
    description: 'No Content-Security-Policy header detected. CSP prevents XSS and data injection.',
    fix: "Add Content-Security-Policy header: \"default-src 'self'; script-src 'self'\"",
  },
  {
    rule: 'CORS_WILDCARD',
    title: 'CORS Wildcard Origin',
    regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]?\*['"]?/g,
    severity: 'high',
    cwe: 'CWE-942',
    owasp: 'A05:2021',
    description: 'CORS wildcard (*) allows any origin. Use specific trusted origins.',
    fix: 'Replace * with specific origins: ["https://yourdomain.com"]',
  },
  {
    rule: 'CORS_CREDENTIALS_WILDCARD',
    title: 'CORS Credentials with Wildcard',
    regex: /credentials\s*:\s*true.*origin\s*:\s*true|origin\s*:\s*true.*credentials\s*:\s*true/g,
    severity: 'critical',
    cwe: 'CWE-942',
    owasp: 'A05:2021',
    description: 'CORS with credentials: true and origin: true reflects any origin, enabling credential theft.',
    fix: 'Use a specific origin allowlist when credentials: true',
  },

  // ── Next.js Config ─────────────────────────────────────────────────────────
  {
    rule: 'NEXTJS_POWERED_BY',
    title: 'Next.js: X-Powered-By Header Enabled',
    regex: /poweredByHeader\s*:\s*true/g,
    severity: 'low',
    cwe: 'CWE-200',
    description: 'X-Powered-By header reveals technology stack. Disable for security through obscurity.',
    fix: 'Set poweredByHeader: false in next.config.js',
  },
  {
    rule: 'NEXTJS_WILDCARD_IMAGES',
    title: 'Next.js: Wildcard Image Domain',
    regex: /images\s*:\s*\{[^}]*(?:domains|remotePatterns)[^}]*\*\*/g,
    severity: 'medium',
    cwe: 'CWE-918',
    description: 'Wildcard image domains can be abused for SSRF via Next.js image optimization.',
    fix: 'Specify exact domains in images.remotePatterns',
  },

  // ── Firebase ───────────────────────────────────────────────────────────────
  {
    rule: 'FIREBASE_OPEN_RULES',
    title: 'Firebase: Open Security Rules',
    regex: /allow\s+read\s*,\s*write\s*:\s*if\s+true/g,
    severity: 'critical',
    cwe: 'CWE-284',
    description: 'Firebase rules allow unauthenticated read/write. Any user can access all data.',
    fix: 'Change to: allow read, write: if request.auth != null;',
  },
  {
    rule: 'FIREBASE_OPEN_STORAGE',
    title: 'Firebase: Open Storage Rules',
    regex: /allow\s+read\s*,\s*write\s*;/g,
    severity: 'critical',
    cwe: 'CWE-284',
    description: 'Firebase Storage rules allow unrestricted access. Add authentication checks.',
    fix: 'Add auth check: allow read, write: if request.auth != null;',
  },

  // ── Terraform ──────────────────────────────────────────────────────────────
  {
    rule: 'TERRAFORM_PUBLIC_S3',
    title: 'Terraform: Public S3 Bucket',
    regex: /acl\s*=\s*"public-read(?:-write)?"/g,
    severity: 'critical',
    cwe: 'CWE-284',
    description: 'S3 bucket with public ACL. Data is accessible to the internet.',
    fix: 'Use acl = "private" and configure bucket policy for specific access',
  },
  {
    rule: 'TERRAFORM_OPEN_SG',
    title: 'Terraform: Open Security Group (0.0.0.0/0)',
    regex: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/g,
    severity: 'high',
    cwe: 'CWE-284',
    description: 'Security group open to all IPs. Restrict to specific CIDR blocks.',
    fix: 'Replace 0.0.0.0/0 with specific IP ranges for the service',
  },
  {
    rule: 'TERRAFORM_WILDCARD_IAM',
    title: 'Terraform: Wildcard IAM Action',
    regex: /actions?\s*=\s*\[\s*"\*"\s*\]/g,
    severity: 'critical',
    cwe: 'CWE-250',
    description: 'IAM policy with Action: "*" grants unrestricted access. Apply least privilege.',
    fix: 'Replace with specific actions: ["s3:GetObject", "s3:PutObject"]',
  },
  {
    rule: 'TERRAFORM_NO_ENCRYPTION',
    title: 'Terraform: Unencrypted Storage',
    regex: /encrypted\s*=\s*false/g,
    severity: 'high',
    cwe: 'CWE-311',
    description: 'Storage is not encrypted. Enable encryption at rest.',
    fix: 'Set encrypted = true and configure KMS key',
  },
  {
    rule: 'TERRAFORM_NO_LOGGING',
    title: 'Terraform: Missing Access Logging',
    regex: /logging\s*\{[^}]*enabled\s*=\s*false/g,
    severity: 'medium',
    cwe: 'CWE-778',
    description: 'Access logging is disabled. Enable for audit trail and incident response.',
    fix: 'Set enabled = true and configure log destination',
  },

  // ── Terraform (expanded) ───────────────────────────────────────────────────
  {
    rule: 'TERRAFORM_RDS_PUBLIC',
    title: 'Terraform: Publicly Accessible RDS',
    regex: /publicly_accessible\s*=\s*true/g,
    severity: 'critical',
    cwe: 'CWE-284',
    description: 'RDS instance is publicly accessible. Databases should not be exposed to the internet.',
    fix: 'Set publicly_accessible = false and use VPC private subnets',
  },
  {
    rule: 'TERRAFORM_CLOUDFRONT_HTTP',
    title: 'Terraform: CloudFront Allows HTTP',
    regex: /viewer_protocol_policy\s*=\s*["']allow-all["']/g,
    severity: 'high',
    cwe: 'CWE-319',
    description: 'CloudFront distribution allows HTTP traffic. Enforce HTTPS-only.',
    fix: 'Set viewer_protocol_policy = "redirect-to-https"',
  },
  {
    rule: 'TERRAFORM_LAMBDA_ADMIN',
    title: 'Terraform: Lambda with Admin Role',
    regex: /(?:policy_arn|role)\s*=\s*.*AdministratorAccess/g,
    severity: 'critical',
    cwe: 'CWE-250',
    description: 'Lambda function attached to AdministratorAccess policy. Apply least privilege.',
    fix: 'Create a custom IAM policy with only the permissions the function needs',
  },
  {
    rule: 'TERRAFORM_S3_NO_VERSIONING',
    title: 'Terraform: S3 Bucket Without Versioning',
    regex: /versioning\s*\{[\s\S]*?enabled\s*=\s*false/g,
    severity: 'medium',
    cwe: 'CWE-693',
    confidence: 'medium',
    description: 'S3 bucket versioning disabled. Versioning protects against accidental deletion and ransomware.',
    fix: 'Set enabled = true in the versioning block',
  },

  // ── Kubernetes ─────────────────────────────────────────────────────────────
  {
    rule: 'K8S_PRIVILEGED_CONTAINER',
    title: 'Kubernetes: Privileged Container',
    regex: /privileged\s*:\s*true/g,
    severity: 'critical',
    cwe: 'CWE-250',
    description: 'Privileged Kubernetes pod can escape to the host. Remove privileged flag.',
    fix: 'Set privileged: false. Use specific capabilities if needed.',
  },
  {
    rule: 'K8S_HOST_NETWORK',
    title: 'Kubernetes: Host Network Mode',
    regex: /hostNetwork\s*:\s*true/g,
    severity: 'high',
    cwe: 'CWE-284',
    description: 'Pod uses host network, bypassing network policies and isolation.',
    fix: 'Remove hostNetwork: true. Use Kubernetes Services for networking.',
  },
  {
    rule: 'K8S_NO_RESOURCE_LIMITS',
    title: 'Kubernetes: Missing Resource Limits',
    regex: /containers\s*:/g,
    severity: 'medium',
    cwe: 'CWE-770',
    confidence: 'low',
    description: 'Container without resource limits can consume unbounded CPU/memory (DoS).',
    fix: 'Add resources.limits.cpu and resources.limits.memory to container spec',
  },
  {
    rule: 'K8S_RUN_AS_ROOT',
    title: 'Kubernetes: Running as Root',
    regex: /runAsUser\s*:\s*0\b/g,
    severity: 'high',
    cwe: 'CWE-250',
    description: 'Pod running as root (UID 0). Use a non-root user.',
    fix: 'Set runAsUser: 1000 and runAsNonRoot: true in securityContext',
  },
  {
    rule: 'K8S_DEFAULT_SA',
    title: 'Kubernetes: Default Service Account',
    regex: /serviceAccountName\s*:\s*["']?default["']?/g,
    severity: 'medium',
    cwe: 'CWE-284',
    description: 'Using default service account. Create a dedicated SA with minimal permissions.',
    fix: 'Create a dedicated ServiceAccount with only needed RBAC bindings',
  },

  {
    rule: 'K8S_LATEST_IMAGE',
    title: 'Kubernetes: Container Using :latest Tag',
    regex: /image\s*:\s*["']?\S+:latest["']?/g,
    severity: 'medium',
    cwe: 'CWE-1104',
    description: 'Container image uses :latest tag, which is mutable and can change unexpectedly.',
    fix: 'Pin to a specific image digest or version tag',
  },

  // ── Docker Compose ─────────────────────────────────────────────────────────
  {
    rule: 'COMPOSE_HOST_MOUNT',
    title: 'Docker Compose: Sensitive Host Mount',
    regex: /volumes\s*:\s*\n\s*-\s*(?:\/etc|\/var\/run\/docker\.sock|\/root|\/proc|\/sys)/gm,
    severity: 'critical',
    cwe: 'CWE-284',
    description: 'Mounting sensitive host paths into container enables escape and privilege escalation.',
    fix: 'Remove sensitive host mounts. Use named volumes for data persistence.',
  },

  // ── Nginx ──────────────────────────────────────────────────────────────────
  {
    rule: 'NGINX_AUTOINDEX',
    title: 'Nginx: Directory Listing Enabled',
    regex: /autoindex\s+on/g,
    severity: 'medium',
    cwe: 'CWE-548',
    description: 'Directory listing exposes file structure. Disable autoindex.',
    fix: 'Set autoindex off; in nginx configuration',
  },
  {
    rule: 'NGINX_SERVER_TOKENS',
    title: 'Nginx: Server Version Exposed',
    regex: /server_tokens\s+on/g,
    severity: 'low',
    cwe: 'CWE-200',
    description: 'Server tokens reveal nginx version. Disable for security.',
    fix: 'Set server_tokens off; in nginx.conf',
  },

  // ── General Config ─────────────────────────────────────────────────────────
  {
    rule: 'DEBUG_MODE_PRODUCTION',
    title: 'Debug Mode in Production Config',
    regex: /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|['"]true['"])/g,
    severity: 'high',
    cwe: 'CWE-215',
    owasp: 'A05:2021',
    confidence: 'medium',
    description: 'Debug mode exposes stack traces, internal state, and sensitive information.',
    fix: 'Set DEBUG=false in production. Use environment-specific config.',
  },
  {
    rule: 'VERBOSE_ERROR_MESSAGES',
    title: 'Verbose Error Messages',
    regex: /(?:stack|stackTrace|err\.message|error\.message|traceback)\s*(?:\)|,)/g,
    severity: 'medium',
    cwe: 'CWE-209',
    owasp: 'A05:2021',
    confidence: 'low',
    description: 'Exposing stack traces or detailed errors in responses leaks internal information.',
    fix: 'Log errors server-side. Return generic error messages to clients.',
  },

  // ── Go Security ──────────────────────────────────────────────────────────
  {
    rule: 'GO_SQL_SPRINTF',
    title: 'Go: SQL Injection via fmt.Sprintf',
    regex: /fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']*%/gi,
    severity: 'critical',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'Go SQL query built with fmt.Sprintf enables SQL injection. Use parameterized queries.',
    fix: 'Use db.Query("SELECT * FROM users WHERE id = $1", id)',
  },
  {
    rule: 'GO_TEMPLATE_UNESCAPED',
    title: 'Go: Unescaped HTML Template',
    regex: /template\.HTML\s*\(/g,
    severity: 'high',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'template.HTML() marks content as safe, bypassing Go HTML template escaping.',
    fix: 'Avoid template.HTML() with user input. Let html/template auto-escape.',
  },

  // ── Rust Security ──────────────────────────────────────────────────────────
  {
    rule: 'RUST_UNSAFE_BLOCK',
    title: 'Rust: unsafe Block',
    regex: /\bunsafe\s*\{/g,
    severity: 'medium',
    cwe: 'CWE-676',
    confidence: 'low',
    description: 'Rust unsafe block bypasses memory safety guarantees. Review for correctness.',
    fix: 'Minimize unsafe code. Wrap in safe abstractions with safety invariants documented.',
  },
  {
    rule: 'RUST_UNWRAP_IN_PROD',
    title: 'Rust: .unwrap() Without Error Handling',
    regex: /\.unwrap\(\)/g,
    severity: 'low',
    cwe: 'CWE-391',
    confidence: 'low',
    description: '.unwrap() panics on error. Use proper error handling in production code.',
    fix: 'Use .unwrap_or(), .unwrap_or_default(), or ? operator for error propagation.',
  },

  // ── Deprecated Node.js ─────────────────────────────────────────────────────
  {
    rule: 'DEPRECATED_BUFFER',
    title: 'Deprecated: new Buffer()',
    regex: /\bnew\s+Buffer\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-676',
    description: 'new Buffer() is deprecated and has security implications. Use Buffer.from().',
    fix: 'Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe()',
  },
];

export class ConfigAuditor extends BaseAgent {
  constructor() {
    super('ConfigAuditor', 'Detect security misconfigurations in infrastructure and app config', 'config');
  }

  async analyze(context) {
    const { rootPath, files, recon } = context;
    let findings = [];

    // ── Scan Dockerfiles ──────────────────────────────────────────────────────
    const dockerfiles = files.filter(f => {
      const basename = path.basename(f);
      return basename === 'Dockerfile' || basename.startsWith('Dockerfile.');
    });
    for (const file of dockerfiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, DOCKERFILE_PATTERNS));
      findings = findings.concat(this.checkDockerfileUser(file));
    }

    // ── Scan docker-compose ───────────────────────────────────────────────────
    const composeFiles = files.filter(f => /docker-compose\.ya?ml$/i.test(path.basename(f)));
    for (const file of composeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, CONFIG_PATTERNS));
    }

    // ── Scan Terraform ────────────────────────────────────────────────────────
    const tfFiles = files.filter(f => path.extname(f) === '.tf');
    for (const file of tfFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, CONFIG_PATTERNS));
    }

    // ── Scan Kubernetes manifests ─────────────────────────────────────────────
    const k8sFiles = files.filter(f => {
      const relPath = path.relative(rootPath, f).replace(/\\/g, '/');
      return /\.ya?ml$/i.test(f) && /(?:k8s|kubernetes|deploy|helm|manifests)/i.test(relPath);
    });
    for (const file of k8sFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, CONFIG_PATTERNS));
    }

    // ── Project-level: K8s NetworkPolicy check ─────────────────────────────────
    if (k8sFiles.length > 0) {
      const hasNetworkPolicy = k8sFiles.some(f => {
        const content = this.readFile(f);
        return content && /kind\s*:\s*NetworkPolicy/i.test(content);
      });
      if (!hasNetworkPolicy) {
        findings.push(createFinding({
          file: k8sFiles[0],
          line: 0,
          severity: 'medium',
          category: 'config',
          rule: 'K8S_NO_NETWORK_POLICY',
          title: 'Kubernetes: No NetworkPolicy Defined',
          description: 'Kubernetes manifests found but no NetworkPolicy defined. Without network policies, all pod-to-pod traffic is allowed.',
          matched: 'Missing NetworkPolicy',
          confidence: 'medium',
          fix: 'Add a NetworkPolicy resource to restrict pod-to-pod traffic',
        }));
      }
    }

    // ── Scan config files ─────────────────────────────────────────────────────
    const configFiles = files.filter(f => {
      const basename = path.basename(f);
      return [
        'vercel.json', 'netlify.toml', 'next.config.js', 'next.config.mjs', 'next.config.ts',
        'nginx.conf', 'Caddyfile', 'firebase.json', 'firestore.rules', 'storage.rules',
        '.env.example', '.env.sample', '.env.local',
      ].includes(basename);
    });
    for (const file of configFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, CONFIG_PATTERNS));
    }

    // ── Scan all code files for general config issues ─────────────────────────
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.py', '.rb', '.go', '.rs', '.php'].includes(ext);
    });
    const generalPatterns = CONFIG_PATTERNS.filter(p =>
      ['CORS_WILDCARD', 'CORS_CREDENTIALS_WILDCARD', 'DEBUG_MODE_PRODUCTION',
       'DEPRECATED_BUFFER', 'GO_SQL_SPRINTF', 'GO_TEMPLATE_UNESCAPED',
       'RUST_UNSAFE_BLOCK', 'RUST_UNWRAP_IN_PROD'].includes(p.rule)
    );
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, generalPatterns));
    }

    return findings;
  }

  /**
   * Check if a Dockerfile has a USER instruction before CMD/ENTRYPOINT.
   */
  checkDockerfileUser(filePath) {
    const content = this.readFile(filePath);
    if (!content) return [];

    const hasUser = /^USER\s+(?!root)\S+/m.test(content);
    const hasCmd = /^(?:CMD|ENTRYPOINT)\s+/m.test(content);

    if (hasCmd && !hasUser) {
      return [createFinding({
        file: filePath,
        line: 1,
        severity: 'high',
        category: 'config',
        rule: 'DOCKER_NO_USER',
        title: 'Dockerfile: No Non-Root USER',
        description: 'No USER instruction found. Container runs as root, enabling escape attacks.',
        matched: 'Missing USER instruction',
        fix: 'Add before CMD: RUN addgroup -S app && adduser -S app -G app\nUSER app',
      })];
    }
    return [];
  }
}

export default ConfigAuditor;
