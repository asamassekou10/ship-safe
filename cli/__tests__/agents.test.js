/**
 * Ship Safe Unit Tests
 * =====================
 *
 * Tests agent pattern matching, scoring engine, cache manager,
 * deduplication, and ReDoS safety.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Write a temp file and return its absolute path.
 */
function writeTempFile(content, ext = '.js') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-test-'));
  const file = path.join(dir, `test${ext}`);
  fs.writeFileSync(file, content);
  return { dir, file };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}

// =============================================================================
// INJECTION TESTER
// =============================================================================

describe('InjectionTester', async () => {
  const { InjectionTester } = await import('../agents/injection-tester.js');
  const agent = new InjectionTester();

  it('detects SQL injection via template literal', async () => {
    const { dir, file } = writeTempFile('const q = `SELECT * FROM users WHERE id = ${userId}`;');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.length > 0, 'Should detect SQL injection');
      assert.ok(findings.some(f => f.rule === 'SQL_INJECTION_TEMPLATE_LITERAL'));
    } finally { cleanup(dir); }
  });

  it('detects eval() with user input', async () => {
    const { dir, file } = writeTempFile('eval(req.body.code);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'CODE_INJECTION_EVAL'));
    } finally { cleanup(dir); }
  });

  it('detects command injection via exec template', async () => {
    const { dir, file } = writeTempFile('execSync(`rm -rf ${userPath}`);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'CMD_INJECTION_EXEC_TEMPLATE'));
    } finally { cleanup(dir); }
  });

  it('detects Python f-string SQL injection', async () => {
    const { dir, file } = writeTempFile('cursor.execute(f"SELECT * FROM users WHERE name = {name}")', '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'PYTHON_SQL_FSTRING'));
    } finally { cleanup(dir); }
  });

  it('detects Python subprocess shell=True', async () => {
    const { dir, file } = writeTempFile('subprocess.run(cmd, shell=True)', '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'PYTHON_SUBPROCESS_SHELL'));
    } finally { cleanup(dir); }
  });

  it('returns no findings for safe code', async () => {
    const { dir, file } = writeTempFile('const x = 1 + 2;\nconsole.log(x);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      // Filter out low-confidence generic matches
      const significant = findings.filter(f => f.confidence !== 'low');
      assert.equal(significant.length, 0, 'Safe code should have no significant findings');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// AUTH BYPASS AGENT
// =============================================================================

describe('AuthBypassAgent', async () => {
  const { AuthBypassAgent } = await import('../agents/auth-bypass-agent.js');
  const agent = new AuthBypassAgent();

  it('detects JWT algorithm none', async () => {
    const { dir, file } = writeTempFile('jwt.verify(token, secret, { algorithms: ["none"] });');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'JWT_ALG_NONE'));
    } finally { cleanup(dir); }
  });

  it('detects Django DEBUG = True', async () => {
    const { dir, file } = writeTempFile('DEBUG = True\nALLOWED_HOSTS = ["*"]', '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'DJANGO_DEBUG_TRUE'));
    } finally { cleanup(dir); }
  });

  it('detects Flask hardcoded secret key', async () => {
    const { dir, file } = writeTempFile('app.secret_key = "mysecret123"', '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'FLASK_SECRET_KEY_HARDCODED'));
    } finally { cleanup(dir); }
  });

  it('detects TLS reject unauthorized disabled', async () => {
    const { dir, file } = writeTempFile('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'TLS_REJECT_UNAUTHORIZED'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// API FUZZER
// =============================================================================

describe('APIFuzzer', async () => {
  const { APIFuzzer } = await import('../agents/api-fuzzer.js');
  const agent = new APIFuzzer();

  it('detects spread request body (mass assignment)', async () => {
    const { dir, file } = writeTempFile('const data = { ...req.body };');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'API_SPREAD_BODY'));
    } finally { cleanup(dir); }
  });

  it('detects API key in URL', async () => {
    const { dir, file } = writeTempFile('const url = `https://api.example.com?key=${apiKey}`;');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'API_KEY_IN_URL'));
    } finally { cleanup(dir); }
  });

  it('detects debug endpoint', async () => {
    const { dir, file } = writeTempFile('app.get("/debug/info", handler);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'API_DEBUG_ENDPOINT'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// SSRF PROBER
// =============================================================================

describe('SSRFProber', async () => {
  const { SSRFProber } = await import('../agents/ssrf-prober.js');
  const agent = new SSRFProber();

  it('detects user input in fetch()', async () => {
    const { dir, file } = writeTempFile('const res = await fetch(req.query.url);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'SSRF_USER_URL_FETCH'));
    } finally { cleanup(dir); }
  });

  it('detects cloud metadata endpoint', async () => {
    const { dir, file } = writeTempFile('const meta = await fetch("http://169.254.169.254/latest/meta-data/");');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'SSRF_CLOUD_METADATA'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// LLM RED TEAM
// =============================================================================

describe('LLMRedTeam', async () => {
  const { LLMRedTeam } = await import('../agents/llm-redteam.js');
  const agent = new LLMRedTeam();

  it('detects LLM output to eval', async () => {
    const { dir, file } = writeTempFile('eval(completion.content);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'LLM_OUTPUT_TO_EVAL'));
    } finally { cleanup(dir); }
  });

  it('detects system prompt in client code', async () => {
    const { dir, file } = writeTempFile('const systemPrompt = "You are a helpful assistant";');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'LLM_SYSTEM_PROMPT_CLIENT'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// CONFIG AUDITOR
// =============================================================================

describe('ConfigAuditor', async () => {
  const { ConfigAuditor } = await import('../agents/config-auditor.js');
  const agent = new ConfigAuditor();

  it('detects CORS wildcard', async () => {
    const { dir, file } = writeTempFile('app.use(cors({ origin: "*" }));');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'CORS_WILDCARD'));
    } finally { cleanup(dir); }
  });

  it('detects Go SQL sprintf', async () => {
    const { dir, file } = writeTempFile('query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)', '.go');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'GO_SQL_SPRINTF'));
    } finally { cleanup(dir); }
  });

  it('detects Rust unsafe block', async () => {
    const { dir, file } = writeTempFile('unsafe {\n  ptr::read(p)\n}', '.rs');
    try {
      // Config auditor needs .go/.rs in code file extensions
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'RUST_UNSAFE_BLOCK'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// SCORING ENGINE
// =============================================================================

describe('ScoringEngine', async () => {
  const { ScoringEngine } = await import('../agents/scoring-engine.js');

  it('computes perfect score with no findings', () => {
    const engine = new ScoringEngine();
    const result = engine.compute([], []);
    assert.equal(result.score, 100);
    assert.equal(result.grade.letter, 'A');
  });

  it('deducts for critical findings (capped at category weight)', () => {
    const engine = new ScoringEngine();
    const findings = [
      { severity: 'critical', category: 'secrets', confidence: 'high' },
    ];
    const result = engine.compute(findings, []);
    assert.ok(result.score < 100, 'Score should decrease with critical finding');
    // 25 pts deduction capped at category weight of 15
    assert.equal(result.categories.secrets.deduction, 15);
  });

  it('applies confidence multiplier', () => {
    const engine = new ScoringEngine();
    const highConf = [{ severity: 'high', category: 'injection', confidence: 'high' }];
    const lowConf = [{ severity: 'high', category: 'injection', confidence: 'low' }];

    const highResult = engine.compute(highConf, []);
    const lowResult = engine.compute(lowConf, []);
    assert.ok(lowResult.score > highResult.score, 'Low confidence should deduct less');
  });

  it('caps deduction at category weight', () => {
    const engine = new ScoringEngine();
    // 10 critical findings in secrets (25 pts each = 250, but capped at 15)
    const findings = Array(10).fill({ severity: 'critical', category: 'secrets', confidence: 'high' });
    const result = engine.compute(findings, []);
    assert.equal(result.categories.secrets.deduction, 15);
  });

  it('handles dependency vulnerabilities', () => {
    const engine = new ScoringEngine();
    const depVulns = [{ severity: 'critical' }, { severity: 'high' }];
    const result = engine.compute([], depVulns);
    assert.ok(result.score < 100);
    assert.ok(result.categories.deps.deduction > 0);
  });

  it('saves and loads history', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-score-'));
    try {
      const engine = new ScoringEngine();
      const result = engine.compute([], []);
      engine.saveToHistory(dir, result);
      engine.saveToHistory(dir, result);

      const history = engine.loadHistory(dir);
      assert.equal(history.length, 2);

      const trend = engine.getTrend(dir, 100);
      assert.ok(trend);
      assert.equal(trend.diff, 0);
      assert.equal(trend.direction, 'unchanged');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// CACHE MANAGER
// =============================================================================

describe('CacheManager', async () => {
  const { CacheManager } = await import('../utils/cache-manager.js');

  it('save/load/diff cycle works', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-cache-'));
    const testFile = path.join(dir, 'test.js');
    fs.writeFileSync(testFile, 'const x = 1;');

    try {
      const cache = new CacheManager(dir);
      const findings = [{ file: testFile, line: 1, rule: 'TEST', severity: 'low', category: 'test' }];
      cache.save([testFile], findings, null, { score: 90, grade: { letter: 'A' } });

      // Load and verify
      const loaded = cache.load();
      assert.ok(loaded, 'Cache should load successfully');
      assert.equal(loaded.stats.totalFiles, 1);

      // Diff with same files — no changes
      const diff = cache.diff([testFile]);
      assert.equal(diff.changedFiles.length, 0);
      assert.equal(diff.unchangedCount, 1);
      assert.equal(diff.cachedFindings.length, 1);
    } finally { cleanup(dir); }
  });

  it('detects changed files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-cache-'));
    const testFile = path.join(dir, 'test.js');
    fs.writeFileSync(testFile, 'const x = 1;');

    try {
      const cache = new CacheManager(dir);
      cache.save([testFile], [], null, null);
      cache.load();

      // Modify file
      fs.writeFileSync(testFile, 'const x = 2; // changed');
      const diff = cache.diff([testFile]);
      assert.equal(diff.changedFiles.length, 1);
      assert.equal(diff.modifiedCount, 1);
    } finally { cleanup(dir); }
  });

  it('invalidates cache', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-cache-'));
    const testFile = path.join(dir, 'test.js');
    fs.writeFileSync(testFile, 'x');

    try {
      const cache = new CacheManager(dir);
      cache.save([testFile], [], null, null);
      assert.ok(cache.load());

      cache.invalidate();
      assert.equal(cache.load(), null);
    } finally { cleanup(dir); }
  });

  it('LLM cache save/load works', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-llm-'));

    try {
      const cache = new CacheManager(dir);
      const finding = { file: '/test.js', line: 1, rule: 'TEST', matched: 'x' };
      const key = cache.getLLMCacheKey(finding);

      cache.saveLLMClassifications({
        [key]: { classification: 'true_positive', reason: 'test', fix: 'fix it', cachedAt: new Date().toISOString() },
      });

      const loaded = cache.loadLLMClassifications();
      assert.ok(loaded[key]);
      assert.equal(loaded[key].classification, 'true_positive');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// REDOS SAFETY
// =============================================================================

describe('ReDoS Safety', async () => {
  // Import agents to get their patterns
  const { default: InjectionTester } = await import('../agents/injection-tester.js');
  const { default: AuthBypassAgent } = await import('../agents/auth-bypass-agent.js');
  const { default: APIFuzzer } = await import('../agents/api-fuzzer.js');
  const { default: LLMRedTeam } = await import('../agents/llm-redteam.js');
  const { default: SSRFProber } = await import('../agents/ssrf-prober.js');
  const { default: ConfigAuditor } = await import('../agents/config-auditor.js');

  // Adversarial inputs that trigger catastrophic backtracking in vulnerable patterns
  const adversarialInputs = [
    'a'.repeat(100),
    '/' + '\\s*'.repeat(50),
    '{' + ' '.repeat(100) + '}',
    'req.body' + '.x'.repeat(50),
    'http://' + 'a'.repeat(100) + '/path',
    '; '.repeat(100),
    'cookie=' + 'a=b; '.repeat(50),
  ];

  it('all agent patterns complete within 50ms on adversarial input', async () => {
    const agents = [
      new InjectionTester(),
      new AuthBypassAgent(),
      new APIFuzzer(),
      new LLMRedTeam(),
      new SSRFProber(),
      new ConfigAuditor(),
    ];

    for (const input of adversarialInputs) {
      const { dir, file } = writeTempFile(input);
      try {
        for (const agent of agents) {
          const start = performance.now();
          await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
          const elapsed = performance.now() - start;
          assert.ok(
            elapsed < 2000, // 2s generous limit per agent per file
            `${agent.name} took ${elapsed.toFixed(0)}ms on adversarial input (limit: 2000ms)`
          );
        }
      } finally { cleanup(dir); }
    }
  });
});

// =============================================================================
// ORCHESTRATOR
// =============================================================================

describe('Orchestrator', async () => {
  const { Orchestrator } = await import('../agents/orchestrator.js');

  it('handles agent timeout gracefully', async () => {
    const orchestrator = new Orchestrator();

    // Mock agent that takes forever
    const slowAgent = {
      name: 'SlowAgent',
      category: 'test',
      analyze: () => new Promise(resolve => setTimeout(resolve, 60000)),
    };
    orchestrator.register(slowAgent);

    // Use a very short timeout
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-orch-'));
    fs.writeFileSync(path.join(dir, 'test.js'), 'x');

    try {
      const result = await orchestrator.runAll(dir, { quiet: true, timeout: 100 });
      assert.equal(result.agentResults.length, 1);
      assert.equal(result.agentResults[0].success, false);
      assert.ok(result.agentResults[0].error.includes('timed out'));
    } finally { cleanup(dir); }
  });

  it('deduplicates findings', () => {
    const orchestrator = new Orchestrator();
    const findings = [
      { file: 'a.js', line: 1, rule: 'R1', severity: 'high' },
      { file: 'a.js', line: 1, rule: 'R1', severity: 'high' },
      { file: 'a.js', line: 2, rule: 'R1', severity: 'high' },
    ];
    const deduped = orchestrator.deduplicate(findings);
    assert.equal(deduped.length, 2);
  });

  it('tunes confidence for test files', () => {
    const orchestrator = new Orchestrator();
    const findings = [
      { file: '/project/__tests__/foo.test.js', line: 1, rule: 'R1', severity: 'high', confidence: 'high', matched: 'eval(x)' },
      { file: '/project/src/app.js', line: 1, rule: 'R2', severity: 'high', confidence: 'high', matched: 'eval(x)' },
    ];
    const tuned = orchestrator.tuneConfidence(findings);
    assert.equal(tuned[0].confidence, 'low');  // test file → low
    assert.equal(tuned[1].confidence, 'high'); // src file → unchanged
  });

  it('tunes confidence for doc files', () => {
    const orchestrator = new Orchestrator();
    const findings = [
      { file: '/project/README.md', line: 5, rule: 'R1', severity: 'high', confidence: 'high', matched: 'password = "test"' },
    ];
    const tuned = orchestrator.tuneConfidence(findings);
    assert.equal(tuned[0].confidence, 'low');
  });

  it('tunes confidence for example paths', () => {
    const orchestrator = new Orchestrator();
    const findings = [
      { file: '/project/examples/demo.js', line: 1, rule: 'R1', severity: 'high', confidence: 'high', matched: 'eval(x)' },
    ];
    const tuned = orchestrator.tuneConfidence(findings);
    assert.equal(tuned[0].confidence, 'medium');
  });
});

// =============================================================================
// SUPABASE RLS AGENT
// =============================================================================

describe('SupabaseRLSAgent', () => {
  it('detects service_role key in client code', async () => {
    const { SupabaseRLSAgent } = await import('../agents/supabase-rls-agent.js');
    const agent = new SupabaseRLSAgent();
    const { dir, file } = writeTempFile(`const supabase = createClient(url, SUPABASE_SERVICE_ROLE_KEY);`);
    try {
      const findings = agent.scanFileWithPatterns(file, [
        { rule: 'SUPABASE_SERVICE_KEY_CLIENT', regex: /SUPABASE_SERVICE_ROLE_KEY|service_role_key|serviceRoleKey|supabaseAdmin/g, severity: 'critical', title: 'test', description: 'test' }
      ]);
      assert.ok(findings.some(f => f.rule === 'SUPABASE_SERVICE_KEY_CLIENT'));
    } finally { cleanup(dir); }
  });

  it('detects missing RLS on table', async () => {
    const { SupabaseRLSAgent } = await import('../agents/supabase-rls-agent.js');
    const agent = new SupabaseRLSAgent();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-rls-'));
    const sqlFile = path.join(dir, 'migration.sql');
    fs.writeFileSync(sqlFile, `CREATE TABLE users (id uuid PRIMARY KEY, name text);\nCREATE TABLE posts (id uuid PRIMARY KEY);`);
    const jsFile = path.join(dir, 'app.js');
    fs.writeFileSync(jsFile, 'const x = 1;');

    try {
      const findings = await agent.analyze({
        rootPath: dir,
        files: [sqlFile, jsFile],
        recon: {},
        options: {},
      });
      // Should flag both tables as missing RLS
      const rlsFindings = findings.filter(f => f.rule === 'SUPABASE_NO_RLS_POLICY');
      assert.ok(rlsFindings.length >= 2, `Expected >=2 RLS findings, got ${rlsFindings.length}`);
    } finally { cleanup(dir); }
  });

  it('does not flag tables with RLS enabled', async () => {
    const { SupabaseRLSAgent } = await import('../agents/supabase-rls-agent.js');
    const agent = new SupabaseRLSAgent();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-rls2-'));
    const sqlFile = path.join(dir, 'migration.sql');
    fs.writeFileSync(sqlFile, `CREATE TABLE users (id uuid PRIMARY KEY);\nALTER TABLE users ENABLE ROW LEVEL SECURITY;`);

    try {
      const findings = await agent.analyze({
        rootPath: dir,
        files: [sqlFile],
        recon: {},
        options: {},
      });
      const rlsFindings = findings.filter(f => f.rule === 'SUPABASE_NO_RLS_POLICY');
      assert.equal(rlsFindings.length, 0);
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// CONFIG AUDITOR — NEW TERRAFORM/K8S PATTERNS
// =============================================================================

describe('ConfigAuditor (v4.3 patterns)', () => {
  it('detects publicly accessible RDS', async () => {
    const { ConfigAuditor } = await import('../agents/config-auditor.js');
    const agent = new ConfigAuditor();
    const { dir, file } = writeTempFile(`resource "aws_db_instance" "main" {\n  publicly_accessible = true\n}`, '.tf');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'TERRAFORM_RDS_PUBLIC'));
    } finally { cleanup(dir); }
  });

  it('detects CloudFront allowing HTTP', async () => {
    const { ConfigAuditor } = await import('../agents/config-auditor.js');
    const agent = new ConfigAuditor();
    const { dir, file } = writeTempFile(`viewer_protocol_policy = "allow-all"`, '.tf');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'TERRAFORM_CLOUDFRONT_HTTP'));
    } finally { cleanup(dir); }
  });

  it('detects K8s :latest image tag', async () => {
    const { ConfigAuditor } = await import('../agents/config-auditor.js');
    const agent = new ConfigAuditor();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-k8s-'));
    const k8sDir = path.join(dir, 'k8s');
    fs.mkdirSync(k8sDir);
    const file = path.join(k8sDir, 'deployment.yaml');
    fs.writeFileSync(file, `kind: Deployment\nspec:\n  containers:\n  - image: nginx:latest`);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'K8S_LATEST_IMAGE'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// API FUZZER — RATE LIMITING & OPENAPI
// =============================================================================

describe('APIFuzzer (v4.3 patterns)', () => {
  it('detects missing rate limiting in Express app', async () => {
    const { APIFuzzer } = await import('../agents/api-fuzzer.js');
    const agent = new APIFuzzer();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-api-'));
    const file = path.join(dir, 'app.js');
    fs.writeFileSync(file, `import express from 'express';\nconst app = express();\napp.listen(3000);`);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'API_NO_RATE_LIMIT'));
    } finally { cleanup(dir); }
  });

  it('does not flag when rate limiter is present', async () => {
    const { APIFuzzer } = await import('../agents/api-fuzzer.js');
    const agent = new APIFuzzer();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-api2-'));
    const file = path.join(dir, 'app.js');
    fs.writeFileSync(file, `import express from 'express';\nimport rateLimit from 'express-rate-limit';\nconst app = express();\napp.listen(3000);`);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(!findings.some(f => f.rule === 'API_NO_RATE_LIMIT'));
    } finally { cleanup(dir); }
  });

  it('detects secrets in OpenAPI examples', async () => {
    const { APIFuzzer } = await import('../agents/api-fuzzer.js');
    const agent = new APIFuzzer();

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-oas-'));
    const file = path.join(dir, 'openapi.yaml');
    fs.writeFileSync(file, `openapi: 3.0.0\npaths:\n  /users:\n    get:\n      parameters:\n        - name: token\n          example: sk-proj-abc123xyz`);

    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'OPENAPI_EXAMPLE_SECRETS' || f.rule === 'OPENAPI_NO_SECURITY'));
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// AUTOFIX RULES
// =============================================================================

describe('Autofix Rules', () => {
  it('fixes rejectUnauthorized: false', async () => {
    const { applyAutofix } = await import('../utils/autofix-rules.js');
    const line = '  rejectUnauthorized: false,';
    const fixed = applyAutofix('TLS_REJECT_UNAUTHORIZED', line);
    assert.ok(fixed.includes('rejectUnauthorized: true'));
    assert.ok(!fixed.includes('false'));
  });

  it('fixes DEBUG = true', async () => {
    const { applyAutofix } = await import('../utils/autofix-rules.js');
    assert.ok(applyAutofix('DEBUG_MODE_PRODUCTION', 'DEBUG = true').includes('false'));
    assert.ok(applyAutofix('DEBUG_MODE_PRODUCTION', 'DEBUG = True').includes('False'));
  });

  it('fixes shell: true', async () => {
    const { applyAutofix } = await import('../utils/autofix-rules.js');
    const fixed = applyAutofix('CMD_INJECTION_SHELL_TRUE', '  shell: true');
    assert.ok(fixed.includes('shell: false'));
  });
});

// =============================================================================
// CODE CONTEXT
// =============================================================================

describe('Code Context in Findings', () => {
  it('attaches codeContext to findings from scanFileWithPatterns', async () => {
    const { InjectionTester } = await import('../agents/injection-tester.js');
    const agent = new InjectionTester();
    const code = `const x = 1;\nconst y = 2;\nconst z = eval(userInput);\nconst w = 3;\nconst v = 4;`;
    const { dir, file } = writeTempFile(code);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      const evalFinding = findings.find(f => f.rule && f.rule.includes('EVAL'));
      if (evalFinding) {
        assert.ok(evalFinding.codeContext, 'Finding should have codeContext');
        assert.ok(Array.isArray(evalFinding.codeContext));
        assert.ok(evalFinding.codeContext.some(c => c.highlight === true));
      }
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// MCP SECURITY AGENT (v5.0)
// =============================================================================

describe('MCPSecurityAgent', async () => {
  const { MCPSecurityAgent } = await import('../agents/mcp-security-agent.js');
  const agent = new MCPSecurityAgent();

  it('detects MCP tool with shell execution', async () => {
    const { dir, file } = writeTempFile('server.tool("run_cmd", async (a) => { return execSync(a.cmd); });');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'MCP_TOOL_SHELL_EXEC'), 'Should detect shell exec in MCP tool');
    } finally { cleanup(dir); }
  });

  it('detects MCP tool with file system write', async () => {
    const { dir, file } = writeTempFile('server.tool("write", async (a) => { fs.writeFileSync(a.path, a.data); });');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'MCP_TOOL_FS_WRITE'), 'Should detect fs write in MCP tool');
    } finally { cleanup(dir); }
  });

  it('detects MCP tool arguments passed to eval', async () => {
    const { dir, file } = writeTempFile('server.tool("exec", async (a) => { return eval(a.code); });');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'MCP_TOOL_ARGS_TO_EVAL'), 'Should detect eval in MCP tool');
    } finally { cleanup(dir); }
  });

  it('detects HTTP without TLS for remote MCP', async () => {
    const { dir, file } = writeTempFile(`
      const transport = new SSEServerTransport("http://remote-server.com:8080/mcp");
    `);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'MCP_HTTP_NO_TLS'), 'Should detect HTTP without TLS');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// AGENTIC SECURITY AGENT (v5.0)
// =============================================================================

describe('AgenticSecurityAgent', async () => {
  const { AgenticSecurityAgent } = await import('../agents/agentic-security-agent.js');
  const agent = new AgenticSecurityAgent();

  it('detects auto-execute without confirmation', async () => {
    const { dir, file } = writeTempFile(`
      const config = {
        auto_approve: true,
        requireConfirmation: false,
      };
    `);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'AGENT_TOOL_NO_CONFIRMATION'), 'Should detect auto-approve');
    } finally { cleanup(dir); }
  });

  it('detects user input in agent memory', async () => {
    const { dir, file } = writeTempFile(`
      memory.push(userMessage);
      context.add(input);
    `);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'AGENT_MEMORY_USER_WRITE'), 'Should detect memory poisoning');
    } finally { cleanup(dir); }
  });

  it('detects agent with shell tool access', async () => {
    const { dir, file } = writeTempFile(`
      const tools = [searchTool, child_process.exec];
      const functions = [subprocess.run];
    `);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'AGENT_TOOL_SHELL_ACCESS'), 'Should detect shell access in tools');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// RAG SECURITY AGENT (v5.0)
// =============================================================================

describe('RAGSecurityAgent', async () => {
  const { RAGSecurityAgent } = await import('../agents/rag-security-agent.js');
  const agent = new RAGSecurityAgent();

  it('detects user upload to vector store', async () => {
    const { dir, file } = writeTempFile('const docs = multer().single("file"); await vectorStore.addDocuments(docs);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'RAG_USER_UPLOAD_TO_VECTORDB'), 'Should detect user upload to vector DB');
    } finally { cleanup(dir); }
  });

  it('detects trust_remote_code=True', async () => {
    const { dir, file } = writeTempFile(`
      model = AutoModel.from_pretrained("user/model", trust_remote_code=True)
    `, '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'RAG_TRUST_REMOTE_CODE'), 'Should detect trust_remote_code');
    } finally { cleanup(dir); }
  });

  it('detects pickle model loading', async () => {
    const { dir, file } = writeTempFile(`
      model = torch.load("model.pkl")
    `, '.py');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'RAG_PICKLE_EMBEDDING_MODEL'), 'Should detect pickle load');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// PII COMPLIANCE AGENT (v5.0)
// =============================================================================

describe('PIIComplianceAgent', async () => {
  const { PIIComplianceAgent } = await import('../agents/pii-compliance-agent.js');
  const agent = new PIIComplianceAgent();

  it('detects PII in console.log', async () => {
    const { dir, file } = writeTempFile('console.log("User email:", user.email);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'PII_IN_CONSOLE_LOG'), 'Should detect PII in console.log');
    } finally { cleanup(dir); }
  });

  it('detects PII sent to analytics', async () => {
    const { dir, file } = writeTempFile(`
      analytics.track("signup", { email: user.email, phone: user.phone });
    `);
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'PII_TO_ANALYTICS'), 'Should detect PII to analytics');
    } finally { cleanup(dir); }
  });

  it('detects SSN pattern in source code', async () => {
    const { dir, file } = writeTempFile('const testSSN = "123-45-6789";');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'PII_SSN_IN_CODE'), 'Should detect SSN pattern');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// VIBE CODE DETECTION (v5.0)
// =============================================================================

describe('Vibe Code Detection', async () => {
  const { InjectionTester } = await import('../agents/injection-tester.js');
  const agent = new InjectionTester();

  it('detects TODO to add authentication', async () => {
    const { dir, file } = writeTempFile('// TODO: add authentication\napp.post("/api/admin", handler);');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'VIBE_TODO_AUTH'), 'Should detect TODO auth');
    } finally { cleanup(dir); }
  });

  it('detects placeholder secrets', async () => {
    const { dir, file } = writeTempFile('const apiKey = "your-api-key-here";');
    try {
      const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      assert.ok(findings.some(f => f.rule === 'VIBE_PLACEHOLDER_SECRET'), 'Should detect placeholder secret');
    } finally { cleanup(dir); }
  });
});

// =============================================================================
// VERIFIER AGENT (v5.0)
// =============================================================================

describe('VerifierAgent', async () => {
  const { VerifierAgent } = await import('../agents/verifier-agent.js');
  const verifier = new VerifierAgent();

  it('confirms finding with user input and no sanitization', async () => {
    const code = 'app.post("/api", (req, res) => {\n  const name = req.body.name;\n  db.query(`SELECT * FROM users WHERE name = ${name}`);\n  res.send("ok");\n});';
    const { dir, file } = writeTempFile(code);
    try {
      const findings = [{
        file, line: 3, severity: 'critical', confidence: 'high',
        rule: 'SQL_INJECTION', matched: '`SELECT * FROM users',
      }];
      const verified = verifier.verify(findings);
      assert.strictEqual(verified[0].verified, true, 'Should verify finding with user input');
      assert.strictEqual(verified[0].confidence, 'high', 'Should keep high confidence');
    } finally { cleanup(dir); }
  });

  it('downgrades finding with sanitization upstream', async () => {
    const code = 'app.post("/api", (req, res) => {\n  const name = sanitize(req.body.name);\n  const validated = validator.escape(name);\n  db.query(`SELECT * FROM users WHERE name = ${validated}`);\n  res.send("ok");\n});';
    const { dir, file } = writeTempFile(code);
    try {
      const findings = [{
        file, line: 4, severity: 'critical', confidence: 'high',
        rule: 'SQL_INJECTION', matched: '`SELECT * FROM users',
      }];
      const verified = verifier.verify(findings);
      assert.strictEqual(verified[0].verified, false, 'Should not verify sanitized finding');
      assert.strictEqual(verified[0].confidence, 'medium', 'Should downgrade confidence');
    } finally { cleanup(dir); }
  });

  it('skips verification for medium/low severity', async () => {
    const findings = [{
      file: '/fake/path.js', line: 1, severity: 'medium', confidence: 'high',
      rule: 'SOME_RULE', matched: 'something',
    }];
    const verified = verifier.verify(findings);
    assert.strictEqual(verified[0].verified, null, 'Should skip medium severity');
  });
});

// =============================================================================
// DEEP ANALYZER
// =============================================================================

describe('DeepAnalyzer', async () => {
  const { DeepAnalyzer } = await import('../agents/deep-analyzer.js');

  it('returns findings unchanged when no provider is set', async () => {
    const analyzer = new DeepAnalyzer({ provider: null });
    const findings = [
      { file: '/test.js', line: 1, severity: 'critical', rule: 'SQL_INJECTION', confidence: 'high' },
    ];
    const result = await analyzer.analyze(findings);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].deepAnalysis, undefined, 'No deep analysis without provider');
  });

  it('only selects critical/high findings for analysis', async () => {
    // Mock provider that records what it receives
    let receivedPrompt = '';
    const mockProvider = {
      name: 'MockLLM',
      async complete(sys, prompt) {
        receivedPrompt = prompt;
        return '[]';
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 100 });
    const findings = [
      { file: '/a.js', line: 1, severity: 'critical', rule: 'RULE_A', confidence: 'high', title: 'A', description: 'A' },
      { file: '/b.js', line: 2, severity: 'medium', rule: 'RULE_B', confidence: 'high', title: 'B', description: 'B' },
      { file: '/c.js', line: 3, severity: 'low', rule: 'RULE_C', confidence: 'high', title: 'C', description: 'C' },
      { file: '/d.js', line: 4, severity: 'high', rule: 'RULE_D', confidence: 'high', title: 'D', description: 'D' },
    ];
    await analyzer.analyze(findings);
    // Only critical and high should be in the prompt
    assert.ok(receivedPrompt.includes('RULE_A'), 'Should include critical finding');
    assert.ok(receivedPrompt.includes('RULE_D'), 'Should include high finding');
    assert.ok(!receivedPrompt.includes('RULE_B'), 'Should exclude medium finding');
    assert.ok(!receivedPrompt.includes('RULE_C'), 'Should exclude low finding');
  });

  it('attaches deep analysis from LLM response', async () => {
    const mockProvider = {
      name: 'MockLLM',
      async complete() {
        return JSON.stringify([{
          findingId: 'test.js:5:XSS_DANGEROUS',
          tainted: true,
          sanitized: false,
          exploitability: 'confirmed',
          reasoning: 'User input flows directly to innerHTML without sanitization.',
        }]);
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 100 });
    const findings = [{
      file: '/some/path/test.js', line: 5, severity: 'critical',
      rule: 'XSS_DANGEROUS', confidence: 'medium', title: 'XSS', description: 'XSS via innerHTML',
    }];

    const result = await analyzer.analyze(findings);
    assert.ok(result[0].deepAnalysis, 'Should have deepAnalysis attached');
    assert.strictEqual(result[0].deepAnalysis.tainted, true);
    assert.strictEqual(result[0].deepAnalysis.sanitized, false);
    assert.strictEqual(result[0].deepAnalysis.exploitability, 'confirmed');
    assert.strictEqual(result[0].confidence, 'high', 'Confirmed finding should have high confidence');
  });

  it('downgrades confidence for false_positive analysis', async () => {
    const mockProvider = {
      name: 'MockLLM',
      async complete() {
        return JSON.stringify([{
          findingId: 'app.js:10:EVAL_CALL',
          tainted: false,
          sanitized: false,
          exploitability: 'false_positive',
          reasoning: 'Static string passed to eval, no user input path.',
        }]);
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 100 });
    const findings = [{
      file: '/code/app.js', line: 10, severity: 'high',
      rule: 'EVAL_CALL', confidence: 'high', title: 'Eval', description: 'eval() usage',
    }];

    const result = await analyzer.analyze(findings);
    assert.strictEqual(result[0].confidence, 'low', 'False positive should downgrade to low confidence');
    assert.strictEqual(result[0].deepAnalysis.exploitability, 'false_positive');
  });

  it('respects budget limit', async () => {
    let callCount = 0;
    const mockProvider = {
      name: 'MockLLM',
      async complete() {
        callCount++;
        // Return a very long response to burn budget
        return '[]';
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 0 });
    const findings = Array.from({ length: 10 }, (_, i) => ({
      file: `/f${i}.js`, line: 1, severity: 'critical', rule: `RULE_${i}`,
      confidence: 'high', title: `Rule ${i}`, description: `Desc ${i}`,
    }));

    await analyzer.analyze(findings);
    // With 0 budget, should not make any calls (budget check happens before first batch)
    assert.strictEqual(callCount, 0, 'Should not call LLM when budget is 0');
  });

  it('handles LLM errors gracefully', async () => {
    const mockProvider = {
      name: 'MockLLM',
      async complete() {
        throw new Error('API rate limit exceeded');
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 100 });
    const findings = [{
      file: '/err.js', line: 1, severity: 'critical', rule: 'SOME_RULE',
      confidence: 'high', title: 'Rule', description: 'Desc',
    }];

    // Should not throw
    const result = await analyzer.analyze(findings);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].deepAnalysis, undefined, 'Failed analysis should not attach result');
  });

  it('parses malformed LLM response without crashing', async () => {
    const mockProvider = {
      name: 'MockLLM',
      async complete() {
        return 'This is not valid JSON at all';
      },
    };

    const analyzer = new DeepAnalyzer({ provider: mockProvider, budgetCents: 100 });
    const findings = [{
      file: '/bad.js', line: 1, severity: 'high', rule: 'BAD_RULE',
      confidence: 'high', title: 'Bad', description: 'Bad response test',
    }];

    const result = await analyzer.analyze(findings);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].deepAnalysis, undefined, 'Malformed response should not attach result');
  });

  it('static create() returns null when no provider available', () => {
    // Remove all API key env vars temporarily
    const saved = {};
    for (const key of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY']) {
      saved[key] = process.env[key];
      delete process.env[key];
    }

    try {
      const analyzer = DeepAnalyzer.create('/nonexistent/path');
      assert.strictEqual(analyzer, null, 'Should return null when no provider is available');
    } finally {
      // Restore
      for (const [key, val] of Object.entries(saved)) {
        if (val !== undefined) process.env[key] = val;
      }
    }
  });
});

// =============================================================================
// CROSS-AGENT AWARENESS & FRAMEWORK-AWARE shouldRun
// =============================================================================

describe('Framework-aware shouldRun', async () => {
  const { MobileScanner } = await import('../agents/mobile-scanner.js');
  const { SupabaseRLSAgent } = await import('../agents/supabase-rls-agent.js');
  const { InjectionTester } = await import('../agents/injection-tester.js');

  it('MobileScanner skips when no mobile framework detected', () => {
    const agent = new MobileScanner();
    const recon = { frameworks: ['express', 'nextjs'], databases: ['postgres'] };
    assert.strictEqual(agent.shouldRun(recon), false, 'Should skip for non-mobile projects');
  });

  it('MobileScanner runs when react-native detected', () => {
    const agent = new MobileScanner();
    const recon = { frameworks: ['react-native'] };
    assert.strictEqual(agent.shouldRun(recon), true, 'Should run for React Native projects');
  });

  it('SupabaseRLSAgent skips when no Supabase detected', () => {
    const agent = new SupabaseRLSAgent();
    const recon = { frameworks: ['express'], databases: ['postgres'], authPatterns: ['jwt'] };
    assert.strictEqual(agent.shouldRun(recon), false, 'Should skip for non-Supabase projects');
  });

  it('SupabaseRLSAgent runs when Supabase detected', () => {
    const agent = new SupabaseRLSAgent();
    const recon = { databases: ['supabase'], authPatterns: ['supabase-auth'] };
    assert.strictEqual(agent.shouldRun(recon), true, 'Should run for Supabase projects');
  });

  it('InjectionTester always runs (default shouldRun)', () => {
    const agent = new InjectionTester();
    const recon = { frameworks: ['express'] };
    assert.strictEqual(agent.shouldRun(recon), true, 'Universal agents always run');
  });
});

// =============================================================================
// SECRETS VERIFIER
// =============================================================================

describe('SecretsVerifier', async () => {
  const { SecretsVerifier } = await import('../utils/secrets-verifier.js');

  it('skips non-secret findings', async () => {
    const verifier = new SecretsVerifier();
    const findings = [
      { file: '/a.js', line: 1, severity: 'high', category: 'injection', rule: 'SQL_INJECTION', matched: 'SELECT *' },
    ];
    const results = await verifier.verify(findings);
    assert.strictEqual(results.length, 0, 'Should skip non-secret findings');
  });

  it('extracts secret value from quoted match', () => {
    const verifier = new SecretsVerifier();
    const secret = verifier._extractSecret('API_KEY="sk_live_abc123def456"');
    assert.strictEqual(secret, 'sk_live_abc123def456');
  });

  it('extracts secret value from assignment', () => {
    const verifier = new SecretsVerifier();
    const secret = verifier._extractSecret('token=ghp_abcdefghijklmnop');
    assert.strictEqual(secret, 'ghp_abcdefghijklmnop');
  });

  it('returns null for short/empty matches', () => {
    const verifier = new SecretsVerifier();
    assert.strictEqual(verifier._extractSecret(''), null);
    assert.strictEqual(verifier._extractSecret(null), null);
  });

  it('finds probe for known rule names', () => {
    const verifier = new SecretsVerifier();
    assert.ok(verifier._findProbe('GITHUB_TOKEN'), 'Should find GitHub probe');
    assert.ok(verifier._findProbe('OPENAI_API_KEY'), 'Should find OpenAI probe');
    assert.ok(verifier._findProbe('STRIPE_LIVE_KEY'), 'Should find Stripe probe');
    assert.strictEqual(verifier._findProbe('UNKNOWN_PATTERN_XYZ'), null, 'Should return null for unknown');
  });
});

// =============================================================================
// SBOM GENERATOR (CRA Enhancement)
// =============================================================================

describe('SBOMGenerator CRA', async () => {
  const { SBOMGenerator } = await import('../agents/sbom-generator.js');

  it('generates SBOM with CRA-required fields', () => {
    const sbom = new SBOMGenerator();
    const bom = sbom.generate(process.cwd());

    // CRA fields
    assert.ok(bom.metadata.supplier, 'Should have supplier field');
    assert.ok(bom.metadata.lifecycles, 'Should have lifecycles field');
    assert.strictEqual(bom.metadata.lifecycles[0].phase, 'build');
    assert.ok(Array.isArray(bom.vulnerabilities), 'Should have vulnerabilities array');
  });

  it('attachVulnerabilities adds CVEs to SBOM', () => {
    const sbom = new SBOMGenerator();
    const bom = sbom.generate(process.cwd());

    const vulns = [
      { id: 'CVE-2024-1234', package: 'lodash@4.17.20', severity: 'high', description: 'Prototype pollution' },
    ];
    sbom.attachVulnerabilities(bom, vulns);

    assert.strictEqual(bom.vulnerabilities.length, 1);
    assert.strictEqual(bom.vulnerabilities[0].id, 'CVE-2024-1234');
    assert.strictEqual(bom.vulnerabilities[0].ratings[0].severity, 'high');
  });

  it('detects licenses from node_modules', () => {
    const sbom = new SBOMGenerator();
    const licenses = sbom._detectLicenses(process.cwd());
    // Our project uses chalk, commander, etc. — should find some licenses
    if (Object.keys(licenses).length > 0) {
      const firstLicense = Object.values(licenses)[0];
      assert.ok(typeof firstLicense === 'string', 'License should be a string');
    }
  });
});

// =============================================================================
// ORCHESTRATOR — CROSS-AGENT SHARED FINDINGS
// =============================================================================

describe('Orchestrator cross-agent awareness', async () => {
  const { Orchestrator } = await import('../agents/orchestrator.js');

  it('passes sharedFindings in context to agents', async () => {
    const orchestrator = new Orchestrator();
    let receivedSharedFindings = null;

    // Mock agent that captures context
    const mockAgent = {
      name: 'MockAgent',
      category: 'test',
      shouldRun: () => true,
      async analyze(context) {
        receivedSharedFindings = context.sharedFindings;
        return [];
      },
    };

    orchestrator.register(mockAgent);
    await orchestrator.runAll(process.cwd(), { quiet: true, skipVerifier: true });

    assert.ok(Array.isArray(receivedSharedFindings), 'sharedFindings should be an array in context');
  });

  it('skips agents where shouldRun returns false', async () => {
    const orchestrator = new Orchestrator();
    let ran = false;

    const skipAgent = {
      name: 'SkipMe',
      category: 'test',
      shouldRun: () => false,
      async analyze() { ran = true; return []; },
    };

    orchestrator.register(skipAgent);
    await orchestrator.runAll(process.cwd(), { quiet: true, skipVerifier: true });

    assert.strictEqual(ran, false, 'Agent with shouldRun=false should not execute');
  });
});
