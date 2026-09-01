/**
 * Regression tests for scanner rules that previously treated ordinary source
 * data as executable security-sensitive code.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { AuthBypassAgent } from '../agents/auth-bypass-agent.js';
import { APIFuzzer } from '../agents/api-fuzzer.js';
import { InjectionTester } from '../agents/injection-tester.js';
import { SSRFProber } from '../agents/ssrf-prober.js';
import { SupplyChainAudit } from '../agents/supply-chain-agent.js';
import { dependencyName } from '../commands/deps.js';

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-fp-'));
  const paths = Object.entries(files).map(([name, content]) => {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    return file;
  });
  return { dir, paths };
}

function context(dir, paths) {
  return { rootPath: dir, files: paths, recon: {}, options: {} };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

describe('false-positive calibration', () => {
  it('does not treat auth links as missing-rate-limit endpoints', async () => {
    const { dir, paths } = fixture({
      'Nav.tsx': '<Link href="/login">Log in</Link>\n<Link href="/signup">Get started</Link>',
    });
    try {
      const findings = await new AuthBypassAgent().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule === 'NO_RATE_LIMIT_LOGIN').length, 0);
    } finally { cleanup(dir); }
  });

  it('still detects a mutation route for an auth endpoint', async () => {
    const { dir, paths } = fixture({
      'auth.js': 'app.post("/api/auth/login", authMiddleware, loginHandler);',
    });
    try {
      const findings = await new AuthBypassAgent().analyze(context(dir, paths));
      assert.ok(findings.some(f => f.rule === 'NO_RATE_LIMIT_LOGIN'));
    } finally { cleanup(dir); }
  });

  it('does not treat ordinary API filename fields as upload metadata', async () => {
    const { dir, paths } = fixture({
      'github.ts': 'const file = item as Record<string, unknown>;\nreturn { filename: file.filename };',
    });
    try {
      const findings = await new APIFuzzer().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule === 'API_UPLOAD_NO_TYPE_CHECK').length, 0);
    } finally { cleanup(dir); }
  });

  it('still detects an upload filename used without type validation', async () => {
    const { dir, paths } = fixture({
      'upload.js': 'import multer from "multer";\nconst upload = multer();\napp.post("/upload", upload.single("file"), (req, res) => res.send(req.file.originalname));',
    });
    try {
      const findings = await new APIFuzzer().analyze(context(dir, paths));
      assert.ok(findings.some(f => f.rule === 'API_UPLOAD_NO_TYPE_CHECK'));
    } finally { cleanup(dir); }
  });

  it('does not treat document.write inside a browser expression string as outer-file XSS', async () => {
    const { dir, paths } = fixture({
      'cdp.mjs': 'await evaluate("document.open(); document.write(\'<body>\'); document.close(); true");',
    });
    try {
      const findings = await new InjectionTester().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule === 'XSS_DOCUMENT_WRITE').length, 0);
    } finally { cleanup(dir); }
  });

  it('still detects a direct document.write call', async () => {
    const { dir, paths } = fixture({
      'page.js': 'document.write(userInput);',
    });
    try {
      const findings = await new InjectionTester().analyze(context(dir, paths));
      assert.ok(findings.some(f => f.rule === 'XSS_DOCUMENT_WRITE'));
    } finally { cleanup(dir); }
  });

  it('does not treat a metadata blocklist as metadata access', async () => {
    const { dir, paths } = fixture({
      'request-security.ts': "if (hostname === 'metadata.google.internal') return false;\nif (hostname === '169.254.169.254') return false;",
    });
    try {
      const findings = await new SSRFProber().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule === 'SSRF_CLOUD_METADATA').length, 0);
    } finally { cleanup(dir); }
  });

  it('still detects a request to a cloud metadata endpoint', async () => {
    const { dir, paths } = fixture({
      'metadata.js': 'const response = await fetch("http://169.254.169.254/latest/meta-data/");',
    });
    try {
      const findings = await new SSRFProber().analyze(context(dir, paths));
      assert.ok(findings.some(f => f.rule === 'SSRF_CLOUD_METADATA'));
    } finally { cleanup(dir); }
  });

  it('does not treat fixed URLs, same-origin client calls, or robots metadata as SSRF', async () => {
    const { dir, paths } = fixture({
      'pages.tsx': 'const url = process.env.CMS_URL;\nawait fetch(url);\nawait client.fetch(`/repos/${owner}/${repo}/issues/${id}`);\nawait fetch(`/api/findings?${params}`);\nconst metadata = { robots: { follow: true } };\nredirect("/security");',
    });
    try {
      const findings = await new SSRFProber().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule.startsWith('SSRF_')).length, 0);
    } finally { cleanup(dir); }
  });

  it('still detects request-derived URLs and redirect options', async () => {
    const { dir, paths } = fixture({
      'route.js': 'await fetch(req.query.url);\nawait fetch(`https://${req.query.host}/avatar`);\nawait fetch(target, { redirect: "follow" });',
    });
    try {
      const findings = await new SSRFProber().analyze(context(dir, paths));
      assert.ok(findings.some(f => f.rule === 'SSRF_USER_URL_FETCH'));
      assert.ok(findings.some(f => f.rule === 'SSRF_URL_TEMPLATE'));
      assert.ok(findings.some(f => f.rule === 'SSRF_REDIRECT_FOLLOW'));
    } finally { cleanup(dir); }
  });

  it('does not treat a fixed Chrome DevTools loopback endpoint as SSRF', async () => {
    const { dir, paths } = fixture({
      'cdp.mjs': 'await fetch(`http://127.0.0.1:${port}/json/list`);',
    });
    try {
      const findings = await new SSRFProber().analyze(context(dir, paths));
      assert.equal(findings.filter(f => f.rule === 'SSRF_INTERNAL_IP').length, 0);
    } finally { cleanup(dir); }
  });

  it('allows exact popular packages while retaining typo detection', async () => {
    const safe = fixture({
      'package.json': JSON.stringify({ dependencies: { next: '^15.3.1' } }),
    });
    const suspect = fixture({
      'package.json': JSON.stringify({ dependencies: { nexxt: '^15.3.1' } }),
    });
    try {
      const safeFindings = await new SupplyChainAudit().analyze(context(safe.dir, safe.paths));
      const suspectFindings = await new SupplyChainAudit().analyze(context(suspect.dir, suspect.paths));
      assert.equal(safeFindings.filter(f => f.rule === 'TYPOSQUAT_SUSPECT').length, 0);
      assert.ok(suspectFindings.some(f => f.rule === 'TYPOSQUAT_SUSPECT'));
    } finally {
      cleanup(safe.dir);
      cleanup(suspect.dir);
    }
  });

  it('uses normalized dependency names in every report format', () => {
    assert.equal(dependencyName({ name: 'next' }), 'next');
    assert.equal(dependencyName({ id: 'CVE-2026-0001' }), 'CVE-2026-0001');
    assert.equal(dependencyName({}), 'unknown');
  });
});
