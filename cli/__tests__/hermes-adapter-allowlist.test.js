import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { HermesSecurityAgent } from '../agents/hermes-security-agent.js';

function project(content, relativePath) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-hermes-adapter-'));
  const file = path.join(dir, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return { dir, file };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

async function scan(content, relativePath = 'plugins/platforms/telegram/adapter.py') {
  const fixture = project(content, relativePath);
  try {
    return await new HermesSecurityAgent().analyze({
      rootPath: fixture.dir,
      files: [fixture.file],
      recon: {},
      options: {},
    });
  } finally {
    cleanup(fixture.dir);
  }
}

describe('Hermes network adapter allowlist boundary', () => {
  it('detects an empty allowlist that falls through to agent dispatch', async () => {
    const findings = await scan(`
from hermes_agent.gateway import dispatch_agent

class TelegramAdapter:
    async def handle_message(self, message):
        self.allowlist = self.config.get("allowlist", [])
        if not self.allowlist:
            return await dispatch_agent(message)
        return await dispatch_agent(message)
`);

    const finding = findings.find((item) => item.rule === 'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN');
    assert.ok(finding, 'expected a fail-open adapter finding');
    assert.equal(finding.severity, 'critical');
    assert.equal(finding.posture, 'boundary');
  });

  it('detects a session ID used as the only authorization gate', async () => {
    const findings = await scan(`
from hermes_agent.gateway import resolve_gateway_approval

class WebhookAdapter:
    async def resolve_approval(self, session_id, approval_id):
        if session_id:
            return await resolve_gateway_approval(session_id, approval_id)
        return None
`);

    assert.ok(findings.some((item) => item.rule === 'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN'));
  });

  it('accepts an explicit non-empty allowlist with fail-closed rejection', async () => {
    const findings = await scan(`
from hermes_agent.gateway import dispatch_agent

class TelegramAdapter:
    async def handle_message(self, message, sender_id):
        if not self.allowlist or sender_id not in self.allowlist:
            raise PermissionError("sender is not allowed")
        return await dispatch_agent(message)
`);

    assert.equal(
      findings.filter((item) => item.rule === 'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN').length,
      0,
      'a fail-closed adapter should not be reported'
    );
  });

  it('does not treat comments or docstrings as authorization evidence', async () => {
    const findings = await scan(`
from hermes_agent.gateway import dispatch_agent

class TelegramAdapter:
    async def handle_message(self, message):
        """The allowlist must reject unauthorized senders with PermissionError."""
        # allowlist and raise PermissionError are documented above, not enforced here.
        return await dispatch_agent(message)
`);

    assert.ok(
      findings.some((item) => item.rule === 'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN'),
      'comments and docstrings must not suppress a missing authorization check'
    );
  });

  it('does not treat ACP/local IPC as a network adapter boundary', async () => {
    const findings = await scan(`
from hermes_agent.acp_adapter import dispatch_agent

class AcpAdapter:
    async def handle_message(self, message, session_id):
        if session_id:
            return await dispatch_agent(message, session_id=session_id)
        return None
`, 'acp_adapter/permissions.py');

    assert.equal(
      findings.filter((item) => item.rule === 'HERMES_ADAPTER_ALLOWLIST_FAIL_OPEN').length,
      0,
      'ACP/local IPC is intentionally outside the network-adapter rule'
    );
  });
});
