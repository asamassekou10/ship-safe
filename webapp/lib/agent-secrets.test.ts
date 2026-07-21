import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AGENT_SECRET_MASK,
  decryptAgentEnvVars,
  encryptAgentEnvVars,
  isEncryptedAgentEnvVars,
  maskAgentEnvVars,
  mergeAgentEnvVarUpdate,
} from './agent-secrets.ts';

process.env.AGENT_SECRETS_KEY = 'test-only-agent-secret-key';

test('encrypts and decrypts agent environment variables', () => {
  const source = { OPENAI_API_KEY: 'sk-test', REGION: 'us-east-1' };
  const encrypted = encryptAgentEnvVars(source);

  assert.equal(isEncryptedAgentEnvVars(encrypted), true);
  assert.equal(JSON.stringify(encrypted).includes('sk-test'), false);
  assert.deepEqual(decryptAgentEnvVars(encrypted), source);
});

test('masks all values returned to the client', () => {
  const encrypted = encryptAgentEnvVars({ OPENAI_API_KEY: 'sk-test', REGION: 'us-east-1' });
  assert.deepEqual(maskAgentEnvVars(encrypted), {
    OPENAI_API_KEY: AGENT_SECRET_MASK,
    REGION: AGENT_SECRET_MASK,
  });
});

test('preserves masked values while allowing replacement and deletion', () => {
  const encrypted = encryptAgentEnvVars({ OPENAI_API_KEY: 'old-key', REGION: 'us-east-1', REMOVE_ME: 'yes' });
  const merged = mergeAgentEnvVarUpdate(encrypted, {
    OPENAI_API_KEY: AGENT_SECRET_MASK,
    REGION: 'eu-west-1',
  });

  assert.deepEqual(merged, { OPENAI_API_KEY: 'old-key', REGION: 'eu-west-1' });
});

test('reads legacy plaintext records for migration compatibility', () => {
  assert.deepEqual(decryptAgentEnvVars({ KIMI_API_KEY: 'legacy-key' }), { KIMI_API_KEY: 'legacy-key' });
});

test('falls back to the auth secret after a dedicated key is introduced', () => {
  delete process.env.AGENT_SECRETS_KEY;
  process.env.AUTH_SECRET = 'existing-auth-secret';
  const encrypted = encryptAgentEnvVars({ OPENAI_API_KEY: 'existing-key' });

  process.env.AGENT_SECRETS_KEY = 'new-dedicated-secret';
  assert.deepEqual(decryptAgentEnvVars(encrypted), { OPENAI_API_KEY: 'existing-key' });

  delete process.env.AUTH_SECRET;
  process.env.AGENT_SECRETS_KEY = 'test-only-agent-secret-key';
});
