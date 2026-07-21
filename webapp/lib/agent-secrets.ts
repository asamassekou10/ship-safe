import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const AGENT_SECRET_MASK = '********';

const FORMAT = 'ship-safe.agent-env.v1';
const AAD = Buffer.from(FORMAT, 'utf8');

interface EncryptedAgentEnvVars extends Record<string, string> {
  format: typeof FORMAT;
  iv: string;
  tag: string;
  ciphertext: string;
}

function encryptionKeys() {
  const secrets = [process.env.AGENT_SECRETS_KEY, process.env.AUTH_SECRET, process.env.NEXTAUTH_SECRET]
    .filter((secret): secret is string => Boolean(secret));
  const uniqueSecrets = [...new Set(secrets)];
  if (uniqueSecrets.length === 0) {
    throw new Error('AGENT_SECRETS_KEY or AUTH_SECRET must be configured before storing agent secrets.');
  }
  return uniqueSecrets.map(secret => createHash('sha256').update(secret, 'utf8').digest());
}

function sanitizeEnvVars(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};

  const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
  const safe: Record<string, string> = {};
  for (const [rawKey, rawValue] of Object.entries(value).slice(0, 50)) {
    const key = rawKey.trim().slice(0, 100);
    if (!key || blockedKeys.has(key) || typeof rawValue !== 'string') continue;
    safe[key] = rawValue.slice(0, 4096);
  }
  return safe;
}

export function isEncryptedAgentEnvVars(value: unknown): value is EncryptedAgentEnvVars {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const envelope = value as Record<string, unknown>;
  return envelope.format === FORMAT
    && typeof envelope.iv === 'string'
    && typeof envelope.tag === 'string'
    && typeof envelope.ciphertext === 'string';
}

export function encryptAgentEnvVars(value: unknown): EncryptedAgentEnvVars {
  const plaintext = JSON.stringify(sanitizeEnvVars(value));
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKeys()[0], iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  return {
    format: FORMAT,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

export function decryptAgentEnvVars(value: unknown): Record<string, string> {
  if (!isEncryptedAgentEnvVars(value)) return sanitizeEnvVars(value);

  for (const key of encryptionKeys()) {
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.iv, 'base64'));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(value.ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');
      return sanitizeEnvVars(JSON.parse(plaintext));
    } catch {
      continue;
    }
  }

  throw new Error('Unable to decrypt agent secrets with the configured encryption keys.');
}

export function maskAgentEnvVars(value: unknown): Record<string, string> {
  return Object.fromEntries(
    Object.keys(decryptAgentEnvVars(value)).map(key => [key, AGENT_SECRET_MASK]),
  );
}

export function mergeAgentEnvVarUpdate(stored: unknown, update: unknown): Record<string, string> {
  const current = decryptAgentEnvVars(stored);
  const incoming = sanitizeEnvVars(update);

  return Object.fromEntries(
    Object.entries(incoming).map(([key, value]) => [
      key,
      value === AGENT_SECRET_MASK && key in current ? current[key] : value,
    ]),
  );
}

export function maskAgentSecrets<T extends { envVars: unknown }>(agent: T): Omit<T, 'envVars'> & { envVars: Record<string, string> } {
  return { ...agent, envVars: maskAgentEnvVars(agent.envVars) };
}
