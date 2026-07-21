import {
  decryptAgentEnvVars,
  encryptAgentEnvVars,
  maskAgentEnvVars,
  mergeAgentEnvVarUpdate,
} from './agent-secrets.ts';

export const LLM_API_KEYS = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'DEEPSEEK_API_KEY',
  'MOONSHOT_API_KEY',
  'KIMI_API_KEY',
  'XAI_API_KEY',
  'GOOGLE_API_KEY',
] as const;

export interface LLMSettingsValue {
  provider: string;
  model: string;
  think: boolean;
  swarm: boolean;
  apiKeys: Record<string, string>;
}

type StoredLLMSettings = Record<string, string | boolean | Record<string, string>>;

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function allowedApiKeys(value: unknown): Record<string, string> {
  const input = objectValue(value);
  return Object.fromEntries(
    Object.entries(input)
      .filter(([key, item]) => LLM_API_KEYS.includes(key as typeof LLM_API_KEYS[number]) && typeof item === 'string')
      .map(([key, item]) => [key, (item as string).slice(0, 4096)]),
  );
}

export function readLLMSettings(value: unknown): LLMSettingsValue {
  const settings = objectValue(value);
  const apiKeys = allowedApiKeys(decryptAgentEnvVars(settings.apiKeys));

  return {
    provider: typeof settings.provider === 'string' ? settings.provider : 'auto',
    model: typeof settings.model === 'string' ? settings.model : '',
    think: settings.think === true,
    swarm: settings.swarm === true,
    apiKeys,
  };
}

export function maskLLMSettings(value: unknown): LLMSettingsValue | null {
  if (!value) return null;
  const settings = readLLMSettings(value);
  return { ...settings, apiKeys: maskAgentEnvVars(settings.apiKeys) };
}

export function secureLLMSettings(update: unknown, stored?: unknown): StoredLLMSettings {
  const next = objectValue(update);
  const current = readLLMSettings(stored);
  const incomingKeys = allowedApiKeys(next.apiKeys);
  const mergedKeys = mergeAgentEnvVarUpdate(current.apiKeys, incomingKeys);
  const apiKeys = Object.fromEntries(Object.entries(mergedKeys).filter(([, value]) => value.trim()));

  return {
    provider: typeof next.provider === 'string' ? next.provider : current.provider,
    model: typeof next.model === 'string' ? next.model.slice(0, 120) : current.model,
    think: typeof next.think === 'boolean' ? next.think : current.think,
    swarm: typeof next.swarm === 'boolean' ? next.swarm : current.swarm,
    apiKeys: encryptAgentEnvVars(apiKeys),
  };
}
