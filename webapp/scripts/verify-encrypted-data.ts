import { PrismaClient } from '@prisma/client';
import { decryptAgentEnvVars, isEncryptedAgentEnvVars } from '../lib/agent-secrets.ts';
import { readLLMSettings } from '../lib/llm-credentials.ts';

if (!process.env.AGENT_SECRETS_KEY) {
  throw new Error('AGENT_SECRETS_KEY is required for dedicated-key verification.');
}

const prisma = new PrismaClient();

try {
  const [agents, users] = await Promise.all([
    prisma.agent.findMany({ select: { envVars: true } }),
    prisma.user.findMany({ select: { llmSettings: true } }),
  ]);
  const settings = users
    .map(user => user.llmSettings)
    .filter((value): value is NonNullable<typeof value> => Boolean(value));

  if (agents.some(agent => !isEncryptedAgentEnvVars(agent.envVars))) {
    throw new Error('At least one agent credential record is not encrypted.');
  }
  if (settings.some(value => {
    const record = value as Record<string, unknown>;
    return !isEncryptedAgentEnvVars(record.apiKeys);
  })) {
    throw new Error('At least one LLM settings record is not encrypted.');
  }

  delete process.env.AUTH_SECRET;
  delete process.env.NEXTAUTH_SECRET;

  agents.forEach(agent => decryptAgentEnvVars(agent.envVars));
  settings.forEach(value => readLLMSettings(value));

  console.log(`Verified ${agents.length} agent and ${settings.length} LLM settings records with AGENT_SECRETS_KEY only.`);
} finally {
  await prisma.$disconnect();
}
