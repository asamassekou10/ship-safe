import { PrismaClient } from '@prisma/client';
import { isEncryptedAgentEnvVars } from '../lib/agent-secrets.ts';
import { secureLLMSettings } from '../lib/llm-credentials.ts';

const prisma = new PrismaClient();
const rekey = process.argv.includes('--rekey');

try {
  const users = await prisma.user.findMany({
    select: { id: true, llmSettings: true },
  });
  const settingsUsers = users.filter(user => user.llmSettings);
  let migrated = 0;

  for (const user of settingsUsers) {
    const settings = user.llmSettings as Record<string, unknown>;
    if (isEncryptedAgentEnvVars(settings.apiKeys) && !rekey) continue;
    await prisma.user.update({
      where: { id: user.id },
      data: { llmSettings: secureLLMSettings(settings, settings) },
    });
    migrated += 1;
  }

  console.log(`${rekey ? 'Re-keyed' : 'Encrypted'} ${migrated} of ${settingsUsers.length} LLM settings records.`);
} finally {
  await prisma.$disconnect();
}
