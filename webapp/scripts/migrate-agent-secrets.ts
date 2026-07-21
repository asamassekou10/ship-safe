import { PrismaClient } from '@prisma/client';
import { decryptAgentEnvVars, encryptAgentEnvVars, isEncryptedAgentEnvVars } from '../lib/agent-secrets.ts';

const prisma = new PrismaClient();
const rekey = process.argv.includes('--rekey');

try {
  const agents = await prisma.agent.findMany({ select: { id: true, envVars: true } });
  let migrated = 0;

  for (const agent of agents) {
    if (isEncryptedAgentEnvVars(agent.envVars) && !rekey) continue;
    await prisma.agent.update({
      where: { id: agent.id },
      data: { envVars: encryptAgentEnvVars(decryptAgentEnvVars(agent.envVars)) },
    });
    migrated += 1;
  }

  console.log(`${rekey ? 'Re-keyed' : 'Encrypted'} ${migrated} of ${agents.length} agent secret records.`);
} finally {
  await prisma.$disconnect();
}
