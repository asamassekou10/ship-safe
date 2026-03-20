import { Prisma } from '@prisma/client';
import { prisma } from './prisma';

export async function logAudit(params: {
  userId?: string;
  orgId?: string;
  action: string;
  target?: string;
  meta?: Record<string, unknown>;
  ip?: string;
}) {
  await prisma.auditLog.create({
    data: {
      ...params,
      meta: params.meta as Prisma.InputJsonValue | undefined,
    },
  }).catch(console.error);
}
