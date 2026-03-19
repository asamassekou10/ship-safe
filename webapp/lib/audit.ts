import { prisma } from './prisma';

export async function logAudit(params: {
  userId?: string;
  orgId?: string;
  action: string;
  target?: string;
  meta?: Record<string, unknown>;
  ip?: string;
}) {
  await prisma.auditLog.create({ data: params }).catch(console.error);
}
