import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import type { Metadata } from 'next';
import ScanForm from './ScanForm';

export const metadata: Metadata = {
  title: 'New Scan — Ship Safe',
};

export default async function ScanPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  const isPaid = plan === 'pro' || plan === 'team' || plan === 'enterprise';

  const freeScansLimit = isPaid ? 0 : parseInt(process.env.FREE_SCAN_LIMIT ?? '1', 10);
  const freeScansUsed = isPaid ? 0 : await prisma.scan.count({ where: { userId: session.user.id } });

  return <ScanForm freeScansUsed={freeScansUsed} freeScansLimit={freeScansLimit} />;
}
