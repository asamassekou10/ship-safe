import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

// GET — get notification settings
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  let settings = await prisma.notificationSetting.findUnique({
    where: { userId: session.user.id },
  });

  // Create defaults if not exists
  if (!settings) {
    settings = await prisma.notificationSetting.create({
      data: { userId: session.user.id },
    });
  }

  return NextResponse.json(settings);
}

// PUT — update notification settings
export async function PUT(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json();
  const {
    emailOnComplete,
    emailOnCritical,
    emailDigest,
    slackWebhookUrl,
    slackOnComplete,
    slackOnCritical,
  } = body;

  const settings = await prisma.notificationSetting.upsert({
    where: { userId: session.user.id },
    create: {
      userId: session.user.id,
      ...(emailOnComplete !== undefined && { emailOnComplete }),
      ...(emailOnCritical !== undefined && { emailOnCritical }),
      ...(emailDigest !== undefined && { emailDigest }),
      ...(slackWebhookUrl !== undefined && { slackWebhookUrl }),
      ...(slackOnComplete !== undefined && { slackOnComplete }),
      ...(slackOnCritical !== undefined && { slackOnCritical }),
    },
    update: {
      ...(emailOnComplete !== undefined && { emailOnComplete }),
      ...(emailOnCritical !== undefined && { emailOnCritical }),
      ...(emailDigest !== undefined && { emailDigest }),
      ...(slackWebhookUrl !== undefined && { slackWebhookUrl }),
      ...(slackOnComplete !== undefined && { slackOnComplete }),
      ...(slackOnCritical !== undefined && { slackOnCritical }),
    },
  });

  return NextResponse.json(settings);
}
