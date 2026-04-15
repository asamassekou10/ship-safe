import { NextRequest, NextResponse } from 'next/server';
import { stripe } from '@/lib/stripe';
import { prisma } from '@/lib/prisma';

export async function POST(req: NextRequest) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature');

  if (!sig) {
    return NextResponse.json({ error: 'Missing signature' }, { status: 400 });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.userId;
    const plan = session.metadata?.plan;

    if (userId && plan) {
      await prisma.user.update({
        where: { id: userId },
        data: { plan },
      });

      await prisma.payment.updateMany({
        where: { stripeSessionId: session.id },
        data: {
          status: 'paid',
          stripePaymentId: session.subscription as string,
        },
      });
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    const payment = await prisma.payment.findFirst({
      where: { stripePaymentId: subscription.id },
    });
    if (payment) {
      await prisma.user.update({
        where: { id: payment.userId },
        data: { plan: 'free' },
      });
      await prisma.payment.updateMany({
        where: { stripePaymentId: subscription.id },
        data: { status: 'refunded' },
      });
    }
  }

  return NextResponse.json({ received: true });
}
