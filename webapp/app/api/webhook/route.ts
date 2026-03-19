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
      // Upgrade user plan
      await prisma.user.update({
        where: { id: userId },
        data: { plan },
      });

      // Mark payment as paid
      await prisma.payment.updateMany({
        where: { stripeSessionId: session.id },
        data: {
          status: 'paid',
          stripePaymentId: session.payment_intent as string,
        },
      });
    }
  }

  return NextResponse.json({ received: true });
}
