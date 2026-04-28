import { NextRequest, NextResponse } from 'next/server';
import { stripe, PLANS } from '@/lib/stripe';
import { prisma } from '@/lib/prisma';

const PRICE_TO_PLAN: Record<string, string> = Object.fromEntries(
  Object.entries(PLANS).map(([plan, { priceId }]) => [priceId, plan])
);

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

  if (event.type === 'customer.subscription.updated') {
    const subscription = event.data.object;
    const priceId = subscription.items.data[0]?.price.id;
    const newPlan = priceId ? PRICE_TO_PLAN[priceId] : undefined;
    if (newPlan) {
      const payment = await prisma.payment.findFirst({
        where: { stripePaymentId: subscription.id },
      });
      if (payment) {
        await prisma.user.update({
          where: { id: payment.userId },
          data: { plan: newPlan },
        });
        await prisma.payment.updateMany({
          where: { stripePaymentId: subscription.id },
          data: { plan: newPlan },
        });
      }
    }
  }

  if (event.type === 'invoice.payment_failed') {
    const invoice = event.data.object;
    const subDetails = invoice.parent?.subscription_details?.subscription;
    const subscriptionId = typeof subDetails === 'string' ? subDetails : subDetails?.id;
    if (subscriptionId) {
      await prisma.payment.updateMany({
        where: { stripePaymentId: subscriptionId },
        data: { status: 'failed' },
      });
    }
    console.error(`Payment failed for invoice ${invoice.id}, customer ${invoice.customer}`);
  }

  return NextResponse.json({ received: true });
}
