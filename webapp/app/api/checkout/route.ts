import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { stripe, PLANS } from '@/lib/stripe';

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id || !session.user.email) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { plan } = await req.json();

  if (plan !== 'pro' && plan !== 'team') {
    return NextResponse.json({ error: 'Invalid plan' }, { status: 400 });
  }

  const planConfig = PLANS[plan as keyof typeof PLANS];
  const origin = req.nextUrl.origin;

  const checkoutSession = await stripe.checkout.sessions.create({
    mode: 'payment',
    customer_email: session.user.email,
    line_items: [{ price: planConfig.priceId, quantity: 1 }],
    metadata: {
      userId: session.user.id,
      plan,
    },
    success_url: `${origin}/app?upgraded=${plan}`,
    cancel_url: `${origin}/pricing`,
  });

  // Record pending payment
  await prisma.payment.create({
    data: {
      userId: session.user.id,
      stripeSessionId: checkoutSession.id,
      plan,
      amount: planConfig.price,
      status: 'pending',
    },
  });

  return NextResponse.json({ url: checkoutSession.url });
}
