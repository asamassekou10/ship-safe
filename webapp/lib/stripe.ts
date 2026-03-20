import Stripe from 'stripe';

let _stripe: Stripe | null = null;

export function getStripe(): Stripe {
  if (!_stripe) {
    if (!process.env.STRIPE_SECRET_KEY) {
      throw new Error('STRIPE_SECRET_KEY is not set');
    }
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return _stripe;
}

/** @deprecated Use getStripe() instead */
export const stripe = new Proxy({} as Stripe, {
  get(_, prop) {
    return (getStripe() as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export const PLANS = {
  pro: {
    priceId: 'price_1TD476CDeQdNDMtzO0XkRs8o',
    price: 900, // $9 in cents
    name: 'Ship Safe Pro',
  },
  team: {
    priceId: 'price_1TD47iCDeQdNDMtzpvJelLIa',
    price: 1900, // $19 in cents
    name: 'Ship Safe Team',
  },
} as const;
