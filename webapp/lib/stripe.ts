import Stripe from 'stripe';

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export const PLANS = {
  pro: {
    price: 900, // $9 in cents
    name: 'Ship Safe Pro',
  },
  team: {
    price: 1900, // $19 in cents
    name: 'Ship Safe Team',
  },
} as const;
