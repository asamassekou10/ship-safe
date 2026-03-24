export interface Plan {
  name: string;
  price: string;
  period: string;
  desc: string;
  cta: string;
  ctaHref: string;
  featured: boolean;
  features: string[];
}

export const plans: Plan[] = [
  {
    name: 'Pro',
    price: '$9',
    period: 'one-time',
    desc: 'For developers who ship fast and need full coverage.',
    cta: 'Buy Pro',
    ctaHref: '/app/checkout?plan=pro',
    featured: true,
    features: [
      'Unlimited cloud scans',
      'Private repos (GitHub, GitLab, upload)',
      'All 18 security agents',
      'AI deep analysis (bring your own API key)',
      'Scan history + score trends',
      'PDF reports (branded)',
      'API access for CI/CD webhooks',
      'Email notifications',
      'Priority support',
    ],
  },
  {
    name: 'Team',
    price: '$19',
    period: 'one-time per seat',
    desc: 'For teams that need collaboration and shared visibility.',
    cta: 'Buy Team',
    ctaHref: '/app/checkout?plan=team',
    featured: false,
    features: [
      'Everything in Pro',
      'Shared team workspace',
      'Role-based access (owner, admin, viewer)',
      'Slack + webhook notifications',
      'GitHub App (PR comments + checks)',
      'Aggregate team security score',
      'Audit log',
      'Dedicated support',
    ],
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    desc: 'On-premise, SSO, SLA, and custom policies.',
    cta: 'Contact us',
    ctaHref: 'mailto:hello@shipsafecli.com',
    featured: false,
    features: [
      'Everything in Team',
      'On-premise deployment',
      'SSO / SAML',
      'Custom security policies',
      'SLA & dedicated support',
      'Volume pricing',
    ],
  },
];

export const pricingFaq = [
  {
    q: 'Is the CLI always free?',
    a: 'Yes. The CLI is MIT open-source and will always be free. You can run unlimited scans locally on any repo. The paid plans are for the hosted web dashboard — cloud scans, scan history, team features, and PDF reports. AI features use your own API key (Anthropic, OpenAI, Gemini, or local Ollama).',
  },
  {
    q: 'What counts as a cloud scan?',
    a: 'A cloud scan is when you submit a repo through the web dashboard for scanning. Running the CLI locally never counts against any limit.',
  },
  {
    q: 'Is it really one-time? No subscriptions?',
    a: 'Yes. Pay once, use forever. No recurring charges, no surprise renewals. Future major version upgrades may be offered as optional paid upgrades at a discount.',
  },
  {
    q: 'Do you offer refunds?',
    a: 'Yes. If you are not satisfied within 30 days of purchase, we will issue a full refund — no questions asked.',
  },
];
