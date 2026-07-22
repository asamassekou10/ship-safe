import type { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: ['Twitterbot', 'facebookexternalhit', 'LinkedInBot', 'Slackbot', 'WhatsApp', 'Discordbot', 'iMessageBot'],
        allow: '/',
      },
      {
        userAgent: '*',
        allow: ['/', '/app/guide'],
        disallow: [
          '/api/',
          '/app/admin',
          '/app/agent-teams',
          '/app/agents',
          '/app/checkout',
          '/app/compare',
          '/app/content-agent',
          '/app/deploy',
          '/app/findings',
          '/app/guardian',
          '/app/history',
          '/app/intelligence',
          '/app/onboarding',
          '/app/policies',
          '/app/repos',
          '/app/scan',
          '/app/scans',
          '/app/settings',
          '/app/team',
          '/app/team-runs',
        ],
      },
    ],
    sitemap: 'https://www.shipsafecli.com/sitemap.xml',
  };
}
