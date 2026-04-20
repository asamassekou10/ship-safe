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
        allow: '/',
        disallow: ['/app/', '/api/'],
      },
    ],
    sitemap: 'https://www.shipsafecli.com/sitemap.xml',
  };
}
