import type { MetadataRoute } from 'next';
import { posts } from '@/data/blog';

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = 'https://shipsafecli.com';

  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const blogEntries: MetadataRoute.Sitemap = posts.map((post) => {
    const postDate = new Date(post.date);
    const isRecent = postDate >= thirtyDaysAgo;
    return {
      url: `${baseUrl}/blog/${post.slug}`,
      lastModified: postDate,
      changeFrequency: isRecent ? 'weekly' : 'monthly',
      priority: isRecent ? 0.85 : 0.75,
    };
  });

  const latestPost = posts.length > 0 ? new Date(posts[0].date) : new Date('2026-04-01');

  return [
    {
      url: baseUrl,
      lastModified: latestPost,
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: `${baseUrl}/pricing`,
      lastModified: new Date('2026-04-01'),
      changeFrequency: 'monthly',
      priority: 0.9,
    },
    {
      url: `${baseUrl}/openclaw`,
      lastModified: new Date('2026-04-01'),
      changeFrequency: 'monthly',
      priority: 0.8,
    },
    {
      url: `${baseUrl}/hermes`,
      lastModified: new Date('2026-04-12'),
      changeFrequency: 'monthly',
      priority: 0.85,
    },
    {
      url: `${baseUrl}/breach/vercel-april-2026`,
      lastModified: new Date('2026-04-19'),
      changeFrequency: 'monthly',
      priority: 0.9,
    },
    {
      url: `${baseUrl}/docs`,
      lastModified: latestPost,
      changeFrequency: 'weekly',
      priority: 0.9,
    },
    {
      url: `${baseUrl}/blog`,
      lastModified: latestPost,
      changeFrequency: 'weekly',
      priority: 0.8,
    },
    ...blogEntries,
    {
      url: `${baseUrl}/login`,
      lastModified: new Date(),
      changeFrequency: 'yearly',
      priority: 0.3,
    },
    {
      url: `${baseUrl}/signup`,
      lastModified: new Date(),
      changeFrequency: 'yearly',
      priority: 0.4,
    },
  ];
}
