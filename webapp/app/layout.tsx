import type { Metadata } from 'next';
import Providers from './providers';
import AuroraBackground from '@/components/AuroraBackground';
import { Analytics } from '@vercel/analytics/next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Ship Safe — Find Security Vulnerabilities Before You Ship',
  description: 'Scan your codebase for secrets, vulnerabilities, and dependency CVEs. Get a 0-100 security score in seconds. Free CLI, no signup required.',
  metadataBase: new URL('https://shipsafe.dev'),
  openGraph: {
    title: 'Ship Safe — Find Security Vulnerabilities Before You Ship',
    description: 'Scan your codebase for secrets, vulnerabilities, and dependency CVEs. Get a 0-100 security score in seconds. Free CLI, no signup required.',
    type: 'website',
    url: 'https://shipsafe.dev',
    siteName: 'Ship Safe',
    images: [{ url: 'https://shipsafe.dev/api/og', width: 1200, height: 630, alt: 'Ship Safe' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe — Find Security Vulnerabilities Before You Ship',
    description: 'Scan your codebase for secrets, vulnerabilities, and dependency CVEs. Get a 0-100 security score in seconds. Free CLI, no signup required.',
    images: ['https://shipsafe.dev/api/og'],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta name="theme-color" content="#ffffff" />
        <link rel="icon" type="image/png" href="/logo.png" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <AuroraBackground />
        <Providers>{children}</Providers>
        <Analytics />
      </body>
    </html>
  );
}
