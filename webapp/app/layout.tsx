import type { Metadata } from 'next';
import Providers from './providers';
import AuroraBackground from '@/components/AuroraBackground';
import './globals.css';

export const metadata: Metadata = {
  title: 'Ship Safe — Security toolkit for vibe coders',
  description: 'Scan for secrets, detect code vulnerabilities, audit dependencies, and get a 0-100 security score. Free CLI, no signup required.',
  metadataBase: new URL('https://shipsafe.dev'),
  openGraph: {
    title: 'Ship Safe — Security toolkit for vibe coders',
    description: 'Scan for secrets, detect code vulnerabilities, audit dependencies, and get a 0-100 security score.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe — Security toolkit for vibe coders',
    description: 'Scan for secrets, detect code vulnerabilities, audit dependencies, and get a 0-100 security score.',
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
      </body>
    </html>
  );
}
