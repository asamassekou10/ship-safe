import type { Metadata } from 'next';
import { Geist, Geist_Mono, Instrument_Serif } from 'next/font/google';
import Providers from './providers';
import AuroraBackground from '@/components/AuroraBackground';
import ScrollProgress from '@/components/ScrollProgress';
import { Analytics } from '@vercel/analytics/next';
import './globals.css';

const geistSans = Geist({
  subsets: ['latin'],
  variable: '--font-geist-sans',
  display: 'swap',
});

const geistMono = Geist_Mono({
  subsets: ['latin'],
  variable: '--font-geist-mono',
  display: 'swap',
});

const instrumentSerif = Instrument_Serif({
  weight: '400',
  subsets: ['latin'],
  style: ['normal', 'italic'],
  variable: '--font-instrument-serif',
  display: 'swap',
});

export const metadata: Metadata = {
  title: {
    default: 'Ship Safe — AI Agent Security Scanner for Developers',
    template: '%s | Ship Safe',
  },
  description: 'AI agent security scanner that detects LLM vulnerabilities, MCP configuration security issues, RAG poisoning, secrets, and dependency CVEs. 24 agents, one command. Free CLI, no signup required.',
  metadataBase: new URL('https://www.shipsafecli.com'),
  keywords: ['AI agent security scanner', 'LLM vulnerability CLI', 'MCP configuration security', 'RAG poisoning prevention', 'security scanner', 'secret detection', 'LLM security', 'prompt injection scanner', 'OWASP Agentic AI Top 10', 'DevSecOps', 'application security', 'dependency CVE scanner', 'open source SAST'],
  alternates: {
    canonical: 'https://www.shipsafecli.com',
  },
  openGraph: {
    title: 'Ship Safe — AI Agent Security Scanner for Developers',
    description: '23 AI security agents detect LLM vulnerabilities, MCP misconfigurations, RAG poisoning, secrets, and CVEs. One command. Free and open source.',
    type: 'website',
    url: 'https://www.shipsafecli.com',
    siteName: 'Ship Safe',
    images: [{ url: 'https://www.shipsafecli.com/og1.png', width: 1200, height: 628, alt: 'Ship Safe - AI Agent Security Scanner' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe — AI Agent Security Scanner for Developers',
    description: '23 AI security agents detect LLM vulnerabilities, MCP misconfigurations, RAG poisoning, secrets, and CVEs. One command. Free and open source.',
    images: ['https://www.shipsafecli.com/og1.png'],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={`${geistSans.variable} ${geistMono.variable} ${instrumentSerif.variable}`}>
      <head>
        <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />
        <meta name="theme-color" content="#0a0a0a" media="(prefers-color-scheme: dark)" />
        <link rel="icon" type="image/png" href="/logo.png" />
      </head>
      <body>
        <ScrollProgress />
        <AuroraBackground />
        <Providers>{children}</Providers>
        <Analytics />
      </body>
    </html>
  );
}
