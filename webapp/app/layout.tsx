import type { Metadata } from 'next';
import Providers from './providers';
import AuroraBackground from '@/components/AuroraBackground';
import { Analytics } from '@vercel/analytics/next';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'Ship Safe — AI Agent Security Scanner for Developers',
    template: '%s | Ship Safe',
  },
  description: 'AI agent security scanner that detects LLM vulnerabilities, MCP configuration security issues, RAG poisoning, secrets, and dependency CVEs. 19 agents, one command. Free CLI, no signup required.',
  metadataBase: new URL('https://www.shipsafecli.com'),
  keywords: ['AI agent security scanner', 'LLM vulnerability CLI', 'MCP configuration security', 'RAG poisoning prevention', 'security scanner', 'secret detection', 'LLM security', 'prompt injection scanner', 'OWASP Agentic AI Top 10', 'DevSecOps', 'application security', 'dependency CVE scanner', 'open source SAST'],
  alternates: {
    canonical: 'https://www.shipsafecli.com',
  },
  openGraph: {
    title: 'Ship Safe — AI Agent Security Scanner for Developers',
    description: '19 AI security agents detect LLM vulnerabilities, MCP misconfigurations, RAG poisoning, secrets, and CVEs. One command. Free and open source.',
    type: 'website',
    url: 'https://www.shipsafecli.com',
    siteName: 'Ship Safe',
    images: [{ url: 'https://www.shipsafecli.com/api/og?title=Ship+Safe&description=19+AI+security+agents+detect+LLM+vulnerabilities%2C+MCP+misconfigurations%2C+RAG+poisoning%2C+secrets%2C+and+CVEs.+Free+and+open+source.&label=AI+Agent+Security+Scanner&badge=MIT+Open+Source', width: 1200, height: 630, alt: 'Ship Safe - AI Agent Security Scanner' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Ship Safe — AI Agent Security Scanner for Developers',
    description: '19 AI security agents detect LLM vulnerabilities, MCP misconfigurations, RAG poisoning, secrets, and CVEs. One command. Free and open source.',
    images: ['https://www.shipsafecli.com/api/og?title=Ship+Safe&description=19+AI+security+agents+detect+LLM+vulnerabilities%2C+MCP+misconfigurations%2C+RAG+poisoning%2C+secrets%2C+and+CVEs.+Free+and+open+source.&label=AI+Agent+Security+Scanner&badge=MIT+Open+Source'],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />
        <meta name="theme-color" content="#0a0a0a" media="(prefers-color-scheme: dark)" />
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
