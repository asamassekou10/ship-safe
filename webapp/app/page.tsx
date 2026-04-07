import type { Metadata } from 'next';
import Nav from '@/components/Nav';
import Hero from '@/components/Hero';
import TrustBar from '@/components/TrustBar';
import HowItWorks from '@/components/HowItWorks';
import Features from '@/components/Features';
import AgentDirectory from '@/components/AgentDirectory';
import AccuracyBenchmark from '@/components/AccuracyBenchmark';
import ComparisonTable from '@/components/ComparisonTable';
import PricingTeaser from '@/components/PricingTeaser';
import FAQ from '@/components/FAQ';
import CTA from '@/components/CTA';
import ScrollAnimator from '@/components/ScrollAnimator';
import DemoScanner from '@/components/DemoScanner';
import ThreatMarquee from '@/components/ThreatMarquee';
import RecentPosts from '@/components/RecentPosts';
import { getRepoStats } from '@/lib/stats';

export const metadata: Metadata = {
  title: 'Ship Safe — AI Agent Security Scanner for Developers',
  description: '19 AI security agents scan your codebase for LLM vulnerabilities, MCP configuration security issues, RAG poisoning, secrets, and dependency CVEs. OWASP Agentic AI Top 10 mapping, live advisory feeds, deep watch mode. Free CLI.',
  keywords: ['AI agent security scanner', 'LLM vulnerability CLI', 'MCP configuration security', 'RAG poisoning prevention', 'prevent RAG poisoning', 'application security scanner', 'AI security agents', 'secret scanner', 'OWASP Agentic AI Top 10', 'memory poisoning detection', 'prompt injection scanner', 'DevSecOps tool', 'free security scanner', 'open source SAST'],
  alternates: {
    canonical: 'https://www.shipsafecli.com',
  },
};

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'SoftwareApplication',
      name: 'Ship Safe',
      applicationCategory: 'DeveloperApplication',
      operatingSystem: 'Windows, macOS, Linux',
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'USD',
      },
      description: '19 AI security agents scan your codebase for secrets, vulnerabilities, memory poisoning, and dependency CVEs in one command.',
      url: 'https://www.shipsafecli.com',
      downloadUrl: 'https://www.npmjs.com/package/ship-safe',
      softwareVersion: '7.0.0',
      author: {
        '@type': 'Organization',
        name: 'Ship Safe',
        url: 'https://www.shipsafecli.com',
      },
    },
    {
      '@type': 'FAQPage',
      mainEntity: [
        {
          '@type': 'Question',
          name: 'Does Ship Safe work without an API key?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Yes. All core commands (audit, scan, red-team, ci, score, deps, diff, vibe-check, benchmark, guard) work fully offline with no API key. AI classification is optional.',
          },
        },
        {
          '@type': 'Question',
          name: 'Is my code sent to an LLM?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Only if you use the agent command or omit --no-ai. When AI is used, only matched snippets are sent. Secret values are masked. The audit command with --no-ai is fully local.',
          },
        },
        {
          '@type': 'Question',
          name: 'How is Ship Safe different from Semgrep or Snyk?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Ship Safe is purpose-built for indie devs and small teams. One command covers secrets, code vulns, deps, config, CI/CD, LLM security, and mobile with no account, no config files, and no dashboard to log into.',
          },
        },
        {
          '@type': 'Question',
          name: 'What about false positives?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Ship Safe has context-aware confidence tuning that automatically downgrades findings in test files, documentation, comments, and example code, reducing false positives by up to 70%.',
          },
        },
        {
          '@type': 'Question',
          name: 'Is the CLI always free?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Yes. The CLI is MIT open-source and will always be free. You can run unlimited scans locally on any repo. The paid plans are for the hosted web dashboard.',
          },
        },
        {
          '@type': 'Question',
          name: 'Is it safe to run in CI?',
          acceptedAnswer: {
            '@type': 'Answer',
            text: 'Yes. Use ship-safe ci for pipeline-optimized output with threshold gating, severity-based failure, and GitHub PR comments. SARIF output is available for GitHub Security tab.',
          },
        },
      ],
    },
    {
      '@type': 'Organization',
      name: 'Ship Safe',
      url: 'https://www.shipsafecli.com',
      logo: 'https://www.shipsafecli.com/logo.png',
      sameAs: [
        'https://github.com/asamassekou10/ship-safe',
        'https://www.npmjs.com/package/ship-safe',
      ],
    },
  ],
};

export default async function Home() {
  const { stars, downloads } = await getRepoStats();

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore — static JSON-LD, no user input
      />
      <ScrollAnimator />
      <Nav />
      <main>
        <Hero stars={stars} downloads={downloads} />
        <TrustBar stars={stars} downloads={downloads} />
        <DemoScanner />
        <HowItWorks />
        <Features />
        <AgentDirectory />
        <ThreatMarquee />
        <AccuracyBenchmark />
        <ComparisonTable />
        <PricingTeaser />
        <RecentPosts />
        <FAQ />
      </main>
      <CTA />
    </>
  );
}
