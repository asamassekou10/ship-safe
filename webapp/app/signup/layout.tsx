import type { Metadata } from 'next';

const ogImage = 'https://shipsafecli.com/api/og?title=Create+Your+Ship+Safe+Account&description=Start+scanning+for+LLM+vulnerabilities%2C+MCP+misconfigs%2C+secrets%2C+and+CVEs.+Free+to+get+started.&label=Sign+Up&badge=Free+forever';

export const metadata: Metadata = {
  title: 'Sign Up',
  description: 'Create your Ship Safe account. Get access to cloud scanning, scan history, team collaboration, and security reports.',
  alternates: {
    canonical: 'https://shipsafecli.com/signup',
  },
  openGraph: {
    title: 'Create Your Ship Safe Account',
    description: 'Start scanning for LLM vulnerabilities, MCP misconfigs, secrets, and CVEs. Free to get started.',
    type: 'website',
    url: 'https://shipsafecli.com/signup',
    siteName: 'Ship Safe',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Sign Up for Ship Safe' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Create Your Ship Safe Account',
    description: 'Start scanning for LLM vulnerabilities, MCP misconfigs, secrets, and CVEs. Free to get started.',
    images: [ogImage],
  },
};

export default function SignupLayout({ children }: { children: React.ReactNode }) {
  return children;
}
