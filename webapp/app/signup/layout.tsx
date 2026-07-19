import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/og1.png';

export const metadata: Metadata = {
  title: 'Sign Up',
  description: 'Create your Ship Safe account. Get access to cloud scanning, scan history, team collaboration, and security reports.',
  alternates: {
    canonical: 'https://www.shipsafecli.com/signup',
  },
  openGraph: {
    title: 'Create Your Ship Safe Account',
    description: 'Start scanning for LLM vulnerabilities, MCP misconfigs, secrets, and CVEs. Free to get started.',
    type: 'website',
    url: 'https://www.shipsafecli.com/signup',
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Sign Up for Ship Safe' }],
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
