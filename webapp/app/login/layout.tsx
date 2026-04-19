import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Log In',
  description: 'Log in to your Ship Safe dashboard. Access cloud scanning, scan history, team management, and security reports.',
  alternates: {
    canonical: 'https://shipsafecli.com/login',
  },
  robots: {
    index: false,
  },
};

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children;
}
