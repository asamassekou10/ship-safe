import Nav from '@/components/Nav';
import Hero from '@/components/Hero';
import TrustBar from '@/components/TrustBar';
import HowItWorks from '@/components/HowItWorks';
import Features from '@/components/Features';
import PricingTeaser from '@/components/PricingTeaser';
import FAQ from '@/components/FAQ';
import CTA from '@/components/CTA';
import ScrollAnimator from '@/components/ScrollAnimator';
import DemoScanner from '@/components/DemoScanner';
import { getRepoStats } from '@/lib/stats';

export default async function Home() {
  const { stars, downloads } = await getRepoStats();

  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main>
        <Hero stars={stars} downloads={downloads} />
        <TrustBar stars={stars} downloads={downloads} />
        <DemoScanner />
        <HowItWorks />
        <Features />
        <PricingTeaser />
        <FAQ />
      </main>
      <CTA />
    </>
  );
}
