import Nav from '@/components/Nav';
import Hero from '@/components/Hero';
import Stats from '@/components/Stats';
import Terminal from '@/components/Terminal';
import BeforeAfter from '@/components/BeforeAfter';
import Pillars from '@/components/Pillars';
import Agents from '@/components/Agents';
import HowItWorks from '@/components/HowItWorks';
import Commands from '@/components/Commands';
import CICD from '@/components/CICD';
import FAQ from '@/components/FAQ';
import CTA from '@/components/CTA';
import ScrollAnimator from '@/components/ScrollAnimator';

export default function Home() {
  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main>
        <Hero />
        <Stats />
        <Terminal />
        <BeforeAfter />
        <Pillars />
        <Agents />
        <HowItWorks />
        <Commands />
        <CICD />
        <FAQ />
      </main>
      <CTA />
    </>
  );
}
