"use client";
import Header from "@/component/landing/header";
import HeroSection from "@/component/landing/hero";
import LogoCarousel from "@/component/landing/logo-carousel";
import FutureAI from "@/component/landing/future-ai";
import PlatformStack from "@/component/landing/platform-stack";
import ExperienceSamvaad from "@/component/landing/experience-samvaad";
import DeploymentOptions from "@/component/landing/deployment-options";
import Testimonials from "@/component/landing/testimonials";
import ResearchUpdates from "@/component/landing/research-updates";
import CTAFooter from "@/component/landing/Cta-footer";

export default function Home() {
  return (
    <div className="min-h-screen bg-[#F8F9FB] overflow-x-hidden">
      <Header />
      <main>
        <HeroSection />
        {/* <LogoCarousel /> */}
        <FutureAI />
        <PlatformStack />
        <ExperienceSamvaad />
        <DeploymentOptions />
        <Testimonials />
        <ResearchUpdates />
        <CTAFooter />
      </main>
    </div>
  );
}
