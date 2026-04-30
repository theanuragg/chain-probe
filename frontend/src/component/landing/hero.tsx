"use client";

import React from 'react';

const HeroSection = () => {
  return (
    <section className="relative flex flex-col pt-28 md:pt-40 h-screen min-h-[850px] overflow-visible items-center bg-[#F8F9FB]">
      <div className="flex flex-1 justify-center items-center mx-auto pb-[12vh] w-[85%] md:w-9/12 max-w-[1440px] overflow-visible relative">
        {/* Decorative Background Gradient */}
        <div className="absolute top-[-80%] md:top-[-165%] left-1/2 -translate-x-1/2 w-[160%] md:w-[220%] max-w-none h-auto scale-x-200 scale-y-170 pointer-events-none z-0 opacity-90">
          <div className="w-full h-full bg-gradient-to-b from-[#556ADC]/10 via-[#BED2FF]/5 to-transparent rounded-full blur-3xl" />
        </div>

        {/* Central Glow Effect */}
        <div className="top-1/2 left-1/2 absolute opacity-30 md:opacity-40 blur-[80px] md:blur-[100px] w-[300px] md:w-[600px] h-[200px] md:h-[400px] -translate-x-1/2 -translate-y-1/2 pointer-events-none bg-[#556ADC] rounded-full z-0"></div>

        {/* Content Container */}
        <div className="z-10 relative flex flex-col items-center gap-5 md:gap-10">
          {/* Shimmer Badge */}
          <div className="relative bg-white/50 shadow-[0px_0px_60px_0px_rgba(85,106,220,0.12)] backdrop-blur-lg px-5 py-2.5 border border-[#556ADC]/20 rounded-full overflow-hidden">
            <p className="relative font-display font-semibold text-[#556ADC] text-sm text-center leading-normal tracking-wide">
              Solana&apos;s static analysis engine
            </p>
          </div>

          {/* Main Typography */}
          <div className="flex flex-col items-center gap-2.5 md:gap-3">
            <h1 className="max-w-4xl font-serif text-[48px] text-[#131313] md:text-[72px] text-center leading-[1.05] tracking-tight">
              Static analysis that understands Anchor
            </h1>
            <p className="max-w-[800px] font-sans text-[#4B5563] md:text-[22px] text-lg text-center leading-[1.6]">
              A multi-stage static analysis engine built specifically for Anchor&apos;s account model. It understands what has_one, seeds, Signer&lt;&gt;, and CPI calls actually mean at the constraint level.
            </p>
          </div>

          {/* CTA Button */}
          <div className="mt-2 md:mt-4">
            <a href="?page=audit" aria-label="Analyze your program">
              <button className="relative inline-flex items-center justify-center cursor-pointer font-serif font-medium transition-all duration-500 overflow-hidden rounded-full hover:duration-700 active:scale-95 active:duration-200 touch-manipulation px-8 py-4 text-[18px] bg-[#131313] text-white shadow-[inset_0_0_12px_rgba(255,255,255,1),0px_0px_2px_0_rgba(0,0,0,0.1)] group min-w-[220px]">
                <span className="absolute inset-0 opacity-0 transition-opacity duration-700 bg-[linear-gradient(90deg,#131313_0%,#0A2156_33%,#BED2FF_66%,#FF8717_100%)] group-hover:opacity-100 rounded-full shadow-[inset_0px_0px_12px_2px_rgba(255,255,255,0.5)]"></span>
                <span className="z-10 relative flex items-center gap-2 transition-all duration-500">
                  Analyze Your Program
                </span>
              </button>
            </a>
          </div>
        </div>
      </div>

      {/* Footer Branding Label */}
      <div className="absolute bottom-12 md:bottom-14 flex flex-col items-center gap-8 w-full shrink-0 z-10">
        <p className="font-display font-semibold text-[#999999] text-[12px] uppercase tracking-[3px]">
          Builders build with ChainProbe 
        </p>
      </div>
    </section>
  );
};

export default HeroSection;
