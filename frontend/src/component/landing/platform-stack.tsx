"use client";

import React from "react";

interface SubSection {
  id: number;
  title: string;
  description: string;
  tags: string[];
  gradient: string;
}

const subSections: SubSection[] = [
  {
    id: 0,
    title: "Taint Analysis & Invariant Mining",
    description:
      "Tracks attacker-controlled values through instruction params, unverified accounts, and arithmetic operations. Extracts every require!() condition and checks whether bypass paths exist.",
    tags: ["Taint Flows", "Invariant Checks"],
    gradient: "linear-gradient(135deg, #FF8717 0%, #FFB472 50%, #BED2FF 100%)",
  },
  {
    id: 1,
    title: "Call Graph & CPI Analysis",
    description:
      "Builds directed graphs of instruction-to-CPI flows, binds account parameters across CPI boundaries, and computes the minimum attacker-controlled accounts needed to reach each security-sensitive operation.",
    tags: ["Call Graph", "CPI Tracking", "Attack Surface"],
    gradient: "linear-gradient(135deg, #556ADC 0%, #A5BBFC 50%, #FFB472 100%)",
  },
  {
    id: 2,
    title: "Exploitability Scoring & PoC Generation",
    description:
      "Every finding includes an exploitability score, required attacker footprint, and a runnable test that proves the vulnerability — plus the actual corrected Anchor code as a fix diff.",
    tags: ["PoC Tests", "Fix Diffs", "Security Score"],
    gradient: "linear-gradient(135deg, #131313 0%, #0A2156 50%, #556ADC 100%)",
  },
];

export default function PlatformStack() {
  return (
    <section className="relative w-full py-24 md:py-32 bg-[#F8F9FB]">
      <div className="container mx-auto px-[7.5%] w-full max-w-[1440px]">
        
        {/* Header Area */}
        <div className="flex flex-col items-center gap-4 mb-16 md:mb-20">
          <p className="font-display font-medium text-[#999999] text-[12px] text-center uppercase tracking-[2px]">
            For Solana Developers | Auditors | Protocol Teams
          </p>
          <h2 className="font-serif text-[30px] md:text-[36px] text-[#131313] text-center leading-[1.35]">
            The 8-Stage Analysis Pipeline
          </h2>
        </div>

        {/* Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 md:gap-8">
          {subSections.map((section) => (
            <div
              key={section.id}
              className="group relative flex flex-col gap-6 p-8 bg-white rounded-[24px] md:rounded-[32px] border border-[rgba(0,0,0,0.08)] transition-all duration-300 hover:shadow-lg hover:border-[#556ADC]/20 shadow-[0px_0px_60px_0px_rgba(85,106,220,0.05)]"
            >
              {/* Gradient accent bar */}
              <div 
                className="w-full h-2 rounded-full"
                style={{ background: section.gradient }}
              />

              {/* Text Content */}
              <div className="flex flex-col gap-3">
                <h3 className="font-display font-medium text-[#131313] text-[20px] md:text-[22px] leading-tight tracking-[-0.22px]">
                  {section.title}
                </h3>
                <p className="font-sans text-[#999999] text-[14px] md:text-[15px] leading-[1.55] tracking-[-0.15px]">
                  {section.description}
                </p>
              </div>
              
              {/* Tags */}
              <div className="flex flex-wrap gap-2">
                {section.tags.map((tag) => (
                  <span 
                    key={tag}
                    className="inline-flex items-center bg-[#F0F2FF] px-4 py-2 border border-[rgba(85,106,220,0.12)] rounded-full font-display text-[#4B5563] text-sm tracking-[-0.14px]"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
