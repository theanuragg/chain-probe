"use client";

import React from "react";

const findings = [
  {
    title: "Unsigned Authority",
    description: "AccountInfo used as authority field — no signature verification required",
    severity: "Critical",
    severityColor: "bg-[#FF3D5C]",
    icon: (
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#F0F2FF"/>
        <path d="M24 14v12M24 30v4" stroke="#556ADC" strokeWidth="2.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    title: "Overflow Chain",
    description: "Unchecked arithmetic on user-controlled values reaches token transfer sink",
    severity: "High",
    severityColor: "bg-[#FFAA33]",
    icon: (
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#FFF4F0"/>
        <path d="M16 28l6-8 6 4 6-10" stroke="#FF8717" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    title: "PDA Collision",
    description: "Seeds contain user-supplied mint — attacker can derive same PDA address",
    severity: "Critical",
    severityColor: "bg-[#FF3D5C]",
    icon: (
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#F0FFF4"/>
        <circle cx="20" cy="24" r="6" stroke="#8FC461" strokeWidth="2"/>
        <circle cx="28" cy="24" r="6" stroke="#8FC461" strokeWidth="2"/>
      </svg>
    ),
  },
];

export default function ExperienceSamvaad() {
  return (
    <section className="relative flex flex-col items-center py-24 px-4 md:px-0 bg-[#F8F9FB]">
      {/* Header */}
      <div className="z-10 text-center mb-16">
        <h2 className="font-serif text-3xl md:text-[36px] text-[#131313] leading-[1.35] mb-4">
          See it in action
        </h2>
        <p className="font-sans text-[#999999] text-lg max-w-xl mx-auto">
          Every vulnerability is proven with a runnable PoC test and a side-by-side fix diff.
        </p>
      </div>

      {/* Findings Dashboard */}
      <div className="z-10 w-full max-w-[1200px] bg-white rounded-[24px] md:rounded-[32px] border border-black/[0.08] shadow-[0px_0px_60px_0px_rgba(85,106,220,0.08)] overflow-hidden">
        {/* Dashboard Top Nav */}
        <div className="flex justify-between items-center px-8 md:px-12 py-6 border-b border-black/[0.04]">
          <h3 className="font-display font-medium text-[#131313]/80 text-sm md:text-base">
            Sample Findings
          </h3>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full rounded-full bg-green-400"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-[10px] md:text-xs font-bold tracking-[2px] text-[#131313]/40 uppercase">
              3 FINDINGS
            </span>
          </div>
        </div>

        {/* Dashboard Content */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-0">
          {findings.map((finding, idx) => (
            <div
              key={idx}
              className={`flex flex-col gap-6 p-8 md:p-10 ${
                idx < findings.length - 1 ? "border-b md:border-b-0 md:border-r border-black/[0.04]" : ""
              }`}
            >
              {/* Icon */}
              <div className="w-12 h-12">
                {finding.icon}
              </div>

              {/* Title & Severity */}
              <div className="flex items-start justify-between gap-3">
                <h4 className="font-display font-medium text-[#131313] text-[18px] leading-tight">
                  {finding.title}
                </h4>
                <span className={`shrink-0 px-2.5 py-1 rounded-full text-[10px] font-bold text-white uppercase tracking-wide ${finding.severityColor}`}>
                  {finding.severity}
                </span>
              </div>

              {/* Description */}
              <p className="font-sans text-[#999999] text-[14px] leading-[1.55]">
                {finding.description}
              </p>

              {/* Action link */}
              <a href="?page=audit" className="font-display text-[13px] font-medium text-[#556ADC] hover:text-[#0A2156] transition-colors inline-flex items-center gap-1">
                View full report
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M1 7h12M8 2l5 5-5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </a>
            </div>
          ))}
        </div>
      </div>

      {/* Footer text */}
      <div className="z-10 mt-20 md:mt-28">
        <h2 className="font-serif text-3xl md:text-[36px] text-[#131313] text-center leading-[1.35] opacity-90 mx-auto max-w-2xl">
          Every finding comes with a PoC test and a fix diff.
        </h2>
      </div>
    </section>
  );
}
