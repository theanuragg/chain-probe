"use client";

import React, { useState } from "react";

const tabs = [
  { id: "conversational", label: "Conversational Agents" },
  { id: "tts", label: "Text to Speech" },
  { id: "stt", label: "Speech to Text" },
  { id: "vision", label: "Vision" },
  { id: "dubbing", label: "Dubbing" },
];

const samvaadCards = [
  {
    title: "Cart Recovery",
    motif: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-motif-01-20.svg",
    gradient: "from-[#E8A5C8] via-[#B9D1F9] to-[#E8A5C8]",
    shadow: "rgba(232, 165, 200, 0.3)",
  },
  {
    title: "Appointment Booking",
    motif: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-motif-02-21.svg",
    gradient: "from-[#FFA133] via-[#FFE2B5] to-[#FFA133]",
    shadow: "rgba(255, 161, 51, 0.3)",
  },
  {
    title: "Payment follow-ups",
    motif: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-motif-03-22.svg",
    gradient: "from-[#8FC461] via-[#E2F0D9] to-[#8FC461]",
    shadow: "rgba(143, 196, 97, 0.3)",
  },
];

export default function ExperienceSamvaad() {
  const [activeTab, setActiveTab] = useState("conversational");

  return (
    <section className="relative flex flex-col items-center pt-24 pb-44 px-4 md:px-0 bg-background overflow-hidden">
      {/* Background Decorative Gradients */}
      <div className="absolute top-[20%] left-[-10%] w-[120%] h-[60%] bg-[radial-gradient(circle_at_center,rgba(85,106,220,0.05)_0%,transparent_70%)] pointer-events-none" />

      {/* Header */}
      <div className="z-10 text-center mb-12">
        <h2 className="font-season-mix text-3xl md:text-[36px] text-foreground leading-[1.35] mb-12">
          See it in action
        </h2>

        {/* Tab Bar */}
        <div className="flex flex-wrap justify-center gap-2 md:gap-3 p-1.5 bg-black/[0.03] backdrop-blur-md rounded-full border border-black/[0.05] w-fit mx-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-2.5 rounded-full text-xs md:text-[13px] font-medium transition-all duration-300 tracking-wide ${
                activeTab === tab.id
                  ? "bg-white text-accent shadow-[0_2px_10px_rgba(85,106,220,0.1)] border border-sr-indigo-100"
                  : "text-muted-foreground hover:text-foreground hover:bg-black/[0.02]"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Experience Dashboard */}
      <div className="z-10 w-full max-w-[1200px] bg-white rounded-[40px] md:rounded-[48px] border border-black/[0.08] shadow-[0px_0px_60px_0px_rgba(85,106,220,0.08)] overflow-hidden">
        {/* Dashboard Top Nav */}
        <div className="flex justify-between items-center px-8 md:px-12 py-8 border-b border-black/[0.04]">
          <h3 className="font-display font-medium text-foreground/80 text-sm md:text-base">
            Experience Samvaad
          </h3>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-[10px] md:text-xs font-bold tracking-[2px] text-foreground/40 uppercase">
              LIVE
            </span>
          </div>
        </div>

        {/* Dashboard Content */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 md:gap-4 p-8 md:p-14 lg:p-20 items-center justify-items-center">
          {samvaadCards.map((card, idx) => (
            <div
              key={idx}
              className="flex flex-col items-center gap-8 w-full group cursor-pointer"
            >
              {/* Motif Container */}
              <div className="relative flex items-center justify-center w-[200px] h-[200px] md:w-[240px] md:h-[240px]">
                {/* Background Shadow Glow */}
                <div 
                  className="absolute inset-0 blur-[30px] opacity-20 scale-90 group-hover:scale-100 transition-transform duration-700"
                  style={{ backgroundColor: card.shadow }}
                />
                
                {/* The SVG Motif */}
                <img
                  src={card.motif}
                  alt={card.title}
                  width={240}
                  height={240}
                  className="relative z-10 w-full h-full object-contain filter drop-shadow-xl transform transition-transform duration-700 group-hover:scale-105"
                />

                {/* Floating "Start Speaking" Glass Button */}
                <div className="absolute z-20 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
                  <div className="glass-surface px-6 py-2.5 rounded-full inner-glass-glow border border-white/50 shadow-lg backdrop-blur-sm group-hover:bg-white/40 transition-colors duration-500">
                    <span className="text-white text-xs md:text-sm font-medium whitespace-nowrap">
                      Start Speaking
                    </span>
                  </div>
                </div>
              </div>

              {/* Card Label */}
              <p className="font-display text-[15px] md:text-base font-medium text-muted-foreground group-hover:text-foreground transition-colors duration-300">
                {card.title}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Footer text */}
      <div className="z-10 mt-32 md:mt-48">
        <h2 className="font-season-mix text-3xl md:text-[36px] text-foreground text-center leading-[1.35] opacity-90 mx-auto max-w-2xl">
          Enterprise-grade security. Built in from day one.
        </h2>
      </div>
    </section>
  );
}