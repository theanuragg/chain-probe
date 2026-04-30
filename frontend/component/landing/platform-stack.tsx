"use client";

import React, { useEffect, useRef, useState } from "react";

interface SubSection {
  id: number;
  title: string;
  description: string;
  tags: string[];
  gradient: string;
  image: string;
}

const subSections: SubSection[] = [
  {
    id: 0,
    title: "Population-scale Applications",
    description:
      "Building products India can use. Conversational agents fluent in India's languages. Platforms that run enterprise workflows from start to finish.",
    tags: ["Samvaad", "Studio"],
    gradient: "linear-gradient(135deg, #FF8717 0%, #FFB472 50%, #BED2FF 100%)",
    image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/built-for-01-2.png",
  },
  {
    id: 1,
    title: "State-of-the-art Models",
    description:
      "State-of-the-art models trained on sovereign data, delivering strong performance across Indian languages.",
    tags: ["Bulbul", "Saaras", "Dub", "Audio", "..."],
    gradient: "linear-gradient(135deg, #556ADC 0%, #A5BBFC 50%, #FFB472 100%)",
    image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/built-for-02-3.png",
  },
  {
    id: 2,
    title: "Infrastructure to serve models efficiently",
    description:
      "A token factory built to handle complexity of model serving so teams can focus on building products, not managing infrastructure.",
    tags: ["Compute", "Optimization", "Scale"],
    gradient: "linear-gradient(135deg, #131313 0%, #0A2156 50%, #556ADC 100%)",
    image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/built-for-03-4.png",
  },
];

export default function PlatformStack() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    const handleScroll = () => {
      if (!containerRef.current) return;

      const rect = containerRef.current.getBoundingClientRect();
      const scrollProgress = -rect.top / (rect.height - window.innerHeight);
      
      // Map progress to index 0, 1, 2
      const newIndex = Math.min(
        subSections.length - 1,
        Math.max(0, Math.floor(scrollProgress * subSections.length))
      );
      
      if (newIndex !== activeIndex) {
        setActiveIndex(newIndex);
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [activeIndex]);

  return (
    <section 
      ref={containerRef}
      className="relative w-full h-[300vh]"
    >
      {/* Sticky Container */}
      <div className="sticky top-0 h-screen flex flex-col justify-center overflow-hidden">
        <div className="container mx-auto px-[7.5%] w-full max-w-[1440px]">
          
          {/* Header Area */}
          <div className="flex flex-col items-center gap-4 mb-16 md:mb-20">
            <p className="font-display font-medium text-[#999999] text-[12px] text-center uppercase tracking-[2px]">
              For Enterprise | Government | Developers
            </p>
            <h2 className="font-serif text-[30px] md:text-[36px] text-[#131313] text-center leading-[1.35]">
              India&apos;s Full-stack Sovereign AI Platform
            </h2>
          </div>

          {/* Platform Split View */}
          <div className="flex flex-col md:flex-row items-stretch w-full gap-8 md:gap-0 bg-transparent">
            
            {/* Left Column: Visual Canvas */}
            <div className="relative w-full md:w-1/2 aspect-[4/3] md:aspect-auto md:h-[480px] rounded-[48px] border border-[rgba(0,0,0,0.08)] overflow-hidden">
              {subSections.map((section, idx) => (
                <div
                  key={section.id}
                  className="absolute inset-0 transition-opacity duration-700 ease-in-out"
                  style={{ 
                    opacity: activeIndex === idx ? 1 : 0,
                    background: section.gradient,
                    zIndex: activeIndex === idx ? 10 : 0
                  }}
                >
                  <div className="relative w-full h-full flex items-center justify-center p-12">
                     <div className="relative w-full h-full glass-surface rounded-[32px] overflow-hidden shadow-2xl transition-transform duration-1000 ease-out flex items-center justify-center"
                          style={{ transform: activeIndex === idx ? 'scale(1)' : 'scale(0.95)' }}>
                        <img 
                          src={section.image} 
                          alt={section.title}
                          height={96}
                          width={96}
                                                    className="object-cover"
                          sizes="(max-width: 768px) 100vw, 50vw"
                        />
                        {/* Overlay to match the design's "glass" feel in the center */}
                        <div className="absolute inset-x-20 inset-y-24 glass-surface rounded-[24px] border border-white/40 shadow-[inset_0_0_12px_rgba(255,255,255,1)]"></div>
                     </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Right Column: Text Content */}
            <div className="relative w-full md:w-1/2 min-h-[350px] md:min-h-0 flex items-center">
              <div className="relative w-full px-6 md:px-20 py-8 md:py-16">
                {subSections.map((section, idx) => (
                  <div
                    key={section.id}
                    className={`absolute inset-x-6 md:inset-x-20 transition-all duration-700 ease-in-out flex flex-col gap-8 ${
                      activeIndex === idx 
                        ? "opacity-100 translate-y-0" 
                        : "opacity-0 translate-y-8 pointer-events-none"
                    }`}
                  >
                    <div className="flex flex-col gap-3 md:gap-4">
                      <h3 className="font-display font-medium text-[#131313] text-[24px] md:text-[26px] leading-tight tracking-[-0.26px]">
                        {section.title}
                      </h3>
                      <p className="max-w-[480px] font-display text-[#999999] text-[16px] md:text-[18px] leading-[1.55] tracking-[-0.18px]">
                        {section.description}
                      </p>
                    </div>
                    
                    <div className="flex flex-wrap gap-2 md:gap-3">
                      {section.tags.map((tag) => (
                        <span 
                          key={tag}
                          className="inline-flex items-center bg-[#F0F2FF] px-4 md:px-5 py-2 md:py-2.5 border border-[rgba(85,106,220,0.12)] rounded-full font-display text-[#4B5563] text-sm md:text-[18px] tracking-[-0.18px]"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </div>
      </div>
      
      {/* Scroll Indicators for Context */}
      <div className="absolute bottom-10 left-1/2 -translate-x-1/2 flex gap-2 z-[100]">
        {[0, 1, 2].map((i) => (
          <div 
            key={i} 
            className={`h-1 rounded-full transition-all duration-500 ${activeIndex === i ? 'w-8 bg-[#556ADC]' : 'w-2 bg-black/10'}`} 
          />
        ))}
      </div>
    </section>
  );
}