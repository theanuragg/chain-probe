import React from 'react';

/**
 * LogoCarousel Component
 * 
 * An expert-level clone of the infinite scrolling logo carousel section.
 * Features:
 * - Pixel-perfect replication of "India builds with Sarvam" label styling.
 * - Smooth infinite horizontal scrolling animation using standard CSS.
 * - Grayscale logo treatment consistent with the design instructions.
 * - Responsive layout handling.
 */

const logos = [
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-01-4.svg", alt: "Flipkart" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-02-5.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-03-6.svg", alt: "NABARD" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-04-7.svg", alt: "LIC" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-05-8.svg", alt: "Infosys" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-06-9.svg", alt: "CRED" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-07-10.svg", alt: "Decentro" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-08-11.svg", alt: "Axis Bank" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-09-12.svg", alt: "Mahindra Finance" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-10-13.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-11-14.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-12-15.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-13-16.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-14-17.svg", alt: "Partner Logo" },
  { src: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/samvaad-logo-15-18.svg", alt: "Partner Logo" }
];

export default function LogoCarousel() {
  return (
    <div className="flex flex-col items-center gap-8 pb-8 md:pb-14 w-full shrink-0">
      {/* Label: India builds with Sarvam */}
      <p className="font-matter font-semibold text-[#999999] text-[12px] uppercase tracking-[3px] leading-normal pt-12 md:pt-0">
        India builds with Sarvam
      </p>

      {/* Infinite Logo Carousel */}
      <div 
        className="logo-carousel-container w-full overflow-hidden relative cursor-default" 
        role="region" 
        aria-label="Partner logos carousel"
      >
        <style dangerouslySetInnerHTML={{ __html: `
          @keyframes infiniteScroll {
            from { transform: translateX(0); }
            to { transform: translateX(-50%); }
          }
          .logo-carousel-track {
            display: flex;
            width: fit-content;
            animation: infiniteScroll 40s linear infinite;
          }
          .logo-carousel-track:hover {
            animation-play-state: paused;
          }
          .logo-mask {
            mask-image: linear-gradient(to right, transparent, black 15%, black 85%, transparent);
            -webkit-mask-image: linear-gradient(to right, transparent, black 15%, black 85%, transparent);
          }
        `}} />

        <div className="logo-mask overflow-hidden">
          <div className="logo-carousel-track flex items-center py-4">
            {/* First set of logos */}
            <div className="flex items-center gap-12 md:gap-24 px-12 md:px-24">
              {logos.map((logo, index) => (
                <div key={`set1-${index}`} className="flex-shrink-0 grayscale hover:grayscale-0 transition-all duration-300 opacity-60 hover:opacity-100 h-8 md:h-12 flex items-center justify-center">
                  <img 
                    src={logo.src} 
                    alt={logo.alt} 
                    className="w-auto h-full object-contain pointer-events-none"
                    loading="lazy"
                  />
                </div>
              ))}
            </div>
            {/* Second set of logos for seamless loop */}
            <div className="flex items-center gap-12 md:gap-24 px-12 md:px-24">
              {logos.map((logo, index) => (
                <div key={`set2-${index}`} className="flex-shrink-0 grayscale hover:grayscale-0 transition-all duration-300 opacity-60 hover:opacity-100 h-8 md:h-12 flex items-center justify-center">
                  <img 
                    src={logo.src} 
                    alt={logo.alt} 
                    className="w-auto h-full object-contain pointer-events-none"
                    loading="lazy"
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}