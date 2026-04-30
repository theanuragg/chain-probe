import React from 'react';

const Testimonials = () => {
  return (
    <section className="relative w-full py-24 md:py-44 bg-[#F8F9FB]">
      <div className="container mx-auto px-[7.5%] max-w-[1440px]">
        {/* Section Heading */}
        <div className="flex flex-col items-center mb-12 md:mb-16 text-center">
          <h2 className="font-serif text-[32px] md:text-[36px] text-[#131313] leading-[1.35] mb-4">
            Trusted by Solana builders
          </h2>
        </div>

        {/* Testimonial Card */}
        <div className="relative bg-white rounded-[24px] md:rounded-[48px] p-8 md:p-16 lg:p-20 shadow-[0px_0px_60px_0px_rgba(85,106,220,0.06)] border border-black/5 overflow-hidden">
          <div className="flex flex-col h-full">
            {/* ChainProbe Logo placeholder */}
            <div className="mb-8 md:mb-12">
              <span className="font-bold text-xl text-[#131313]">ChainProbe</span>
            </div>

            {/* Quote Text */}
            <blockquote className="max-w-[1000px] mb-12 md:mb-16">
              <p className="font-sans text-[18px] md:text-[22px] text-[#4B5563] leading-[1.6] tracking-[-0.01em]">
                ChainProbe caught an unsigned authority vulnerability in our escrow program that two previous audits missed. The PoC test proved it immediately, and the fix diff gave us the exact code change. This is the kind of tool the Solana ecosystem has been waiting for.
              </p>
            </blockquote>

            {/* Footer: Profile and Button */}
            <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-8 mt-auto">
              <div className="flex items-center gap-4">
                <div className="relative w-12 h-12 md:w-14 md:h-14 rounded-full overflow-hidden shrink-0 border border-black/5 bg-[#F3F4F6] flex items-center justify-center">
                  <span className="font-bold text-[#131313] text-lg">SP</span>
                </div>
                <div className="flex flex-col">
                  <cite className="not-italic font-sans font-semibold text-[16px] text-[#131313] leading-tight">
                    Solana Protocol Team
                  </cite>
                  <span className="font-sans text-[14px] text-[#999999] mt-1">
                    DeFi Protocol, Solana
                  </span>
                </div>
              </div>

              <div className="flex">
                <a 
                  href="#"
                  className="inline-flex items-center justify-center px-6 py-3 bg-[#F3F4F6] text-[#131313] font-sans font-medium text-[14px] rounded-full hover:bg-[#E5E7EB] transition-colors duration-200"
                >
                  View Sample Report
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Testimonials;