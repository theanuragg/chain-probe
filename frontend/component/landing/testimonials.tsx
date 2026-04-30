import React from 'react';

const Testimonials = () => {
  return (
    <section className="relative w-full py-24 md:py-44 bg-[#F8F9FB]">
      <div className="container mx-auto px-[7.5%] max-w-[1440px]">
        {/* Section Heading */}
        <div className="flex flex-col items-center mb-12 md:mb-16 text-center">
          <h2 className="font-serif text-[32px] md:text-[36px] text-[#131313] leading-[1.35] mb-4">
            What our customers say
          </h2>
        </div>

        {/* Testimonial Card */}
        <div className="relative bg-white rounded-[24px] md:rounded-[48px] p-8 md:p-16 lg:p-20 shadow-[0px_0px_60px_0px_rgba(85,106,220,0.06)] border border-black/5 overflow-hidden">
          <div className="flex flex-col h-full">
            {/* Tata Capital Logo */}
            <div className="mb-8 md:mb-12">
              <img
                src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/tata-capital-26.svg"
                alt="Tata Capital"
                className="h-6 md:h-8 w-auto object-contain"
                loading="lazy"
              />
            </div>

            {/* Quote Text */}
            <blockquote className="max-w-[1000px] mb-12 md:mb-16">
              <p className="font-sans text-[18px] md:text-[22px] text-[#4B5563] leading-[1.6] tracking-[-0.01em]">
                Our partnership with Sarvam has enabled us to scale highly personalized, product and segment-specific conversations across the customer lifecycle. By embedding multilingual interactions across our consumer loan products, we are reaching more customers with greater relevance, breaking access barriers, and deepening engagement in a cost-effective manner.
              </p>
            </blockquote>

            {/* Footer: Profile and Button */}
            <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-8 mt-auto">
              <div className="flex items-center gap-4">
                <div className="relative w-12 h-12 md:w-14 md:h-14 rounded-full overflow-hidden shrink-0 border border-black/5">
                  <img
                    src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/icons/testimonial-profiel-1.png"
                    alt="Shallu Kaushik"
                    height={96}
                    width={96}
                    className="object-cover"
                  />
                </div>
                <div className="flex flex-col">
                  <cite className="not-italic font-sans font-semibold text-[16px] text-[#131313] leading-tight">
                    Shallu Kaushik
                  </cite>
                  <span className="font-sans text-[14px] text-[#999999] mt-1">
                    Chief Digital Officer, Tata Capital
                  </span>
                </div>
              </div>

              <div className="flex">
                <a 
                  href="#"
                  className="inline-flex items-center justify-center px-6 py-3 bg-[#F3F4F6] text-[#131313] font-sans font-medium text-[14px] rounded-full hover:bg-[#E5E7EB] transition-colors duration-200"
                >
                  Read case study
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