import React from 'react';

const ResearchUpdates = () => {
  const updates = [
    {
      type: "COMPANY",
      title: "Introducing Sarvam Akshar",
      date: "February 15, 2026",
      image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/42d675e333219227dd0a6872d6405088722eb6e1-2400x1800-6.png",
      alt: "Sarvam Akshar",
    },
    {
      type: "COMPANY",
      title: "Announcing Sarvam Edge",
      date: "February 14, 2026",
      image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/fff4fe106a03242dec49bd27025e1b55a51de0b9-1800x1350-5.png",
      alt: "Sarvam Edge",
    },
    {
      type: "COMPANY",
      title: "Introducing Sarvam Studio",
      date: "February 12, 2026",
      image: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/a8c0e7c607de1a5f08beffb3644b9bd468d6238e-2400x1800-7.png",
      alt: "Sarvam Studio",
    }
  ];

  return (
    <section className="bg-[#F8F9FB] py-24 md:py-44 overflow-hidden">
      <div className="container mx-auto px-4 md:px-[7.5%] max-w-[1440px]">
        {/* Section Header */}
        <div className="flex flex-col items-center mb-12 md:mb-16 text-center">
          <h2 className="font-serif text-[32px] md:text-[36px] font-normal leading-[1.35] text-[#131313]">
            Research & Updates
          </h2>
        </div>

        {/* Updates Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 md:gap-8">
          {updates.map((update, index) => (
            <div 
              key={index}
              className="group bg-white rounded-[24px] md:rounded-[48px] p-4 md:p-6 border border-[rgba(0,0,0,0.08)] flex flex-col transition-all duration-500 hover:shadow-[0px_0px_60px_0px_rgba(85,106,220,0.12)]"
            >
              {/* Card Meta Content */}
              <div className="flex flex-col gap-1 mb-6 md:mb-8 px-2">
                <span className="font-sans text-[10px] md:text-[12px] font-semibold text-[#999999] uppercase tracking-[2px] md:tracking-[3px]">
                  {update.type}
                </span>
                <h3 className="font-sans text-[20px] md:text-[22px] font-medium text-[#131313] tracking-[-0.22px] leading-tight">
                  {update.title}
                </h3>
                <p className="font-sans text-[12px] md:text-[14px] text-[#999999] mt-1">
                  {update.date}
                </p>
              </div>

              {/* Graphic/Image Container */}
              <div className="relative aspect-[4/3] w-full rounded-[16px] md:rounded-[32px] overflow-hidden">
                <img
                  src={update.image}
                  alt={update.alt}
                  height={96}
                  width={96}
                  className="object-cover transition-transform duration-700 group-hover:scale-105"
                  sizes="(max-width: 768px) 100vw, 33vw"
                />
                
                {/* Decorative Overlay for visual depth similar to screenshot */}
                <div className="absolute inset-0 bg-gradient-to-t from-black/5 to-transparent pointer-events-none" />
              </div>
            </div>
          ))}
        </div>

        {/* View All Button */}
        <div className="flex justify-center mt-12 md:mt-16">
          <button className="relative inline-flex items-center justify-center font-sans font-medium text-[14px] md:text-[16px] transition-all duration-500 rounded-full px-6 py-2.5 md:px-8 md:py-3 bg-white text-[#131313] border border-[rgba(0,0,0,0.08)] shadow-[0_0_12px_rgba(0,0,0,0.04)] hover:bg-[#F3F4F6] active:scale-95">
            View All Updates
          </button>
        </div>
      </div>
    </section>
  );
};

export default ResearchUpdates;