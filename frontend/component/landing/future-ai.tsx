import React from 'react';

const FutureAI = () => {
  const assets = {
    heroImage: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/images/home-section-2-1.png",
    logoWhite: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sarvam-logo-white-19.svg"
  };

  const featurePoints = [
    {
      title: "Sovereign by design",
      description: "Build, deploy, and run AI with full control, developed and operated entirely in India"
    },
    {
      title: "State of the art Models",
      description: "Industry-leading models built for India's languages, culture, and context"
    },
    {
      title: "Human at the core",
      description: "Forward deployed engineers work alongside your teams to deliver production-ready agents"
    }
  ];

  return (
    <section className="relative mx-auto w-full md:w-[85%] lg:w-9/12 max-w-[1440px] px-4 md:px-0 py-16 md:py-24">
      <div className="flex flex-col items-center gap-8 md:gap-16">
        {/* Section Heading */}
        <div className="flex flex-col items-center text-center gap-6 w-full opacity-100 transform-none">
          <h2 className="font-serif font-normal text-3xl md:text-[36px] text-[#131313] leading-[1.35] whitespace-pre-line px-3 md:px-0">
            Powering India's AI-first future
          </h2>
        </div>

        {/* Feature Card Wrapper */}
        <div className="flex md:flex-row flex-col gap-3 bg-white p-4 md:p-6 rounded-[24px] md:rounded-[48px] w-full overflow-hidden shadow-[0px_0px_60px_0px_rgba(85,106,220,0.12)] border border-[rgba(0,0,0,0.08)]">
          
          {/* Left: Image Container */}
          <div className="relative rounded-2xl md:rounded-[36px] w-full md:w-[50%] h-[250px] md:h-[420px] overflow-hidden shrink-0">
            <img
              src={assets.heroImage} 
              alt="Sarvam AI Platform sovereign design visual" 
             width={96}
             height={96}
              className="object-cover"
        
            />
            {/* Overlay Logo */}
            <div className="absolute inset-0 flex justify-center items-center">
              <div className="relative mb-20 md:mb-36 w-20 md:w-24 h-auto opacity-90 transition-transform duration-700 hover:scale-110">
                <img 
                  src={assets.logoWhite} 
                  alt="Sarvam Logo" 
                  width={96} 
                  height={96}
                  className="w-full h-auto drop-shadow-lg"
                />
              </div>
            </div>
          </div>

          {/* Right: Feature Content */}
          <div className="flex flex-col flex-1 md:justify-between justify-start gap-8 md:gap-0 px-4 md:px-12 py-6 md:py-10">
            {featurePoints.map((point, index) => (
              <div key={index} className="flex items-start gap-4 group">
                {/* Custom Star Icon */}
                <div className="mt-1 shrink-0 w-6 h-6 flex items-center justify-center">
                  <svg 
                    width="24" 
                    height="24" 
                    viewBox="0 0 24 24" 
                    fill="none" 
                    xmlns="http://www.w3.org/2000/svg"
                    className="w-5 h-5 transition-transform duration-500 group-hover:rotate-90"
                  >
                    <path 
                      d="M12 0L14.5 9.5L24 12L14.5 14.5L12 24L9.5 14.5L0 12L9.5 9.5L12 0Z" 
                      fill="url(#star-gradient)"
                    />
                    <defs>
                      <linearGradient id="star-gradient" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stopColor="#556ADC" />
                        <stop offset="100%" stopColor="#BED2FF" />
                      </linearGradient>
                    </defs>
                  </svg>
                </div>

                {/* Text Content */}
                <div className="flex flex-col gap-1.5 md:gap-3">
                  <h3 className="font-sans font-medium text-[#131313] text-xl md:text-[22px] leading-normal tracking-[-0.22px]">
                    {point.title}
                  </h3>
                  <p className="font-sans text-[#999999] text-base leading-normal tracking-[-0.16px] max-w-[420px]">
                    {point.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default FutureAI;