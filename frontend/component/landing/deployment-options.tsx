import React from 'react';
const DeploymentOptions = () => {
  const options = [
    {
      title: "Sarvam Cloud",
      description: "Fully managed, automatic scaling, fastest time-to-value",
      icon: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sam-sec-01-25.svg",
      bgClass: "bg-[#F0F2FF]",
    },
    {
      title: "Private Cloud (VPC)",
      description: "Your security perimeter, our management",
      icon: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sam-sec-02-24.svg",
      bgClass: "bg-[#FFF4F0]",
    },
    {
      title: "On-Premises",
      description: "Full control, air-gapped for regulated industries",
      icon: "https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sam-sec-03-23.svg",
      bgClass: "bg-[#F0FFF4]",
    }
  ];

  return (
    <section className="relative w-full py-24 md:py-44 bg-background">
      <div className="container mx-auto px-[7.5%] max-w-[1440px]">
        {/* Section Header */}
        <div className="flex flex-col items-center text-center mb-16 md:mb-20">
          <h2 className="font-serif text-[32px] md:text-[36px] text-foreground leading-[1.35] max-w-2xl px-4">
            Built to run<br className="md:hidden" /> anywhere your business runs
          </h2>
        </div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 md:gap-8">
          {options.map((option, index) => (
            <div 
              key={index}
              className="group relative flex items-center md:items-start lg:items-center gap-4 md:gap-6 p-6 md:p-8 bg-card rounded-[24px] md:rounded-[32px] border border-border transition-all duration-300 hover:shadow-lg hover:border-accent-indigo/20 shadow-[0px_0px_60px_0px_rgba(85,106,220,0.05)]"
            >
              {/* Ornamental Icon Container */}
              <div className={`relative shrink-0 w-16 h-16 md:w-20 md:h-20 rounded-2xl overflow-hidden flex items-center justify-center ${option.bgClass} transition-transform duration-500 group-hover:scale-105`}>
                <img
                  src={option.icon}
                  alt={option.title}
                  width={80}
                  height={80}
                  className="w-full h-full object-cover p-2"
                />
              </div>

              {/* Text Content */}
              <div className="flex flex-col gap-1.5">
                <h3 className="font-display font-medium text-[18px] md:text-[20px] text-foreground tracking-[-0.2px]">
                  {option.title}
                </h3>
                <p className="font-display text-[14px] md:text-[15px] text-muted-foreground leading-snug tracking-[-0.1px]">
                  {option.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default DeploymentOptions;