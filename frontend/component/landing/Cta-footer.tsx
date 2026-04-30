import React from 'react';

const CTAFooter = () => {
  return (
    <div className="flex flex-col w-full bg-[#F8F9FB]">
      {/* Search for "Build the future of India's AI with Sarvam" CTA Card */}
      <section className="container py-24 md:py-32">
        <div 
          className="relative w-full aspect-[21/9] min-h-[400px] md:min-h-[520px] rounded-[48px] overflow-hidden flex flex-col items-center justify-center text-center px-6 bg-[#0A101F]"
          style={{
            background: 'linear-gradient(180deg, #131A2B 0%, #0A101F 100%)',
          }}
        >
          {/* Decorative Star/Motif */}
          <div className="absolute top-0 left-0 w-full h-full opacity-40 pointer-events-none">
             {/* Gradient Overlay for texture */}
             <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(85,106,220,0.15)_0%,_transparent_70%)]"></div>
          </div>
          
          <div className="z-10 flex flex-col items-center gap-8 md:gap-12">
            <h2 className="font-season-mix text-[32px] md:text-[48px] text-white leading-[1.2] max-w-2xl font-normal">
              Build the future of India&apos;s AI <br className="hidden md:block" /> with Sarvam.
            </h2>
            
            <div className="relative">
               {/* Star Motif Icon from Screenshot */}
               <div className="mb-8 flex justify-center">
                 <svg width="40" height="40" viewBox="0 0 100 100" fill="white">
                    <path d="M50 0C50 27.6142 27.6142 50 0 50C27.6142 50 50 72.3858 50 100C50 72.3858 72.3858 50 100 50C72.3858 50 50 27.6142 50 0Z" />
                 </svg>
               </div>
               
               <a 
                href="https://dashboard.sarvam.ai/signin"
                className="relative inline-flex items-center justify-center cursor-pointer font-season-mix font-medium transition-all duration-500 overflow-hidden rounded-full px-8 py-4 text-lg bg-[#F0F2FF]/20 text-white backdrop-blur-md border border-white/10 hover:bg-white/30 active:scale-95 group"
               >
                 <span className="z-10 relative flex items-center gap-2">Get Started Now</span>
               </a>
            </div>
          </div>

          {/* Curved Bottom Mask Effect (implied from layout) */}
          <div 
            className="absolute bottom-[-1px] left-0 w-full h-24 bg-[#F8F9FB]"
            style={{ clipPath: 'ellipse(60% 100% at 50% 100%)' }}
          ></div>
        </div>
      </section>

      {/* Comprehensive Sitewide Footer */}
      <footer className="container py-16 md:py-24 flex flex-col">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-y-12 gap-x-8 mb-20">
          
          {/* Brand Column */}
          <div className="col-span-2 md:col-span-1 flex flex-col gap-6">
            <a href="/" className="inline-block">
              <img
                src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sarvam-wordmark-black-1.svg" 
                alt="Sarvam AI" 
                width={120} 
                height={24}
                className="h-6 w-auto"
              />
            </a>
            <p className="font-display text-[14px] text-gray-400">AI for India starts here</p>
            
            <div className="flex gap-3 mt-2">
              <div className="flex items-center justify-center p-2 border border-gray-100 rounded-lg bg-white/50">
                <img 
                  src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/icons/sec-iso-2.png" 
                  alt="ISO 27001 Certified" 
                  width={48} 
                  height={48}
                  className="grayscale hover:grayscale-0 transition-all opacity-60"
                />
              </div>
              <div className="flex items-center justify-center p-2 border border-gray-100 rounded-lg bg-white/50">
                <img
                  src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/icons/sec-soc2-3.png" 
                  alt="SOC2 Type 1 Certified" 
                  width={48} 
                  height={48}
                  className="grayscale hover:grayscale-0 transition-all opacity-60"
                />
              </div>
            </div>
          </div>

          {/* Products Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Products</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Sarvam Samvaad</a>
            </div>
          </div>

          {/* API Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">API</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Text to Speech</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Speech to Text</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">API Pricing</a>
            </div>
          </div>

          {/* Company Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Company</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">About us</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Blogs</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Discord</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Careers</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Terms of service</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Privacy Policy</a>
            </div>
          </div>

          {/* Socials Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Socials</h4>
            <div className="flex flex-col gap-3">
              <a href="https://www.linkedin.com/company/sarvam-ai/" className="text-[14px] text-gray-500 hover:text-black transition-colors">LinkedIn</a>
              <a href="https://x.com/SarvamAI" className="text-[14px] text-gray-500 hover:text-black transition-colors">Twitter</a>
              <a href="https://www.youtube.com/@SarvamAI" className="text-[14px] text-gray-500 hover:text-black transition-colors">YouTube</a>
            </div>
          </div>
          
        </div>

        {/* Bottom Footer Credits */}
        <div className="pt-8 border-t border-black/5 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-[12px] text-gray-400 font-display">Copyright Sarvam AI 2024</p>
          <p className="text-[12px] text-gray-400 font-display">All rights reserved, Bengaluru - 560038</p>
        </div>
      </footer>
    </div>
  );
};

export default CTAFooter;