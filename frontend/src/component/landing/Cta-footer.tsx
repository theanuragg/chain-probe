import React from 'react';

const CTAFooter = () => {
  return (
    <div className="flex flex-col w-full bg-[#F8F9FB]">
      {/* CTA Card */}
      <section className="w-full px-4 md:px-8 py-24 md:py-32">
        <div 
          className="relative w-full max-w-[1440px] mx-auto min-h-[400px] md:min-h-[520px] rounded-[48px] overflow-hidden flex flex-col items-center justify-center text-center px-6"
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
            <h2 className="font-serif text-[32px] md:text-[48px] text-white leading-[1.2] max-w-2xl font-normal">
              Ship secure Anchor programs <br className="hidden md:block" /> with confidence.
            </h2>
            
            <div className="relative">
               {/* Star Motif Icon */}
               <div className="mb-8 flex justify-center">
                 <svg width="40" height="40" viewBox="0 0 100 100" fill="white">
                    <path d="M50 0C50 27.6142 27.6142 50 0 50C27.6142 50 50 72.3858 50 100C50 72.3858 72.3858 50 100 50C72.3858 50 50 27.6142 50 0Z" />
                 </svg>
               </div>
               
               <a 
                href="?page=audit"
                className="relative inline-flex items-center justify-center cursor-pointer font-serif font-medium transition-all duration-500 overflow-hidden rounded-full px-8 py-4 text-lg bg-[#F0F2FF]/20 text-white backdrop-blur-md border border-white/10 hover:bg-white/30 active:scale-95 group"
               >
                 <span className="z-10 relative flex items-center gap-2">Run Your First Audit</span>
               </a>
            </div>
          </div>
        </div>
      </section>

      {/* Comprehensive Sitewide Footer */}
      <footer className="w-full max-w-[1440px] mx-auto px-4 md:px-8 py-16 md:py-24">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-y-12 gap-x-8 mb-20">
          
          {/* Brand Column */}
          <div className="col-span-2 md:col-span-1 flex flex-col gap-6">
              <a href="/" className="inline-block">
                <span className="font-bold text-xl text-[#131313]">ChainProbe</span>
              </a>
              <p className="font-display text-[14px] text-gray-400">Static analysis for Anchor</p>
              
              <div className="flex gap-3 mt-2">
                <div className="flex items-center gap-1.5 px-3 py-2 border border-gray-100 rounded-lg bg-white/50">
                  <span className="text-[10px] font-semibold text-gray-500 tracking-wide">RUST</span>
                </div>
                <div className="flex items-center gap-1.5 px-3 py-2 border border-gray-100 rounded-lg bg-white/50">
                  <span className="text-[10px] font-semibold text-gray-500 tracking-wide">ANCHOR</span>
                </div>
              </div>
          </div>

          {/* Analysis Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Analysis</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Account Validation</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Taint Analysis</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Call Graph</a>
            </div>
          </div>

          {/* Resources Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Resources</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Documentation</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">API Reference</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">GitHub</a>
            </div>
          </div>

          {/* Company Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Company</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">About</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Blog</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Terms of service</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Privacy Policy</a>
            </div>
          </div>

          {/* Socials Column */}
          <div className="flex flex-col gap-5">
            <h4 className="font-display text-[12px] font-semibold text-black uppercase tracking-[1px]">Socials</h4>
            <div className="flex flex-col gap-3">
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Twitter</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">GitHub</a>
              <a href="#" className="text-[14px] text-gray-500 hover:text-black transition-colors">Discord</a>
            </div>
          </div>
          
        </div>

        {/* Bottom Footer Credits */}
        <div className="pt-8 border-t border-black/5 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-[12px] text-gray-400 font-display">Copyright ChainProbe 2026</p>
          <p className="text-[12px] text-gray-400 font-display">Static analysis that understands Anchor</p>
        </div>
      </footer>
    </div>
  );
};

export default CTAFooter;
