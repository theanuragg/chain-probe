import React from 'react';

const FutureAI = () => {
  const featurePoints = [
    {
      title: "Deterministic analysis",
      description: "No AI hallucinations, no pattern matching. Uses syn to parse every .rs file into a full Rust AST — the same parser the Rust compiler uses."
    },
    {
      title: "Multi-stage pipeline",
      description: "Eight analysis stages — AST extraction, trust classification, taint analysis, invariant mining, call graph, pattern detection, chain detection, and exploitability scoring."
    },
    {
      title: "Exploit proof, not descriptions",
      description: "Generates runnable #[tokio::test] PoCs that prove each vulnerability is real, plus side-by-side fix diffs with actual corrected Anchor code."
    }
  ];

  return (
    <section className="relative mx-auto w-full md:w-[85%] lg:w-9/12 max-w-[1440px] px-4 md:px-0 py-16 md:py-24">
      <div className="flex flex-col items-center gap-8 md:gap-16">
        {/* Section Heading */}
        <div className="flex flex-col items-center text-center gap-6 w-full">
          <h2 className="font-serif font-normal text-3xl md:text-[36px] text-[#131313] leading-[1.35] whitespace-pre-line px-3 md:px-0">
            Why existing tools miss vulnerabilities
          </h2>
        </div>

        {/* Feature Card Wrapper */}
        <div className="flex md:flex-row flex-col gap-3 bg-white p-4 md:p-6 rounded-[24px] md:rounded-[48px] w-full overflow-hidden shadow-[0px_0px_60px_0px_rgba(85,106,220,0.12)] border border-[rgba(0,0,0,0.08)]">
          
          {/* Left: Visual Container */}
          <div className="relative rounded-2xl md:rounded-[36px] w-full md:w-[50%] h-[250px] md:h-[420px] overflow-hidden shrink-0 bg-gradient-to-br from-[#131313] via-[#0A2156] to-[#556ADC] flex items-center justify-center">
            {/* Code snippet decoration */}
            <div className="absolute inset-0 p-8 md:p-12 flex flex-col justify-center">
              <div className="font-mono text-[10px] md:text-xs text-white/70 leading-relaxed">
                <div className="text-[#556ADC] mb-1">{'// ChainProbe v4 Analysis Pipeline'}</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 1</span> → AST Extraction</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 2</span> → Trust Classification</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 3</span> → Taint Analysis</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 4</span> → Invariant Mining</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 5</span> → Call Graph & CPI</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 6</span> → Pattern Detection</div>
                <div className="mb-1"><span className="text-[#FF8717]">Stage 7</span> → Chain Detection</div>
                <div><span className="text-[#FF8717]">Stage 8</span> → Exploitability Score</div>
              </div>
            </div>
            
            {/* Overlay accent */}
            <div className="absolute bottom-6 left-6 right-6 glass-surface rounded-[16px] border border-white/30 p-4 backdrop-blur-sm">
              <div className="font-mono text-[10px] text-white/90">
                <span className="text-green-400">✓</span> Security Score: <span className="text-white font-bold">42/100</span>
                <span className="ml-3 text-[#FF3D5C]">2 Critical</span>
                <span className="ml-3 text-[#FFAA33]">3 High</span>
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
                    className="w-5 h-5"
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
