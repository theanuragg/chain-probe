"use client";

import React, { useState, useEffect } from "react";

import { ChevronDown, Menu, X } from "lucide-react";

const Header = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navItems = [
    { label: "PLATFORM", href: "#" },
    { label: "DEVELOPERS", href: "#" },
    { label: "BLOGS", href: "#" },
    { label: "COMPANY", href: "#" },
  ];

  return (
    <header className="fixed top-0 left-0 right-0 z-[10000] p-4 md:p-6 w-full flex justify-center pointer-events-none">
      <nav 
        className={`
          flex justify-between items-center glass-surface 
          shadow-[0px_0px_0px_1px_rgba(0,0,0,0.08)] 
          mx-auto py-3 pr-4 pl-6 rounded-full w-full md:w-11/12 max-w-[1440px]
          transition-all duration-300 pointer-events-auto
          ${isScrolled ? "bg-white/40" : "bg-white/25"}
        `}
      >
        <div className="flex flex-1 justify-between items-center mx-auto max-w-[1440px] w-full">
          {/* Logo Section */}
          <a href="/" className="flex flex-1 items-center gap-2 transition-opacity hover:opacity-80">
            <img 
              src="https://slelguoygbfzlpylpxfs.supabase.co/storage/v1/object/public/test-clones/8cf50684-2b66-43f2-a0ba-6a955350d998-sarvam-ai/assets/svgs/sarvam-wordmark-black-1.svg" 
              alt="Sarvam AI" 
              width={202} 
              height={32}
              className="w-auto h-4 md:h-4.5"
            />
          </a>

          {/* Desktop Navigation Links */}
          <div className="hidden lg:flex flex-2 justify-center items-center gap-2">
            {navItems.map((item) => (
              <div key={item.label} className="relative group">
                <button className="flex items-center gap-1.5 px-4 py-2 rounded-lg transition-colors duration-200 hover:bg-black/5">
                  <span className="font-medium text-[12px] uppercase tracking-[1px] font-display text-[#131313]">
                    {item.label}
                  </span>
                  <ChevronDown className="w-3 h-3 text-[#131313] transition-transform duration-300 group-hover:rotate-180" />
                </button>
              </div>
            ))}
          </div>

          {/* Desktop CTA Buttons */}
          <div className="hidden md:flex flex-1 justify-end items-center gap-3">
            <button className="relative inline-flex items-center justify-center cursor-pointer font-serif font-medium transition-all duration-500 overflow-hidden rounded-full hover:duration-700 active:scale-95 active:duration-200 touch-manipulation px-5 py-3 text-[16px] bg-[#131313] text-white shadow-[inset_0_0_12px_rgba(255,255,255,1),0px_0px_2px_0_rgba(0,0,0,0.1)] group w-fit text-nowrap">
              <span className="absolute inset-0 opacity-0 transition-opacity duration-700 bg-[linear-gradient(90deg,#131313_0%,#0A2156_33%,#BED2FF_66%,#FF8717_100%)] group-hover:opacity-100 group-active:opacity-100 rounded-full shadow-[inset_0px_0px_12px_2px_rgba(255,255,255,0.5)]"></span>
              <span className="z-10 relative flex items-center gap-2 transition-all duration-500">
                Experience Sarvam
              </span>
            </button>
            
            <button className="relative inline-flex items-center justify-center cursor-pointer font-serif font-medium transition-all duration-500 overflow-hidden rounded-full hover:duration-700 active:scale-95 active:duration-200 touch-manipulation px-5 py-3 text-[16px] bg-[#F8F9FB] text-[#131313] shadow-[inset_0_0_12px_rgba(0,0,0,0.09),0px_0px_1px_rgba(0,0,0,0.2)] group w-fit text-nowrap">
              <span className="absolute inset-0 opacity-0 rounded-full transition-opacity duration-700 bg-gradient-to-r from-[#A5BBFC] via-[#D5E2FF] to-[#FFA133] group-hover:opacity-100 group-active:opacity-100 shadow-[inset_0_0_12px_2px_rgba(255,255,255,1)]"></span>
              <span className="z-10 relative flex items-center gap-2 transition-all duration-500">
                Talk to Sales
              </span>
            </button>
          </div>

          {/* Mobile Menu Toggle */}
          <button 
            className="lg:hidden flex flex-col justify-center items-center w-8 h-8 rounded-full hover:bg-black/5"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="absolute top-[calc(100%+12px)] left-4 right-4 lg:hidden pointer-events-auto">
          <div className="bg-white/95 backdrop-blur-[75px] border border-black/8 rounded-[24px] overflow-hidden shadow-xl p-4 flex flex-col gap-4">
            {navItems.map((item) => (
              <a 
                key={item.label} 
                href={item.href} 
                className="px-4 py-3 font-display font-medium text-[14px] uppercase tracking-[1px] text-[#131313] hover:bg-black/5 rounded-xl flex justify-between items-center"
              >
                {item.label}
                <ChevronDown className="w-4 h-4 -rotate-90" />
              </a>
            ))}
            <div className="h-px bg-black/5 my-2" />
            <div className="flex flex-col gap-3 pb-2">
              <button className="w-full py-4 bg-[#131313] text-white rounded-full font-serif font-medium">
                Experience Sarvam
              </button>
              <button className="w-full py-4 bg-[#F8F9FB] text-[#131313] border border-black/5 rounded-full font-serif font-medium">
                Talk to Sales
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

export default Header;