'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Menu, X, ChevronRight, Zap } from 'lucide-react';

const NAV_LINKS = [
  { label: 'Features', href: '#features' },
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'FAQ', href: '#faq' },
];

export default function LandingNavbar() {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handler);
    return () => window.removeEventListener('scroll', handler);
  }, []);

  return (
    <motion.nav
      initial={{ y: -80, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-[#F7F6F2]/90 dark:bg-[#070707]/90 backdrop-blur-xl border-b border-[#E7E5DF] dark:border-[#2A2A2A]/80 shadow-md dark:shadow-2xl'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo (offset for fixed top-left theme toggle) */}
        <Link href="/" className="flex items-center gap-2.5 group pl-11 sm:pl-12">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center shadow-[0_0_12px_rgba(212,175,55,0.15)] group-hover:shadow-[0_0_20px_rgba(212,175,55,0.3)] transition-all">
            <Shield className="w-5 h-5 text-[#D4AF37]" />
          </div>
          <span className="text-lg font-bold text-[#F5F3ED]">
            SENTINEL<span className="text-[#D4AF37]">SCAN</span>
          </span>
        </Link>

        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-8">
          {NAV_LINKS.map((link) => (
            <a
              key={link.label}
              href={link.href}
              className="text-sm text-[#A7A39A] hover:text-[#F5F3ED] transition-colors duration-200 font-medium"
            >
              {link.label}
            </a>
          ))}
        </div>

        {/* CTA Buttons */}
        <div className="hidden md:flex items-center gap-3">
          <Link href="/login" className="btn-ghost text-sm py-2 px-4">
            Sign In
          </Link>
          <Link href="/signup" className="btn-cyber text-sm py-2 px-5">
            <Zap className="w-4 h-4" />
            <span>Start Free</span>
          </Link>
        </div>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden text-[#A7A39A] hover:text-[#F5F3ED]"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle menu"
        >
          {menuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden bg-[#FFFFFF]/95 dark:bg-[#0D0D0D]/95 backdrop-blur-xl border-b border-[#E7E5DF] dark:border-[#2A2A2A]"
          >
            <div className="px-6 py-4 space-y-3">
              {NAV_LINKS.map((link) => (
                <a
                  key={link.label}
                  href={link.href}
                  onClick={() => setMenuOpen(false)}
                  className="flex items-center justify-between py-2 text-[#A7A39A] hover:text-[#F5F3ED]"
                >
                  {link.label}
                  <ChevronRight className="w-4 h-4 text-[#706C64]" />
                </a>
              ))}
              <div className="pt-3 space-y-2 border-t border-[#2A2A2A]">
                <Link href="/login" className="block text-center btn-ghost w-full">Sign In</Link>
                <Link href="/signup" className="block text-center btn-cyber w-full"><span>Start Free</span></Link>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.nav>
  );
}
