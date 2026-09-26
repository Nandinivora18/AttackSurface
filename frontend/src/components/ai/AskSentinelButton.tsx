'use client';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAIStore } from '@/store/aiStore';
import { useAuthStore } from '@/store';
import { cn } from '@/lib/utils';
import { Crosshair } from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
//  Sentinel Intelligence — four-point star SVG mark
//  The orbit ring always rotates (slowly) to feel "alive", not like a spinner.
//  The rest of the star is static. Subtle. Premium.
// ─────────────────────────────────────────────────────────────────────────────
function SentinelCoreMark({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      style={{ display: 'block' }}
    >
      {/* Slowly rotating dashed orbit — uses CSS class injected globally */}
      <circle
        cx="12"
        cy="12"
        r="10.5"
        stroke="currentColor"
        strokeWidth="0.6"
        strokeDasharray="1.5 4"
        opacity="0.28"
        className="si-orbit"
      />
      {/* Inner ring — static */}
      <circle cx="12" cy="12" r="6" stroke="currentColor" strokeWidth="0.35" opacity="0.15" />
      {/* Four-point star arms */}
      <path d="M12 1.5 L12.9 9.5 L12 10.5 L11.1 9.5 Z" fill="currentColor" />
      <path d="M12 22.5 L12.9 14.5 L12 13.5 L11.1 14.5 Z" fill="currentColor" />
      <path d="M1.5 12 L9.5 12.9 L10.5 12 L9.5 11.1 Z" fill="currentColor" />
      <path d="M22.5 12 L14.5 12.9 L13.5 12 L14.5 11.1 Z" fill="currentColor" />
      {/* Center diamond */}
      <path d="M12 9.8 L14.2 12 L12 14.2 L9.8 12 Z" fill="currentColor" opacity="0.9" />
      {/* Orbit particle — top */}
      <circle cx="12" cy="1.5" r="0.7" fill="currentColor" opacity="0.5" className="si-orbit" />
    </svg>
  );
}

interface AskSentinelButtonProps {
  className?: string;
}

export default function AskSentinelButton({ className }: AskSentinelButtonProps) {
  const { isOpen, openAssistant, setCircleToSentinelActive } = useAIStore();
  const { user } = useAuthStore();
  const [isHovered, setIsHovered] = useState(false);
  const [idlePulse, setIdlePulse] = useState(false);
  const [c2sHovered, setC2sHovered] = useState(false);

  // Idle glow pulse: every 6s, briefly brightens for 1.8s then rests.
  // Does NOT run while hovered.
  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    const schedule = () => {
      timeout = setTimeout(() => {
        if (!isHovered) {
          setIdlePulse(true);
          setTimeout(() => {
            setIdlePulse(false);
            schedule();
          }, 1800);
        } else {
          schedule();
        }
      }, 5000);
    };
    schedule();
    return () => clearTimeout(timeout);
  }, [isHovered]);

  if (!user) return null;

  return (
    <>
      {/* Global keyframes — injected once */}
      <style>{`
        @keyframes siOrbit {
          to { transform: rotate(360deg); }
        }
        .si-orbit {
          transform-origin: 12px 12px;
          animation: siOrbit 18s linear infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .si-orbit { animation: none; }
        }
      `}</style>

      <AnimatePresence>
        {!isOpen && (
          <>
            {/* ── Circle to Sentinel secondary button ── */}
            <motion.button
              key="c2s-btn"
              initial={{ opacity: 0, x: 8, scale: 0.9 }}
              animate={{ opacity: isHovered ? 1 : 0, x: isHovered ? 0 : 8, scale: isHovered ? 1 : 0.92 }}
              exit={{ opacity: 0, x: 8, scale: 0.9 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              onClick={() => setCircleToSentinelActive(true)}
              onHoverStart={() => setC2sHovered(true)}
              onHoverEnd={() => setC2sHovered(false)}
              id="circle-to-sentinel-btn"
              aria-label="Circle to Sentinel: select a screen region for AI analysis (Ctrl+Shift+S)"
              title="Circle to Sentinel (Ctrl+Shift+S)"
              className="fixed bottom-[72px] right-6 z-[400] flex items-center gap-2 rounded-xl px-3 py-2 pointer-events-auto"
              style={{
                background: 'linear-gradient(160deg, #141414 0%, #0A0A0A 100%)',
                border: `1px solid ${c2sHovered ? 'rgba(212,175,55,0.45)' : 'rgba(212,175,55,0.16)'}`,
                boxShadow: c2sHovered
                  ? '0 8px 28px rgba(0,0,0,0.7), 0 0 16px rgba(212,175,55,0.14)'
                  : '0 4px 16px rgba(0,0,0,0.5)',
                transform: c2sHovered ? 'translateY(-1px)' : 'none',
                transition: 'all 0.2s ease',
              }}
            >
              <Crosshair
                className="w-3.5 h-3.5 flex-shrink-0 transition-colors duration-200"
                style={{ color: c2sHovered ? '#D4AF37' : 'rgba(212,175,55,0.45)' }}
              />
              <span className="text-[9.5px] font-mono font-semibold" style={{ color: c2sHovered ? '#D8D5CD' : '#5C5852', letterSpacing: '0.05em' }}>
                Circle to Sentinel
              </span>
              <kbd
                className="text-[8px] font-mono px-1 py-0.5 rounded"
                style={{ background: '#1A1A1A', color: '#D4AF37', border: '1px solid #2C2A26' }}
              >
                ⌃⇧S
              </kbd>
            </motion.button>

            {/* ── Main FAB ── */}
            <motion.button
              key="si-fab"
              initial={{ opacity: 0, y: 20, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 16, scale: 0.9 }}
              whileTap={{ scale: 0.96 }}
              transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
              onClick={() => openAssistant()}
              onHoverStart={() => setIsHovered(true)}
              onHoverEnd={() => setIsHovered(false)}
              id="ask-sentinel-fab"
              aria-label="Open Sentinel Intelligence"
              className={cn(
                'fixed bottom-6 right-6 z-[400]',
                'flex items-center gap-0',
                'rounded-2xl overflow-hidden',
                'transition-[box-shadow,transform] duration-300',
                className,
              )}
              style={{
                background: 'linear-gradient(160deg, #141414 0%, #0A0A0A 100%)',
                border: `1px solid ${isHovered ? 'rgba(212,175,55,0.60)' : idlePulse ? 'rgba(212,175,55,0.35)' : 'rgba(212,175,55,0.22)'}`,
                boxShadow: isHovered
                  ? '0 12px 40px rgba(0,0,0,0.85), 0 0 28px rgba(212,175,55,0.22)'
                  : idlePulse
                    ? '0 8px 28px rgba(0,0,0,0.7), 0 0 16px rgba(212,175,55,0.15)'
                    : '0 8px 28px rgba(0,0,0,0.6), 0 0 8px rgba(212,175,55,0.06)',
                transform: isHovered ? 'translateY(-2px)' : 'translateY(0)',
              }}
            >
              {/* ── Icon core ── */}
              <div className="relative w-[46px] h-[46px] flex items-center justify-center flex-shrink-0">
                {/* Radial ambient glow */}
                <div
                  className="absolute inset-0 rounded-2xl pointer-events-none"
                  style={{
                    background: 'radial-gradient(ellipse at center, rgba(212,175,55,0.10) 0%, transparent 65%)',
                    opacity: isHovered ? 1.8 : idlePulse ? 1.2 : 0.7,
                    transition: 'opacity 0.6s ease',
                  }}
                />
                {/* Icon container */}
                <div
                  className="relative w-8 h-8 rounded-xl flex items-center justify-center transition-all duration-300"
                  style={{
                    background: 'linear-gradient(145deg, #1C1808, #0D0B06)',
                    border: `1px solid ${isHovered ? 'rgba(212,175,55,0.55)' : 'rgba(212,175,55,0.25)'}`,
                    boxShadow: isHovered
                      ? '0 0 16px rgba(212,175,55,0.22), inset 0 1px 0 rgba(212,175,55,0.08)'
                      : '0 0 8px rgba(212,175,55,0.08)',
                  }}
                >
                  <span
                    className="text-[#D4AF37] transition-transform duration-300"
                    style={{ transform: isHovered ? 'scale(1.08)' : 'scale(1)' }}
                  >
                    <SentinelCoreMark size={16} />
                  </span>
                </div>
              </div>

              {/* ── Expandable label (hidden → shown on hover) ── */}
              <motion.div
                animate={{
                  width: isHovered ? 168 : 0,
                  opacity: isHovered ? 1 : 0,
                }}
                transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                style={{ overflow: 'hidden' }}
              >
                <div className="pr-4 whitespace-nowrap">
                  <div
                    className="text-[10.5px] font-black font-mono uppercase leading-none"
                    style={{ color: '#F5F3ED', letterSpacing: '0.08em' }}
                  >
                    Sentinel Intelligence
                  </div>
                  <div
                    className="text-[8.5px] font-mono mt-0.5 leading-none"
                    style={{ color: '#D4AF37', opacity: 0.75, letterSpacing: '0.06em' }}
                  >
                    Security Intelligence Assistant
                  </div>
                </div>
              </motion.div>

              {/* ── Compact label (always visible, hides when hover label is shown) ── */}
              <motion.div
                animate={{ width: isHovered ? 0 : 74, opacity: isHovered ? 0 : 1 }}
                transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                style={{ overflow: 'hidden' }}
              >
                <div className="pr-3 whitespace-nowrap">
                  <div
                    className="text-[9.5px] font-bold font-mono uppercase leading-none"
                    style={{ color: '#E6E4DD', letterSpacing: '0.06em' }}
                  >
                    Intelligence
                  </div>
                  <div className="flex items-center gap-1 mt-1">
                    <span
                      className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                      style={{
                        background: '#4FAF72',
                        boxShadow: '0 0 5px rgba(79,175,114,0.65)',
                      }}
                    />
                    <span
                      className="text-[7.5px] font-mono uppercase"
                      style={{ color: '#D4AF37', opacity: 0.7, letterSpacing: '0.1em' }}
                    >
                      Online
                    </span>
                  </div>
                </div>
              </motion.div>
            </motion.button>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
