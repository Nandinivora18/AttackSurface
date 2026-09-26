'use client';
import { motion } from 'framer-motion';
import { useAIStore } from '@/store/aiStore';
import { cn } from '@/lib/utils';

// Sentinel Intelligence mark
function SentinelMark({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ display: 'block' }}>
      <circle cx="12" cy="12" r="10.5" stroke="currentColor" strokeWidth="0.5" strokeDasharray="1.5 4" opacity="0.25" />
      <path d="M12 1.5 L12.9 9.5 L12 10.5 L11.1 9.5 Z" fill="currentColor" />
      <path d="M12 22.5 L12.9 14.5 L12 13.5 L11.1 14.5 Z" fill="currentColor" />
      <path d="M1.5 12 L9.5 12.9 L10.5 12 L9.5 11.1 Z" fill="currentColor" />
      <path d="M22.5 12 L14.5 12.9 L13.5 12 L14.5 11.1 Z" fill="currentColor" />
      <path d="M12 9.8 L14.2 12 L12 14.2 L9.8 12 Z" fill="currentColor" opacity="0.85" />
    </svg>
  );
}

interface FindingAskButtonProps {
  findingId: string;
  findingTitle?: string;
  reportScanUrl?: string;
  className?: string;
  variant?: 'inline' | 'card';
}

export default function FindingAskButton({
  findingId,
  findingTitle,
  reportScanUrl,
  className,
  variant = 'inline',
}: FindingAskButtonProps) {
  const { openAssistant } = useAIStore();

  const handleClick = () => {
    openAssistant({
      findingId,
      findingTitle,
      scanUrl: reportScanUrl,
      contextType: 'finding',
    });
  };

  // Compact card badge variant
  if (variant === 'card') {
    return (
      <button
        onClick={handleClick}
        id={`ask-sentinel-finding-${findingId}`}
        aria-label={`Open Sentinel Intelligence for: ${findingTitle || 'this finding'}`}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-lg transition-all duration-150',
          className,
        )}
        style={{
          padding: '4px 10px',
          fontSize: '10.5px',
          fontWeight: 600,
          background: '#0D0D0D',
          border: '1px solid rgba(212,175,55,0.18)',
          color: '#D4AF37',
        }}
        onMouseEnter={e => {
          const el = e.currentTarget as HTMLElement;
          el.style.borderColor = 'rgba(212,175,55,0.45)';
          el.style.background = '#121008';
          el.style.boxShadow = '0 0 12px rgba(212,175,55,0.12)';
        }}
        onMouseLeave={e => {
          const el = e.currentTarget as HTMLElement;
          el.style.borderColor = 'rgba(212,175,55,0.18)';
          el.style.background = '#0D0D0D';
          el.style.boxShadow = 'none';
        }}
      >
        <span className="text-[#D4AF37]"><SentinelMark size={10} /></span>
        <span>Intelligence</span>
      </button>
    );
  }

  // Full inline variant
  return (
    <motion.button
      whileHover={{ y: -1 }}
      whileTap={{ scale: 0.97 }}
      onClick={handleClick}
      id={`ask-sentinel-finding-${findingId}`}
      aria-label={`Open Sentinel Intelligence for: ${findingTitle || 'this finding'}`}
      className={cn('group flex items-center gap-2.5 rounded-xl transition-all duration-200', className)}
      style={{
        padding: '8px 16px',
        background: 'linear-gradient(135deg, #121008, #0D0B06)',
        border: '1px solid rgba(212,175,55,0.18)',
        color: '#E6E4DD',
      }}
      onMouseEnter={e => {
        const el = e.currentTarget as HTMLElement;
        el.style.borderColor = 'rgba(212,175,55,0.45)';
        el.style.boxShadow = '0 0 20px rgba(212,175,55,0.14)';
      }}
      onMouseLeave={e => {
        const el = e.currentTarget as HTMLElement;
        el.style.borderColor = 'rgba(212,175,55,0.18)';
        el.style.boxShadow = 'none';
      }}
    >
      {/* Icon */}
      <div
        className="w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0 transition-all duration-200"
        style={{
          background: '#181408',
          border: '1px solid rgba(212,175,55,0.25)',
          color: '#D4AF37',
        }}
      >
        <SentinelMark size={12} />
      </div>
      {/* Label */}
      <div className="flex flex-col leading-none gap-0.5">
        <span style={{ fontSize: '11px', fontWeight: 700, color: '#E6E4DD', letterSpacing: '0.04em', fontFamily: 'ui-monospace,monospace', textTransform: 'uppercase' }}>
          Sentinel Intelligence
        </span>
        <span style={{ fontSize: '9px', color: 'rgba(212,175,55,0.55)', fontFamily: 'monospace', letterSpacing: '0.06em' }}>
          Analyze this finding
        </span>
      </div>
    </motion.button>
  );
}
