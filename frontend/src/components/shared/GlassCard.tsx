'use client';
import { cn } from '@/lib/utils';
import { motion } from 'framer-motion';

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  glow?: 'blue' | 'purple' | 'gold' | 'none';
  onClick?: () => void;
  style?: React.CSSProperties;
  role?: string;
  'aria-label'?: string;
  'aria-labelledby'?: string;
  'aria-busy'?: boolean | 'true' | 'false';
  id?: string;
}

export default function GlassCard({
  children, className, hover = false, glow = 'none', onClick, style,
  role, id,
  'aria-label': ariaLabel,
  'aria-labelledby': ariaLabelledby,
  'aria-busy': ariaBusy,
}: GlassCardProps) {
  const glowClass = {
    blue: 'hover:shadow-[0_0_20px_rgba(212,175,55,0.15)] hover:border-[#5C4A20]',
    purple: 'hover:shadow-[0_0_20px_rgba(212,175,55,0.15)] hover:border-[#5C4A20]',
    gold: 'hover:shadow-[0_0_20px_rgba(212,175,55,0.2)] hover:border-[#D4AF37]/50',
    none: '',
  }[glow];

  return (
    <div
      onClick={onClick}
      style={style}
      role={role}
      id={id}
      aria-label={ariaLabel}
      aria-labelledby={ariaLabelledby}
      aria-busy={ariaBusy}
      className={cn(
        'glass-card',
        hover && 'glass-card-hover cursor-pointer',
        glow !== 'none' && glowClass,
        className
      )}
    >
      {children}
    </div>
  );
}
