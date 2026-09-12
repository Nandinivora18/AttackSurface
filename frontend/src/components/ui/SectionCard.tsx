'use client';
import * as React from 'react';
import GlassCard from '@/components/shared/GlassCard';
import { cn } from '@/lib/utils';

interface SectionCardProps {
  icon?: React.ElementType;
  title: string;
  subtitle?: string;
  /** Slot for right-side actions in the header */
  headerActions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  /** Color accent for the icon container */
  accent?: 'blue' | 'purple' | 'red' | 'green' | 'gold';
}

const accentClasses = {
  blue:   'bg-[#5C4A20]/20 border-[#5C4A20] text-[#D4AF37]',
  purple: 'bg-[#5C4A20]/20 border-[#5C4A20] text-[#D4AF37]',
  gold:   'bg-[#5C4A20]/20 border-[#5C4A20] text-[#D4AF37]',
  red:    'bg-red-500/10 border-red-500/20 text-[#EF4444]',
  green:  'bg-green-500/10 border-green-500/20 text-[#22C55E]',
};

export function SectionCard({
  icon: Icon,
  title,
  subtitle,
  headerActions,
  children,
  className,
  accent = 'gold',
}: SectionCardProps) {
  return (
    <GlassCard className={cn('p-6', className)}>
      <div className="flex items-start justify-between gap-4 mb-6 pb-5 border-b border-[#2A2A2A]/60">
        <div className="flex items-start gap-3">
          {Icon && (
            <div
              className={cn(
                'w-9 h-9 rounded-xl border flex items-center justify-center flex-shrink-0 mt-0.5 shadow-sm',
                accentClasses[accent],
              )}
            >
              <Icon className="w-[18px] h-[18px]" aria-hidden="true" />
            </div>
          )}
          <div>
            <h2 className="font-semibold text-[#F5F3ED] text-[15px] leading-tight">{title}</h2>
            {subtitle && (
              <p className="text-xs text-[#A7A39A] mt-0.5">{subtitle}</p>
            )}
          </div>
        </div>
        {headerActions && (
          <div className="flex-shrink-0">{headerActions}</div>
        )}
      </div>
      {children}
    </GlassCard>
  );
}
