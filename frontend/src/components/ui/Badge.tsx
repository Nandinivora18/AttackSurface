'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';

type BadgeVariant =
  | 'critical' | 'high' | 'medium' | 'low' | 'info'
  | 'blue' | 'purple' | 'green' | 'amber' | 'red' | 'slate' | 'forest' | 'champagne' | 'burgundy' | 'gold'
  | 'success' | 'warning';

const variantClasses: Record<BadgeVariant, string> = {
  // Severity
  critical:  'bg-red-500/15 text-[#EF4444] border-red-500/30',
  high:      'bg-orange-500/15 text-[#F97316] border-orange-500/30',
  medium:    'bg-amber-500/15 text-[#F59E0B] border-amber-500/30',
  low:       'bg-green-500/15 text-[#4FAF72] border-green-500/30',
  info:      'bg-slate-500/15 text-[#94A3B8] border-slate-500/30',
  // Semantic
  success:   'bg-green-500/15 text-[#22C55E] border-green-500/30',
  warning:   'bg-amber-500/15 text-[#F59E0B] border-amber-500/30',
  forest:    'bg-green-500/15 text-[#4FAF72] border-green-500/30',
  champagne: 'bg-[#5C4A20]/25 text-[#D4AF37] border-[#5C4A20]',
  gold:      'bg-[#5C4A20]/25 text-[#D4AF37] border-[#5C4A20]',
  burgundy:  'bg-[#5C4A20]/25 text-[#D4AF37] border-[#5C4A20]',
  // UI colors
  blue:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
  purple:    'bg-purple-500/15 text-purple-400 border-purple-500/30',
  green:     'bg-green-500/15 text-[#22C55E] border-green-500/30',
  amber:     'bg-amber-500/15 text-[#F59E0B] border-amber-500/30',
  red:       'bg-red-500/15 text-[#EF4444] border-red-500/30',
  slate:     'bg-[#1F1F1F] text-[#A7A39A] border-[#2A2A2A]',
};

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
  className?: string;
  dot?: boolean;
  uppercase?: boolean;
}

/**
 * Generic badge for statuses, labels, counts and tags.
 */
export function Badge({
  variant = 'slate',
  children,
  className,
  dot = false,
  uppercase = false,
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full',
        'border text-[11px] font-bold tracking-wide leading-none',
        uppercase && 'uppercase',
        variantClasses[variant] || variantClasses.slate,
        className,
      )}
    >
      {dot && (
        <span
          className={cn('w-1.5 h-1.5 rounded-full bg-current flex-shrink-0')}
          aria-hidden="true"
        />
      )}
      {children}
    </span>
  );
}
