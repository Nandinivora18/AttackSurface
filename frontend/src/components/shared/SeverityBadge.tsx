'use client';
import { Severity } from '@/types';
import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
  className?: string;
  count?: number;
}

const SEVERITY_STYLES: Record<Severity, { dot: string; badge: string }> = {
  critical: {
    dot:   'bg-[#EF4444] shadow-[0_0_5px_rgba(239,68,68,0.6)]',
    badge: 'bg-red-500/15 text-[#EF4444] border border-red-500/30',
  },
  high: {
    dot:   'bg-[#F97316] shadow-[0_0_5px_rgba(249,115,22,0.6)]',
    badge: 'bg-orange-500/15 text-[#F97316] border border-orange-500/30',
  },
  medium: {
    dot:   'bg-[#F59E0B] shadow-[0_0_5px_rgba(245,158,11,0.6)]',
    badge: 'bg-amber-500/15 text-[#F59E0B] border border-amber-500/30',
  },
  low: {
    dot:   'bg-[#4FAF72] shadow-[0_0_5px_rgba(79,175,114,0.6)]',
    badge: 'bg-green-500/15 text-[#4FAF72] border border-green-500/30',
  },
  info: {
    dot:   'bg-[#94A3B8]',
    badge: 'bg-slate-500/15 text-[#94A3B8] border border-slate-500/30',
  },
};

export default function SeverityBadge({
  severity,
  size = 'md',
  className,
  count,
}: SeverityBadgeProps) {
  const styles = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full font-bold tracking-wide capitalize',
        size === 'sm'
          ? 'text-[10px] px-2 py-0.5 gap-1'
          : 'text-[11px] px-2.5 py-0.5 gap-1.5',
        styles.badge,
        className,
      )}
    >
      <span
        className={cn('rounded-full flex-shrink-0', size === 'sm' ? 'w-1.5 h-1.5' : 'w-2 h-2', styles.dot)}
        aria-hidden="true"
      />
      <span>{severity}{count !== undefined && ` (${count})`}</span>
    </span>
  );
}
