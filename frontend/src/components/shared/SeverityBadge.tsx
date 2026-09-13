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
    dot:   'bg-rose-600 dark:bg-[#EF4444] shadow-[0_0_5px_rgba(239,68,68,0.4)] dark:shadow-[0_0_5px_rgba(239,68,68,0.6)]',
    badge: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-red-500/15 dark:text-[#EF4444] dark:border-red-500/30 border',
  },
  high: {
    dot:   'bg-amber-600 dark:bg-[#F97316] shadow-[0_0_5px_rgba(249,115,22,0.4)] dark:shadow-[0_0_5px_rgba(249,115,22,0.6)]',
    badge: 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-orange-500/15 dark:text-[#F97316] dark:border-orange-500/30 border',
  },
  medium: {
    dot:   'bg-yellow-600 dark:bg-[#F59E0B] shadow-[0_0_5px_rgba(245,158,11,0.4)] dark:shadow-[0_0_5px_rgba(245,158,11,0.6)]',
    badge: 'bg-yellow-50 text-yellow-800 border-yellow-200 dark:bg-amber-500/15 dark:text-[#F59E0B] dark:border-amber-500/30 border',
  },
  low: {
    dot:   'bg-emerald-600 dark:bg-[#4FAF72] shadow-[0_0_5px_rgba(79,175,114,0.4)] dark:shadow-[0_0_5px_rgba(79,175,114,0.6)]',
    badge: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-green-500/15 dark:text-[#4FAF72] dark:border-green-500/30 border',
  },
  info: {
    dot:   'bg-slate-500 dark:bg-[#94A3B8]',
    badge: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-500/15 dark:text-[#94A3B8] dark:border-slate-500/30 border',
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
