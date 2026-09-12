'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';

interface PageHeaderProps {
  /** Page H1 title */
  title: string;
  /** Optional subtitle / description */
  subtitle?: string;
  /** Optional leading icon (Lucide) */
  icon?: React.ElementType;
  /** Optional slot for right-side actions (buttons etc.) */
  actions?: React.ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  subtitle,
  icon: Icon,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn('flex items-start justify-between gap-4 flex-wrap', className)}>
      <div>
        <h1 className="text-[28px] font-bold text-[#F5F5F5] tracking-tight leading-tight flex items-center gap-2.5">
          {Icon && (
            <Icon className="w-6 h-6 text-[#D4AF37] flex-shrink-0" aria-hidden="true" />
          )}
          {title}
        </h1>
        {subtitle && (
          <p className="text-xs text-[#A1A1A1] mt-1.5 leading-relaxed">{subtitle}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-3 flex-shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
}
