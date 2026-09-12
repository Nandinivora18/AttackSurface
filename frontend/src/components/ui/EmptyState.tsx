'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';

interface EmptyStateProps {
  icon?: React.ElementType;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center py-16 px-6 text-center',
        className,
      )}
      role="status"
    >
      {Icon && (
        <div className="w-14 h-14 rounded-2xl bg-[#111111] border border-[#2A2A2A] flex items-center justify-center mb-5 shadow-sm">
          <Icon className="w-7 h-7 text-[#706C64]" aria-hidden="true" />
        </div>
      )}
      <p className="text-base font-semibold text-[#F5F3ED] mb-1.5">{title}</p>
      {description && (
        <p className="text-sm text-[#A7A39A] max-w-xs leading-relaxed mb-6">
          {description}
        </p>
      )}
      {action && <div>{action}</div>}
    </div>
  );
}
