'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';

type SpinnerSize = 'xs' | 'sm' | 'md' | 'lg';

const sizes: Record<SpinnerSize, string> = {
  xs: 'w-3 h-3 border-[1.5px]',
  sm: 'w-4 h-4 border-2',
  md: 'w-5 h-5 border-2',
  lg: 'w-6 h-6 border-[2.5px]',
};

interface SpinnerProps {
  size?: SpinnerSize;
  className?: string;
  'aria-label'?: string;
}

/**
 * Consistent loading spinner used across all loading states.
 * Inherits the current text color by default.
 */
export function Spinner({
  size = 'md',
  className,
  'aria-label': ariaLabel = 'Loading…',
}: SpinnerProps) {
  return (
    <span
      role="status"
      aria-label={ariaLabel}
      className={cn(
        'inline-block rounded-full border-current/30 border-t-current animate-spin flex-shrink-0',
        sizes[size],
        className,
      )}
    />
  );
}
