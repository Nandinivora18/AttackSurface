'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  /** Lucide icon rendered on the left side of the input */
  leftIcon?: React.ElementType;
  /** Lucide icon or element rendered on the right side */
  rightElement?: React.ReactNode;
  /** Error message — renders red border + helper text */
  error?: string;
  /** Success state — renders green border */
  success?: boolean;
  /** Optional label (renders above the input) */
  label?: string;
  /** Helper / description text below the input */
  hint?: string;
  /** Wrapper className — applied to the outer div */
  wrapperClassName?: string;
  /** Controls the visual size of the input */
  inputSize?: 'sm' | 'md' | 'lg';
}

const sizeClasses = {
  sm: 'h-9 text-[13px] px-3.5',
  md: 'h-[42px] text-sm px-4',
  lg: 'h-12 text-[15px] px-4',
};

const sizeIconLeft = {
  sm: '!pl-10',
  md: '!pl-11',
  lg: '!pl-12',
};

const sizeIconRight = {
  sm: '!pr-10',
  md: '!pr-11',
  lg: '!pr-12',
};

const sizeIconSize = {
  sm: 'w-4 h-4',
  md: 'w-4 h-4',
  lg: 'w-[18px] h-[18px]',
};

const iconLeftOffset = {
  sm: 'left-3.5',
  md: 'left-3.5',
  lg: 'left-4',
};

const iconRightOffset = {
  sm: 'right-3.5',
  md: 'right-3.5',
  lg: 'right-4',
};

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      leftIcon: LeftIcon,
      rightElement,
      error,
      success,
      label,
      hint,
      wrapperClassName,
      inputSize = 'md',
      className,
      disabled,
      id,
      ...props
    },
    ref,
  ) => {
    const generatedId = React.useId();
    const inputId = id ?? generatedId;

    const borderClass = error
      ? 'border-red-500/60 focus:border-red-500/80 focus:shadow-[0_0_0_3px_rgba(239,68,68,0.15)]'
      : success
      ? 'border-green-500/50 focus:border-green-500/70 focus:shadow-[0_0_0_3px_rgba(34,197,94,0.15)]'
      : 'border-cyber-border focus:border-cyber-gold focus:shadow-[0_0_0_3px_rgba(184,134,11,0.15)]';

    return (
      <div className={cn('flex flex-col gap-1.5', wrapperClassName)}>
        {label && (
          <label
            htmlFor={inputId}
            className="block text-xs font-semibold uppercase tracking-wide text-cyber-secondary select-none"
          >
            {label}
          </label>
        )}

        <div className="relative">
          {LeftIcon && (
            <LeftIcon
              className={cn(
                'absolute top-1/2 -translate-y-1/2 flex-shrink-0 text-cyber-muted pointer-events-none',
                iconLeftOffset[inputSize],
                sizeIconSize[inputSize],
              )}
              aria-hidden="true"
            />
          )}

          <input
            ref={ref}
            id={inputId}
            disabled={disabled}
            className={cn(
              // Base
              'w-full rounded-[10px] bg-cyber-surface text-cyber-primary',
              'border transition-all duration-150 outline-none [font-variant-ligatures:none]',
              'placeholder:text-cyber-muted',
              // Size
              sizeClasses[inputSize],
              LeftIcon && sizeIconLeft[inputSize],
              rightElement && sizeIconRight[inputSize],
              // State
              borderClass,
              // Disabled
              disabled && 'opacity-50 cursor-not-allowed',
              className,
            )}
            aria-invalid={error ? 'true' : undefined}
            aria-describedby={
              error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined
            }
            {...props}
          />

          {rightElement && (
            <div
              className={cn(
                'absolute top-1/2 -translate-y-1/2 flex items-center',
                iconRightOffset[inputSize],
              )}
            >
              {rightElement}
            </div>
          )}
        </div>

        {error && (
          <p id={`${inputId}-error`} role="alert" className="text-xs text-red-500 dark:text-red-400 flex items-center gap-1">
            {error}
          </p>
        )}

        {!error && hint && (
          <p id={`${inputId}-hint`} className="text-[11px] text-cyber-muted">
            {hint}
          </p>
        )}
      </div>
    );
  },
);

Input.displayName = 'Input';
