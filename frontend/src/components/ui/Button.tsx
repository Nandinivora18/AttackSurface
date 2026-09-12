'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';
import { Spinner } from './Spinner';

type ButtonVariant = 'primary' | 'ghost' | 'danger' | 'success' | 'outline';
type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  leftIcon?: React.ElementType;
  rightIcon?: React.ElementType;
  fullWidth?: boolean;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary: [
    'relative overflow-hidden isolate',
    'bg-gradient-to-r from-[#D4AF37] via-[#C6A15B] to-[#8A7029] text-[#070707] font-bold',
    'border-0',
    'shadow-[0_4px_14px_rgba(212,175,55,0.25)]',
    'hover:-translate-y-px hover:shadow-[0_6px_22px_rgba(212,175,55,0.35)] hover:text-[#070707]',
    'active:translate-y-0 active:text-[#070707] active:bg-[#8A7029]',
    'focus:text-[#070707] focus-visible:text-[#070707]',
    'disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none disabled:shadow-none disabled:text-[#444444]',
    // Sheen overlay
    'before:absolute before:inset-0 before:-z-10',
    'before:bg-gradient-to-r before:from-[#E7C873] before:to-[#D4AF37]',
    'before:opacity-0 hover:before:opacity-100 before:transition-opacity before:duration-200',
    'before:pointer-events-none',
    '[&>span]:relative [&>span]:z-10',
  ].join(' '),

  ghost: [
    'bg-transparent text-[#A7A39A] font-medium',
    'border border-[#2A2A2A]',
    'hover:text-[#F5F3ED] hover:border-[#5C4A20] hover:bg-[#D4AF37]/10',
    'active:bg-[#D4AF37]/15',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),

  danger: [
    'bg-transparent text-[#EF4444] font-semibold',
    'border border-red-500/30',
    'hover:bg-red-500/10 hover:border-red-500/60 hover:text-red-300',
    'active:bg-red-500/15',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),

  success: [
    'bg-green-600/15 text-[#22C55E] font-semibold',
    'border border-green-500/30',
    'hover:bg-green-600/25 hover:border-green-500/50',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),

  outline: [
    'bg-[#111111] text-[#A7A39A] font-medium',
    'border border-[#2A2A2A]',
    'hover:bg-[#161616] hover:text-[#F5F3ED] hover:border-[#5C4A20]',
    'disabled:opacity-40 disabled:cursor-not-allowed',
  ].join(' '),
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-lg',
  md: 'h-10 px-5 text-sm gap-2 rounded-[10px]',
  lg: 'h-12 px-7 text-[15px] gap-2.5 rounded-[10px]',
};

const iconSize: Record<ButtonSize, string> = {
  sm: 'w-3.5 h-3.5',
  md: 'w-4 h-4',
  lg: 'w-[18px] h-[18px]',
};

/**
 * Unified Button component for all interactive actions in SentinelScan.
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      loading = false,
      leftIcon: LeftIcon,
      rightIcon: RightIcon,
      fullWidth = false,
      className,
      children,
      disabled,
      type = 'button',
      ...props
    },
    ref,
  ) => {
    const isDisabled = disabled || loading;

    return (
      <button
        ref={ref}
        type={type}
        disabled={isDisabled}
        className={cn(
          'inline-flex items-center justify-center',
          'transition-all duration-200 cursor-pointer select-none',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#D4AF37]/50 focus-visible:ring-offset-2 focus-visible:ring-offset-[#070707]',
          variantClasses[variant],
          sizeClasses[size],
          fullWidth && 'w-full',
          className,
        )}
        aria-disabled={isDisabled}
        {...props}
      >
        <span className="inline-flex items-center justify-center gap-[inherit]">
          {loading ? (
            <Spinner size={size === 'sm' ? 'xs' : 'sm'} />
          ) : (
            LeftIcon && <LeftIcon className={iconSize[size]} aria-hidden="true" />
          )}
          {children}
          {!loading && RightIcon && (
            <RightIcon className={iconSize[size]} aria-hidden="true" />
          )}
        </span>
      </button>
    );
  },
);

Button.displayName = 'Button';
