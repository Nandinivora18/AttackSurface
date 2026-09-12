'use client';
import * as React from 'react';
import { cn } from '@/lib/utils';
import { Input, type InputProps } from './Input';

interface FormFieldProps extends InputProps {
  /** Rendered above the input as an accessible <label> */
  label: string;
  /** Error message — shown below the input in red */
  error?: string;
  /** Helper text shown when there is no error */
  hint?: string;
  /** Optional wrapper className */
  className?: string;
}

/**
 * FormField = label + Input + error/hint block, all properly linked via htmlFor/aria-describedby.
 * Use this whenever you have a labeled input in a form.
 */
export function FormField({
  label,
  error,
  hint,
  className,
  ...inputProps
}: FormFieldProps) {
  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <Input
        label={label}
        error={error}
        hint={hint}
        {...inputProps}
      />
    </div>
  );
}
