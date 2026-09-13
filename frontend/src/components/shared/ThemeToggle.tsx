'use client';

import { useEffect, useState } from 'react';
import { useTheme } from 'next-themes';
import { Sun, Moon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ThemeToggleProps {
  className?: string;
  isFloating?: boolean;
}

export default function ThemeToggle({ className, isFloating = true }: ThemeToggleProps) {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div
        className={cn(
          'w-9 h-9 rounded-xl border border-cyber-border bg-cyber-surface opacity-0 pointer-events-none',
          isFloating && 'fixed top-3.5 left-3.5 z-50',
          className
        )}
        aria-hidden="true"
      />
    );
  }

  const isDark = resolvedTheme !== 'light';

  return (
    <button
      type="button"
      onClick={() => setTheme(isDark ? 'light' : 'dark')}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      className={cn(
        'group flex items-center justify-center w-9 h-9 rounded-xl',
        'border transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#D4AF37]',
        'bg-cyber-surface border-cyber-border text-cyber-secondary hover:text-cyber-primary shadow-sm',
        'hover:border-cyber-gold/50 cursor-pointer',
        isFloating && 'fixed top-3.5 left-3.5 z-50 backdrop-blur-md',
        className
      )}
    >
      {isDark ? (
        <Sun className="w-4 h-4 text-[#D4AF37] transition-transform duration-200 group-hover:rotate-45" />
      ) : (
        <Moon className="w-4 h-4 text-[#B8860B] transition-transform duration-200 group-hover:-rotate-12" />
      )}
      <span className="sr-only">{isDark ? 'Switch to light mode' : 'Switch to dark mode'}</span>
    </button>
  );
}
