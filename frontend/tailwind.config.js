/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          // Dynamic theme tokens referencing CSS variables
          bg: 'var(--cyber-bg)',
          bgSecondary: 'var(--cyber-bg-secondary)',
          card: 'var(--cyber-surface)',
          cardElevated: 'var(--cyber-surface-elevated)',
          dark: 'var(--cyber-bg)',
          dark2: 'var(--cyber-bg-secondary)',
          dark3: 'var(--cyber-surface)',
          surface: 'var(--cyber-surface)',
          surfaceElevated: 'var(--cyber-surface-elevated)',
          surfaceHover: 'var(--cyber-surface-hover)',

          // Borders
          border: 'var(--cyber-border)',
          borderSubtle: 'var(--cyber-border-subtle)',
          borderGold: 'var(--cyber-border-gold)',
          borderGoldLight: 'var(--cyber-border-gold)',

          // Metallic Gold Accents
          gold: 'var(--cyber-gold)',
          goldSecondary: 'var(--cyber-gold-secondary)',
          goldMetallic: 'var(--cyber-gold-metallic)',
          goldLight: 'var(--cyber-gold-light)',
          goldWarm: 'var(--cyber-gold-warm)',
          goldDark: 'var(--cyber-gold-dark)',
          goldMuted: 'var(--cyber-gold-muted)',

          // Typography
          textPrimary: 'var(--text-primary)',
          textMain: 'var(--text-primary)',
          primary: 'var(--text-primary)',
          textSecondary: 'var(--text-secondary)',
          secondary: 'var(--text-secondary)',
          textMuted: 'var(--text-muted)',
          muted: 'var(--text-muted)',

          // Aliases for seamless component compatibility
          burgundy: 'var(--cyber-gold-metallic)',
          burgundyLight: 'var(--cyber-gold-light)',
          burgundyDark: 'var(--cyber-gold-dark)',
          champagne: 'var(--cyber-gold)',
          champagneLight: 'var(--cyber-gold-light)',
          blue: 'var(--cyber-gold-metallic)',
          purple: 'var(--cyber-gold)',
          forest: 'var(--cyber-gold-metallic)',
          forestDark: 'var(--cyber-gold-dark)',
          forestLight: 'var(--cyber-gold-light)',
          emerald: 'var(--cyber-gold)',
          navy: 'var(--cyber-bg-secondary)',
        },
        severity: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#4FAF72',
          info: '#94A3B8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(135deg, #070707 0%, #0D0D0D 50%, #111111 100%)',
        'gold-gradient': 'linear-gradient(135deg, #D4AF37 0%, #C6A15B 50%, #8A7029 100%)',
        'gold-gradient-subtle': 'linear-gradient(135deg, rgba(212,175,55,0.12) 0%, rgba(198,161,91,0.04) 100%)',
        'gold-glow': 'radial-gradient(ellipse at center, rgba(212,175,55,0.12) 0%, transparent 70%)',
        'burgundy-glow': 'radial-gradient(ellipse at center, rgba(212,175,55,0.1) 0%, transparent 70%)',
        'champagne-glow': 'radial-gradient(ellipse at center, rgba(212,175,55,0.12) 0%, transparent 70%)',
        'card-glass': 'linear-gradient(135deg, rgba(22,22,22,0.85) 0%, rgba(17,17,17,0.95) 100%)',
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0,0,0,0.8), 0 0 40px rgba(212,175,55,0.06)',
        'cyber-lg': '0 0 40px rgba(0,0,0,0.9), 0 0 60px rgba(212,175,55,0.12)',
        'champagne': '0 0 20px rgba(212,175,55,0.18), 0 0 40px rgba(212,175,55,0.06)',
        'gold-btn': '0 4px 16px rgba(212,175,55,0.25), 0 1px 0 rgba(255,255,255,0.15) inset',
        'card': '0 4px 24px rgba(0,0,0,0.7), 0 1px 0 rgba(255,255,255,0.03) inset',
        'critical': '0 0 20px rgba(239,68,68,0.3)',
        'high': '0 0 20px rgba(249,115,22,0.3)',
      },
      animation: {
        'glow-pulse': 'glow-pulse 3s ease-in-out infinite',
        'float': 'float 6s ease-in-out infinite',
        'scan-line': 'scan-line 2s linear infinite',
        'typing': 'typing 3.5s steps(40,end), blink 0.75s step-end infinite',
        'fade-in-up': 'fade-in-up 0.6s ease-out forwards',
        'shimmer': 'shimmer 2s linear infinite',
        'spin-slow': 'spin 8s linear infinite',
      },
      keyframes: {
        'glow-pulse': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(212,175,55,0.2)' },
          '50%': { boxShadow: '0 0 40px rgba(212,175,55,0.4), 0 0 80px rgba(212,175,55,0.15)' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-12px)' },
        },
        'scan-line': {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
        'fade-in-up': {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'shimmer': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
      borderRadius: {
        'xl2': '1.25rem',
      },
    },
  },
  plugins: [],
};
