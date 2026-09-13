import type { Metadata } from 'next';
import './globals.css';
import { Toaster } from 'react-hot-toast';
import { ThemeProvider } from '@/components/shared/ThemeProvider';
import ThemeToggle from '@/components/shared/ThemeToggle';

export const metadata: Metadata = {
  title: 'SentinelScan — Passive Web Security & Attack Surface Assessment',
  description:
    'Passive web security and attack surface assessment platform. Non-destructive inspection of HTTP headers, SSL/TLS, DNS health, tech fingerprinting, and OWASP Top 10:2025 mapping.',
  keywords: 'security scanner, attack surface, passive scanner, SSL check, security headers, OWASP 2025, vulnerability assessment',
  openGraph: {
    title: 'SentinelScan — Know Your Attack Surface Before Attackers Do',
    description: 'Passive web security and attack surface assessment platform.',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased min-h-screen bg-cyber-bg text-cyber-primary transition-colors duration-200">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          storageKey="sentinel-theme"
        >
          <ThemeToggle />
          {children}
          <Toaster
            position="top-right"
            toastOptions={{
              className: 'border border-cyber-border bg-cyber-surface text-cyber-primary shadow-lg',
              style: {
                borderRadius: '10px',
                fontSize: '14px',
              },
              success: { iconTheme: { primary: '#4FAF72', secondary: 'var(--cyber-surface)' } },
              error: { iconTheme: { primary: '#EF4444', secondary: 'var(--cyber-surface)' } },
            }}
          />
        </ThemeProvider>
      </body>
    </html>
  );
}
