import type { Metadata } from 'next';
import './globals.css';
import { Toaster } from 'react-hot-toast';

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
    <html lang="en" className="dark bg-[#070707]" data-theme="dark" style={{ backgroundColor: '#070707', color: '#F5F3ED' }}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased bg-[#070707] text-[#F5F3ED] min-h-screen" style={{ backgroundColor: '#070707', color: '#F5F3ED' }}>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#111111',
              color: '#F5F3ED',
              border: '1px solid #2A2A2A',
              borderRadius: '10px',
              fontSize: '14px',
            },
            success: { iconTheme: { primary: '#4FAF72', secondary: '#111111' } },
            error: { iconTheme: { primary: '#EF4444', secondary: '#111111' } },
          }}
        />
      </body>
    </html>
  );
}
