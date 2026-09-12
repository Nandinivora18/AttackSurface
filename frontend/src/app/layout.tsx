import type { Metadata } from 'next';
import './globals.css';
import { Toaster } from 'react-hot-toast';

export const metadata: Metadata = {
  title: 'SentinelScan — Know Every Vulnerability Before Attackers Do',
  description:
    'Professional website security assessment platform. Analyze HTTP headers, SSL/TLS, DNS records, technology stack, and security posture in real-time.',
  keywords: 'security scanner, website security, SSL check, security headers, vulnerability assessment',
  openGraph: {
    title: 'SentinelScan',
    description: 'Know Every Vulnerability Before Attackers Do',
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
