'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Shield } from 'lucide-react';
import Sidebar from '@/components/layout/Sidebar';
import DashboardHeader from '@/components/layout/DashboardHeader';
import { useAuthStore, useUIStore } from '@/store';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, fetchMe } = useAuthStore();
  const { sidebarOpen } = useUIStore();
  const router = useRouter();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMe()
      .catch(() => router.push('/login'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center shadow-[0_0_20px_rgba(212,175,55,0.25)] animate-pulse">
            <Shield className="w-6 h-6 text-[#D4AF37]" />
          </div>
          <div className="w-6 h-6 border-2 border-[#5C4A20] border-t-[#D4AF37] rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    if (typeof window !== 'undefined') {
      router.push('/login');
    }
    return null;
  }

  return (
    <div className="flex min-h-screen bg-cyber-bg text-cyber-primary transition-colors duration-200">
      <Sidebar />
      <motion.main
        animate={{ marginLeft: sidebarOpen ? 240 : 70 }}
        transition={{ duration: 0.3, ease: 'easeInOut' }}
        className="flex-1 min-h-screen overflow-y-auto"
      >
        <div className="max-w-7xl mx-auto px-6 py-8">
          <DashboardHeader />
          {children}
        </div>
      </motion.main>
    </div>
  );
}
