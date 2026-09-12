'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, LayoutDashboard, Search, FileText, History,
  User, Settings, LogOut, ChevronLeft, Menu,
} from 'lucide-react';
import { useAuthStore, useUIStore } from '@/store';
import { cn } from '@/lib/utils';
import toast from 'react-hot-toast';

const MAIN_NAV = [
  { href: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/scan', icon: Search, label: 'New Scan' },
  { href: '/reports', icon: FileText, label: 'Reports' },
  { href: '/history', icon: History, label: 'Scan History' },
];

const ADMIN_NAV = [
  { href: '/admin', icon: Shield, label: 'Admin Center' },
];

const BOTTOM_NAV = [
  { href: '/profile', icon: User, label: 'Profile' },
  { href: '/settings', icon: Settings, label: 'Settings' },
];

interface SidebarItemProps {
  href: string;
  icon: React.ElementType;
  label: string;
  collapsed: boolean;
  badge?: number;
}

function SidebarItem({ href, icon: Icon, label, collapsed, badge }: SidebarItemProps) {
  const pathname = usePathname();
  const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(href + '/'));
  return (
    <Link
      href={href}
      className={cn(
        'sidebar-item group relative text-xs font-medium py-2.5 px-3 rounded-[10px] transition-all duration-150 flex items-center gap-3',
        active
          ? 'bg-[#161616] text-[#D4AF37] font-semibold border-l-2 border-[#D4AF37] rounded-l-none'
          : 'text-[#A1A1A1] hover:text-[#F5F5F5] hover:bg-[#141414]',
        collapsed && 'justify-center px-2 rounded-[10px] border-l-0'
      )}
      title={collapsed ? label : undefined}
    >
      <Icon
        className={cn(
          'w-4 h-4 flex-shrink-0 transition-colors',
          active ? 'text-[#D4AF37]' : 'text-[#6F6F6F] group-hover:text-[#F5F5F5]'
        )}
      />
      {!collapsed && <span className="flex-1 truncate">{label}</span>}
      {badge && badge > 0 && (
        <span className="w-4 h-4 rounded-full bg-[#8F7420]/30 text-[#D4AF37] border border-[#D4AF37]/30 text-[10px] font-bold flex items-center justify-center">
          {badge > 9 ? '9+' : badge}
        </span>
      )}
    </Link>
  );
}

export default function Sidebar() {
  const { user, logout } = useAuthStore();
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const router = useRouter();

  const handleLogout = async () => {
    await logout();
    toast.success('Signed out successfully');
    router.push('/login');
  };

  return (
    <motion.aside
      animate={{ width: sidebarOpen ? 245 : 72 }}
      transition={{ duration: 0.25, ease: 'easeInOut' }}
      className="fixed left-0 top-0 bottom-0 z-40 flex flex-col border-r border-[rgba(255,255,255,0.07)] bg-[#080808] overflow-hidden shadow-2xl"
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-[rgba(255,255,255,0.07)] flex-shrink-0">
        <div className="w-8 h-8 rounded-lg bg-[#141414] border border-[rgba(212,175,55,0.3)] flex items-center justify-center shadow-[0_0_12px_rgba(212,175,55,0.15)] flex-shrink-0">
          <Shield className="w-4 h-4 text-[#D4AF37]" />
        </div>
        <AnimatePresence>
          {sidebarOpen && (
            <motion.span
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -6 }}
              className="font-bold text-[#F5F5F5] whitespace-nowrap tracking-wider text-xs uppercase"
            >
              Sentinel<span className="text-[#D4AF37]">Scan</span>
            </motion.span>
          )}
        </AnimatePresence>
        <button
          onClick={toggleSidebar}
          className={cn(
            'ml-auto p-1.5 rounded-lg text-[#6F6F6F] hover:text-[#F5F5F5] hover:bg-[#141414] transition-all flex-shrink-0',
            !sidebarOpen && 'ml-0 absolute right-3.5 top-5'
          )}
          aria-label="Toggle sidebar"
        >
          {sidebarOpen ? <ChevronLeft className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
        </button>
      </div>

      {/* Main Nav */}
      <nav className="flex-1 py-4 px-2 space-y-4 overflow-y-auto">
        {/* MAIN */}
        <div className="space-y-1">
          {sidebarOpen && <p className="px-3 text-[10px] font-bold text-[#6F6F6F] uppercase tracking-wider mb-2">Workspace</p>}
          {MAIN_NAV.map((item) => (
            <SidebarItem key={item.href} {...item} collapsed={!sidebarOpen} />
          ))}
        </div>

        {/* ADMIN */}
        {user?.role === 'admin' && (
          <div className="space-y-1 pt-3 border-t border-[rgba(255,255,255,0.06)]">
            {sidebarOpen && <p className="px-3 text-[10px] font-bold text-[#D4AF37] uppercase tracking-wider mb-2">Admin</p>}
            {ADMIN_NAV.map((item) => (
              <SidebarItem key={item.href} {...item} collapsed={!sidebarOpen} />
            ))}
          </div>
        )}
      </nav>

      {/* Bottom */}
      <div className="border-t border-[rgba(255,255,255,0.07)] px-2 py-3 space-y-1 flex-shrink-0">
        {BOTTOM_NAV.map((item) => (
          <SidebarItem key={item.href} {...item} collapsed={!sidebarOpen} />
        ))}
        <button
          onClick={handleLogout}
          aria-label="Sign out"
          className={cn(
            'w-full text-xs font-medium py-2.5 px-3 rounded-[10px] text-[#EF4444] hover:text-red-300 hover:bg-red-500/10 flex items-center gap-3 transition-all',
            !sidebarOpen && 'justify-center px-2'
          )}
          title={!sidebarOpen ? 'Sign Out' : undefined}
        >
          <LogOut className="w-4 h-4 flex-shrink-0" />
          {sidebarOpen && <span>Sign Out</span>}
        </button>
      </div>

      {/* User Info */}
      {user && (
        <div className={cn(
          'border-t border-[rgba(255,255,255,0.07)] px-3 py-3 flex items-center gap-3 flex-shrink-0 bg-[#0A0A0A]',
          !sidebarOpen && 'justify-center px-2'
        )}>
          <div className="w-8 h-8 rounded-full bg-[#161616] border border-[rgba(212,175,55,0.35)] flex items-center justify-center flex-shrink-0 text-[#D4AF37] text-xs font-bold shadow-[0_0_8px_rgba(212,175,55,0.15)]">
            {user.name[0]?.toUpperCase()}
          </div>
          <AnimatePresence>
            {sidebarOpen && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="min-w-0"
              >
                <p className="text-xs font-semibold text-[#F5F5F5] truncate">{user.name}</p>
                <p className="text-[11px] text-[#6F6F6F] truncate">{user.email}</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </motion.aside>
  );
}
