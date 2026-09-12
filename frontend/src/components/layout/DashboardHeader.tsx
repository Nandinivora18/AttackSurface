'use client';
import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, CheckCheck, Trash2, Shield, ExternalLink, X } from 'lucide-react';
import { useNotificationStore, useAuthStore } from '@/store';
import Link from 'next/link';

export default function DashboardHeader() {
  const [open, setOpen] = useState(false);
  const { user } = useAuthStore();
  const { notifications, unreadCount, fetchNotifications, fetchUnreadCount, markAsRead, markAllAsRead, deleteNotification } = useNotificationStore();
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchUnreadCount();
    const interval = setInterval(() => {
      fetchUnreadCount();
    }, 15000);
    return () => clearInterval(interval);
  }, [fetchUnreadCount]);

  const handleToggle = () => {
    if (!open) {
      fetchNotifications();
    }
    setOpen(!open);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="flex items-center justify-between pb-6 mb-6 border-b border-[rgba(255,255,255,0.06)]">
      <div className="flex-1"></div>

      <div className="flex items-center gap-4">
        {/* Notification Bell */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={handleToggle}
            className="relative p-2.5 rounded-[10px] border border-[rgba(255,255,255,0.08)] bg-[#101010] hover:border-[rgba(212,175,55,0.3)] text-[#A1A1A1] hover:text-[#F5F5F5] transition-all shadow-sm"
            aria-label="Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-[#8F7420] text-[#050505] text-[10px] font-extrabold flex items-center justify-center shadow-[0_0_8px_rgba(212,175,55,0.4)]">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown */}
          <AnimatePresence>
            {open && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.98 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 mt-2 w-80 sm:w-96 rounded-[14px] bg-[#101010] border border-[rgba(255,255,255,0.08)] shadow-2xl z-50 overflow-hidden"
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(255,255,255,0.06)] bg-[#0C0C0C]">
                  <div className="flex items-center gap-2">
                    <Bell className="w-3.5 h-3.5 text-[#D4AF37]" />
                    <span className="text-xs font-bold text-[#F5F5F5] uppercase tracking-wider">Notifications</span>
                    {unreadCount > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-[#8F7420]/20 text-[#D4AF37] border border-[#D4AF37]/30 text-[10px] font-semibold">
                        {unreadCount} new
                      </span>
                    )}
                  </div>
                  {unreadCount > 0 && (
                    <button
                      onClick={() => markAllAsRead()}
                      className="text-[11px] text-[#A1A1A1] hover:text-[#D4AF37] flex items-center gap-1 transition-colors"
                    >
                      <CheckCheck className="w-3 h-3" /> Mark all read
                    </button>
                  )}
                </div>

                <div className="max-h-80 overflow-y-auto divide-y divide-[rgba(255,255,255,0.04)]">
                  {notifications.length === 0 ? (
                    <div className="p-6 text-center text-[#6F6F6F] text-xs">
                      No notifications yet
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <div
                        key={n.id}
                        onClick={() => !n.is_read && markAsRead(n.id)}
                        className={`p-3.5 transition-colors cursor-pointer flex items-start justify-between gap-3 ${
                          !n.is_read ? 'bg-[#D4AF37]/5' : 'hover:bg-[#141414]'
                        }`}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${!n.is_read ? 'bg-[#D4AF37] shadow-[0_0_6px_rgba(212,175,55,0.6)]' : 'bg-transparent'}`} />
                            <p className="text-xs font-semibold text-[#F5F5F5] truncate">{n.title}</p>
                          </div>
                          {n.message && <p className="text-[11px] text-[#A1A1A1] leading-relaxed line-clamp-2">{n.message}</p>}
                          {n.metadata?.report_id && (
                            <Link
                              href={`/reports/${n.metadata.report_id}`}
                              onClick={() => setOpen(false)}
                              className="inline-flex items-center gap-1 text-[11px] text-[#D4AF37] hover:underline mt-1.5 font-medium"
                            >
                              View Report <ExternalLink className="w-3 h-3" />
                            </Link>

                          )}
                          {n.metadata?.finding_id && (
                            <Link
                              href={`/findings/${n.metadata.finding_id}`}
                              onClick={() => setOpen(false)}
                              className="inline-flex items-center gap-1 text-[11px] text-[#D4AF37] hover:underline mt-1.5 font-medium"
                            >
                              View Finding <ExternalLink className="w-3 h-3" />
                            </Link>
                          )}
                        </div>

                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteNotification(n.id);
                          }}
                          aria-label="Delete notification"
                          className="text-[#706C64] hover:text-[#EF4444] p-1 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </header>
  );
}
