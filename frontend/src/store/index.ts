'use client';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, Scan, Report, Notification } from '@/types';
import api from '@/lib/api';
import { saveTokens, clearTokens } from '@/lib/utils';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  fetchMe: () => Promise<void>;
  setUser: (user: User) => void;
}

interface ScanState {
  recentScans: Scan[];
  currentScan: Scan | null;
  currentReport: Report | null;
  isScanning: boolean;
  scanProgress: number;
  scanStage: string;
  scanMessage: string;
  setRecentScans: (scans: Scan[]) => void;
  setCurrentScan: (scan: Scan | null) => void;
  setCurrentReport: (report: Report | null) => void;
  setScanProgress: (progress: number, stage: string, message: string) => void;
  setIsScanning: (v: boolean) => void;
}

export type ThemeMode = 'light' | 'dark' | 'system';

interface UIState {
  sidebarOpen: boolean;
  theme: ThemeMode;
  setSidebarOpen: (v: boolean) => void;
  toggleSidebar: () => void;
  setTheme: (theme: ThemeMode) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,

      login: async (email, password) => {
        set({ isLoading: true });
        try {
          const res = await api.post('/api/auth/login', { email, password });
          const { access_token, refresh_token, user } = res.data;
          saveTokens(access_token, refresh_token);
          set({ user, isAuthenticated: true, isLoading: false });
        } catch {
          set({ isLoading: false });
          throw new Error('Login failed');
        }
      },

      logout: async () => {
        try {
          // The backend reads the refresh_token HttpOnly cookie automatically.
          // No need to read it from localStorage — the cookie is sent by the browser
          // and revoked server-side. The cookie is also cleared by the Set-Cookie response.
          await api.post('/api/auth/logout', {});
        } catch {}
        clearTokens();
        set({ user: null, isAuthenticated: false });
      },

      fetchMe: async () => {
        try {
          const res = await api.get('/api/users/me');
          set({ user: res.data, isAuthenticated: true });
        } catch (err) {
          clearTokens();
          set({ user: null, isAuthenticated: false });
          throw err;
        }
      },

      setUser: (user) => set({ user, isAuthenticated: !!user }),
    }),
    {
      name: 'sentinel-auth',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
    }
  )
);

export const useScanStore = create<ScanState>((set) => ({
  recentScans: [],
  currentScan: null,
  currentReport: null,
  isScanning: false,
  scanProgress: 0,
  scanStage: '',
  scanMessage: '',
  setRecentScans: (scans) => set({ recentScans: scans }),
  setCurrentScan: (scan) => set({ currentScan: scan }),
  setCurrentReport: (report) => set({ currentReport: report }),
  setScanProgress: (progress, stage, message) => set({ scanProgress: progress, scanStage: stage, scanMessage: message }),
  setIsScanning: (v) => set({ isScanning: v }),
}));

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  isLoading: boolean;
  fetchNotifications: () => Promise<void>;
  fetchUnreadCount: () => Promise<void>;
  markAsRead: (id: string) => Promise<void>;
  markAllAsRead: () => Promise<void>;
  deleteNotification: (id: string) => Promise<void>;
}



export const useNotificationStore = create<NotificationState>((set, get) => ({
  notifications: [],
  unreadCount: 0,
  isLoading: false,

  fetchNotifications: async () => {
    set({ isLoading: true });
    try {
      const res = await api.get<Notification[]>('/api/notifications');
      set({ notifications: res.data, isLoading: false });
    } catch {
      set({ isLoading: false });
    }
  },

  fetchUnreadCount: async () => {
    try {
      const res = await api.get<{ unread_count: number }>('/api/notifications/unread-count');
      set({ unreadCount: res.data.unread_count });
    } catch {}
  },

  markAsRead: async (id: string) => {
    try {
      await api.patch(`/api/notifications/${id}/read`);
      set((state) => ({
        notifications: state.notifications.map((n) => (n.id === id ? { ...n, is_read: true } : n)),
        unreadCount: Math.max(0, state.unreadCount - 1),
      }));
    } catch {}
  },

  markAllAsRead: async () => {
    try {
      await api.patch('/api/notifications/read-all');
      set((state) => ({
        notifications: state.notifications.map((n) => ({ ...n, is_read: true })),
        unreadCount: 0,
      }));
    } catch {}
  },

  deleteNotification: async (id: string) => {
    try {
      await api.delete(`/api/notifications/${id}`);
      set((state) => {
        const target = state.notifications.find((n) => n.id === id);
        return {
          notifications: state.notifications.filter((n) => n.id !== id),
          unreadCount: target && !target.is_read ? Math.max(0, state.unreadCount - 1) : state.unreadCount,
        };
      });
    } catch {}
  },
}));

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarOpen: true,
      theme: 'dark',
      setSidebarOpen: (v: boolean) => set({ sidebarOpen: v }),
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
      setTheme: (theme: ThemeMode) => {
        set({ theme: 'dark' });
        if (typeof document !== 'undefined') {
          document.documentElement.setAttribute('data-theme', 'dark');
        }
      },
    }),
    { name: 'sentinel-ui-storage' }
  )
);

