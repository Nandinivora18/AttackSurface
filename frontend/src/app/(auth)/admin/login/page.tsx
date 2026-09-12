'use client';
import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Eye, EyeOff, Lock, ArrowRight, Mail, AlertTriangle, ShieldCheck, KeyRound, Terminal } from 'lucide-react';
import { useAuthStore } from '@/store';
import api from '@/lib/api';
import { saveTokens, clearTokens, isAuthenticated as hasAccessToken } from '@/lib/utils';
import toast from 'react-hot-toast';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

const schema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  remember_me: z.boolean().optional(),
});

type FormData = z.infer<typeof schema>;

function AdminLoginPageInner() {
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [accessDeniedMessage, setAccessDeniedMessage] = useState<string | null>(null);
  const { user, isAuthenticated } = useAuthStore();
  const router = useRouter();
  const searchParams = useSearchParams();

  // If already authenticated AND a live access token exists in localStorage,
  // redirect based on authoritative role.
  // The hasAccessToken() guard prevents stale Zustand persist state
  // (sentinel-auth key) from triggering a redirect when the token has
  // expired naturally without an explicit logout.
  // If forceLogin / force is passed, skip auto-redirect and display credentials form.
  useEffect(() => {
    if (searchParams.get('forceLogin') === 'true' || searchParams.get('force') === 'true') {
      return;
    }
    if (isAuthenticated && user && hasAccessToken()) {
      if (user.role === 'admin') {
        router.replace('/admin');
      } else {
        router.replace('/dashboard');
      }
    }
  }, [isAuthenticated, user, router, searchParams]);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    setAccessDeniedMessage(null);
    try {
      // Authenticate via backend with portal="admin" parameter
      const res = await api.post('/api/auth/login', {
        ...data,
        portal: 'admin',
      });

      const { access_token, refresh_token, user: loggedUser } = res.data;

      // Authoritative role validation from backend database
      if (loggedUser.role !== 'admin') {
        clearTokens();
        useAuthStore.setState({ user: null, isAuthenticated: false });
        setAccessDeniedMessage('Administrator access required. Standard user accounts cannot access the administrative portal.');
        toast.error('Access Denied: Administrator privileges required.');
        return;
      }

      saveTokens(access_token, refresh_token);
      useAuthStore.setState({ user: loggedUser, isAuthenticated: true });
      toast.success(`Administrator verified. Welcome, ${loggedUser.name}!`);
      window.location.href = '/admin';
    } catch (err: any) {
      // Backend rejected login or returned 403
      clearTokens();
      if (!err.response) {
        toast.error('Cannot reach the server. Make sure the backend is running.');
        return;
      }

      if (err.response.status === 403) {
        const detail = err.response.data?.detail || 'Administrator access required.';
        setAccessDeniedMessage(typeof detail === 'string' ? detail : 'Administrator access required.');
        toast.error('Administrator access required.');
        return;
      }

      const message = err.response.data?.detail || err.response.data?.message || 'Invalid administrator credentials.';
      toast.error(typeof message === 'string' ? message : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[100dvh] bg-[#070707] flex items-center justify-center px-4 py-3 sm:py-5 hero-grid relative">
      {/* Ambient security glows - Rich gold and deep amber */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
        <div className="absolute top-1/4 left-1/3 w-96 h-96 bg-[#D4AF37]/8 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 right-1/4 w-80 h-80 bg-[#5C4A20]/15 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative z-10 page-enter my-auto">
        {/* Brand Logo with Admin Badge */}
        <div className="flex flex-col items-center justify-center gap-2 mb-3 sm:mb-4">
          <Link href="/" className="flex items-center gap-2.5 group" aria-label="SentinelScan home">
            <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border-2 border-[#D4AF37] flex items-center justify-center shadow-[0_0_20px_rgba(212,175,55,0.3)]">
              <Shield className="w-5 h-5 text-[#D4AF37]" aria-hidden />
            </div>
            <span className="text-xl sm:text-2xl font-bold text-[#F5F3ED]">
              Sentinel<span className="text-[#D4AF37]">Scan</span>
            </span>
          </Link>
          <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-[#D4AF37]/40 bg-[#D4AF37]/10 text-[#D4AF37] text-[10px] sm:text-[11px] font-bold tracking-widest uppercase shadow-[0_0_10px_rgba(212,175,55,0.15)]">
            <KeyRound className="w-3 h-3 text-[#D4AF37]" />
            Administrator Access
          </div>
        </div>

        {/* Card */}
        <div className="glass-card px-5 py-4 sm:px-6 sm:py-5 border border-[#5C4A20]/40 bg-[#0E0E0E]/95 shadow-[0_12px_40px_rgba(0,0,0,0.8),0_0_20px_rgba(212,175,55,0.08)]">
          <div className="text-center mb-3 sm:mb-4">
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F3ED] mb-0.5 tracking-tight">Admin Command Center</h1>
            <p className="text-[#A7A39A] text-xs leading-relaxed">
              Restricted administrative portal for authorized security operators only
            </p>
          </div>

          {/* Access Denied Warning */}
          <AnimatePresence>
            {accessDeniedMessage && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-4 overflow-hidden"
              >
                <div
                  role="alert"
                  className="p-3.5 rounded-xl border border-red-500/40 bg-red-500/10 flex flex-col items-center text-center gap-2.5 shadow-[0_0_15px_rgba(239,68,68,0.15)]"
                >
                  <AlertTriangle className="w-5 h-5 text-[#EF4444]" aria-hidden />
                  <div>
                    <h2 className="text-[#EF4444] font-semibold text-sm mb-1">Access Denied</h2>
                    <p className="text-[#F5F3ED]/80 text-xs mb-2.5 leading-relaxed">
                      {accessDeniedMessage}
                    </p>
                    <Link
                      href="/login?forceLogin=true"
                      className="inline-flex items-center justify-center px-3.5 py-1.5 rounded-lg bg-[#2A2A2A] hover:bg-[#333333] text-[#F5F3ED] text-xs font-semibold transition-colors"
                    >
                      Go to User Login &rarr;
                    </Link>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Compliance & Audit Banner */}
          <div className="mb-3.5 p-2.5 rounded-lg border border-[#2A2A2A] bg-[#141414]/60 flex items-start gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#D4AF37] flex-shrink-0 mt-0.5" />
            <p className="text-[11px] text-[#A7A39A] leading-normal">
              <strong className="text-[#F5F3ED]">Restricted System:</strong> Sign-ins are validated via server-side role authority and recorded in audit logs.
            </p>
          </div>

          <form
            onSubmit={(e) => { e.preventDefault(); handleSubmit(onSubmit)(e); }}
            method="POST"
            action="#"
            className="space-y-3 sm:space-y-3.5"
            noValidate
          >
            {/* Admin Email */}
            <Input
              label="Admin Email"
              type="email"
              placeholder="admin@sentinelscan.io"
              autoComplete="email"
              error={errors.email?.message}
              leftIcon={Mail}
              {...register('email')}
            />

            {/* Admin Password */}
            <Input
              label="Password"
              type={showPassword ? 'text' : 'password'}
              placeholder="••••••••"
              autoComplete="current-password"
              error={errors.password?.message}
              leftIcon={Lock}
              rightElement={
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="text-[#706C64] hover:text-[#F5F3ED] transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              }
              {...register('password')}
            />

            {/* Remember me */}
            <div className="flex items-center justify-between gap-4 pt-0.5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  {...register('remember_me')}
                  type="checkbox"
                  id="remember-me"
                  className="w-4 h-4 rounded border-[#2A2A2A] bg-[#0D0D0D] accent-[#D4AF37] focus:ring-2 focus:ring-[#D4AF37]/40"
                />
                <span className="text-xs text-[#A7A39A]">Remember admin session</span>
              </label>
              <Link
                href="/forgot-password"
                className="text-xs text-[#D4AF37] hover:text-[#F5F3ED] transition-colors"
              >
                Forgot password?
              </Link>
            </div>

            {/* Submit */}
            <Button
              type="submit"
              variant="primary"
              size="md"
              loading={loading}
              rightIcon={loading ? undefined : ArrowRight}
              leftIcon={loading ? undefined : ShieldCheck}
              fullWidth
              className="font-bold tracking-wide shadow-[0_0_15px_rgba(212,175,55,0.25)] h-10 mt-1"
            >
              {loading ? 'Verifying Authority…' : 'Admin Sign In'}
            </Button>
          </form>

          {/* Navigation link to standard user login */}
          <div className="mt-3 pt-2.5 sm:mt-3.5 sm:pt-3 border-t border-[#2A2A2A] text-center">
            <p className="text-xs text-[#706C64]">
              Not an administrator?{' '}
              <Link href="/login?forceLogin=true" className="text-[#D4AF37] hover:underline font-medium inline-flex items-center gap-1 ml-1">
                User Login &rarr;
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AdminLoginPage() {
  return (
    <Suspense fallback={null}>
      <AdminLoginPageInner />
    </Suspense>
  );
}
