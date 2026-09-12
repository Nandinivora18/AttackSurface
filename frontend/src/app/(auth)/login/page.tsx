'use client';
import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Eye, EyeOff, Zap, ArrowRight, Mail, AlertTriangle, Lock, ShieldAlert } from 'lucide-react';
import { useAuthStore } from '@/store';
import api from '@/lib/api';
import { saveTokens, isAuthenticated as hasAccessToken } from '@/lib/utils';
import toast from 'react-hot-toast';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

const schema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  remember_me: z.boolean().optional(),
});

type FormData = z.infer<typeof schema>;

function LoginPageInner() {
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [adminAccountNotice, setAdminAccountNotice] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [resendLoading, setResendLoading] = useState(false);
  const { user, isAuthenticated } = useAuthStore();
  const router = useRouter();
  const searchParams = useSearchParams();

  // If already authenticated AND a live access token exists in localStorage,
  // redirect to the appropriate destination.
  // The hasAccessToken() guard prevents stale Zustand persist state
  // (sentinel-auth key) from triggering a redirect when the token has
  // expired naturally without an explicit logout.
  // If forceLogin / force is passed (e.g. user clicked Sign in from /signup or switched portals),
  // skip auto-redirect and display the credentials form.
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

  // OAuth error codes returned by the backend via ?error=<code>
  const OAUTH_ERRORS: Record<string, string> = {
    oauth_cancelled: 'Google sign-in was cancelled.',
    oauth_not_configured: 'Google sign-in is not available on this server.',
    oauth_invalid_state: 'Security check failed. Please try signing in again.',
    oauth_failed: 'Google sign-in failed. Please try again.',
    oauth_missing_info: 'Could not retrieve your Google account information.',
    oauth_unverified_email: 'Your Google account email address is not verified.',
    oauth_email_exists:
      'An account with that email already exists. Please sign in with your email and password instead.',
  };

  // Show a toast for OAuth errors redirected from the backend
  useEffect(() => {
    const errorCode = searchParams.get('error');
    if (errorCode && OAUTH_ERRORS[errorCode]) {
      toast.error(OAUTH_ERRORS[errorCode], { duration: 6000 });
      // Clean up the URL so the error doesn't persist on refresh
      const url = new URL(window.location.href);
      url.searchParams.delete('error');
      window.history.replaceState({}, '', url.toString());
    }
  }, []);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (resendCooldown > 0) {
      timer = setInterval(() => setResendCooldown((p) => p - 1), 1000);
    }
    return () => clearInterval(timer);
  }, [resendCooldown]);

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    setUnverifiedEmail(null);
    setAdminAccountNotice(false);
    try {
      const res = await api.post('/api/auth/login', data);
      const { access_token, refresh_token, user: loggedUser } = res.data;

      // If backend/database role is admin, do not silently treat as normal user
      if (loggedUser.role === 'admin') {
        setAdminAccountNotice(true);
        toast.error('This is an administrator account. Please use Admin Login.');
        return;
      }

      saveTokens(access_token, refresh_token);
      useAuthStore.setState({ user: loggedUser, isAuthenticated: true });
      toast.success(`Welcome back, ${loggedUser.name}!`);
      window.location.href = '/dashboard';
    } catch (err: any) {
      // Network / server unreachable
      if (!err.response) {
        toast.error('Cannot reach the server. Make sure the backend is running.');
        return;
      }
      // Email verification required
      if (err.response.status === 403 && err.response.data?.code === 'EMAIL_NOT_VERIFIED') {
        setUnverifiedEmail(data.email);
        toast.error('Please verify your email before signing in.');
        return;
      }
      // Bad credentials or other auth error
      const message = err.response.data?.detail || err.response.data?.message || 'Invalid email or password.';
      toast.error(typeof message === 'string' ? message : 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!unverifiedEmail) return;
    setResendLoading(true);
    try {
      await api.post('/api/auth/resend-verification', { email: unverifiedEmail });
      toast.success("Check your inbox — we've sent a new verification link.");
      setResendCooldown(60);
    } catch (err: any) {
      if (err.response?.status === 429) {
        toast.error('Too many resend attempts. Please wait a few minutes.');
      } else {
        toast.error('Failed to resend verification email.');
      }
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070707] flex items-center justify-center px-4 hero-grid relative overflow-hidden">
      {/* Ambient glows */}
      <div className="absolute top-1/3 left-1/3 w-80 h-80 bg-[#D4AF37]/5 rounded-full blur-3xl pointer-events-none" aria-hidden />
      <div className="absolute bottom-1/3 right-1/3 w-80 h-80 bg-[#5C4A20]/10 rounded-full blur-3xl pointer-events-none" aria-hidden />

      <div className="w-full max-w-md relative z-10 page-enter">
        {/* Logo */}
        <Link href="/" className="flex items-center justify-center gap-2.5 mb-8 group" aria-label="SentinelScan home">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center shadow-[0_0_15px_rgba(212,175,55,0.2)]">
            <Shield className="w-5 h-5 text-[#D4AF37]" aria-hidden />
          </div>
          <span className="text-xl font-bold text-[#F5F3ED]">
            Sentinel<span className="text-[#D4AF37]">Scan</span>
          </span>
        </Link>

        <div className="glass-card p-8 border border-[#2A2A2A] bg-[#111111]">
          <div className="text-center mb-8">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#D4AF37]/20 bg-[#D4AF37]/5 text-[#D4AF37] text-xs font-semibold uppercase tracking-wider mb-3">
              <Shield className="w-3.5 h-3.5" /> User Portal
            </div>
            <h1 className="text-2xl font-bold text-[#F5F3ED] mb-2">SentinelScan User Login</h1>
            <p className="text-[#A7A39A] text-sm">Sign in to your security command dashboard</p>
          </div>

          {/* Administrator Account Detected Notice */}
          <AnimatePresence>
            {adminAccountNotice && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-6 overflow-hidden"
              >
                <div
                  role="alert"
                  className="p-4 rounded-xl border border-[#D4AF37]/40 bg-[#D4AF37]/10 flex flex-col items-center text-center gap-3 shadow-[0_0_15px_rgba(212,175,55,0.15)]"
                >
                  <ShieldAlert className="w-6 h-6 text-[#D4AF37]" aria-hidden />
                  <div>
                    <h2 className="text-[#D4AF37] font-semibold text-sm mb-1">Administrator Account Detected</h2>
                    <p className="text-[#F5F3ED]/90 text-xs mb-3 leading-relaxed">
                      This is an administrator account. Please use Admin Login to access the management portal.
                    </p>
                    <Link
                      href="/admin/login?forceLogin=true"
                      className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[#D4AF37] hover:bg-[#F5F3ED] text-[#070707] font-semibold text-xs transition-all shadow-[0_0_12px_rgba(212,175,55,0.3)]"
                    >
                      Go to Admin Login &rarr;
                    </Link>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Unverified email banner */}
          <AnimatePresence>
            {unverifiedEmail && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-6 overflow-hidden"
              >
                <div
                  role="alert"
                  className="p-4 rounded-xl border border-orange-500/30 bg-orange-500/10 flex flex-col items-center text-center gap-3"
                >
                  <AlertTriangle className="w-5 h-5 text-orange-400" aria-hidden />
                  <div>
                    <h2 className="text-orange-400 font-semibold text-sm mb-1">Email verification required</h2>
                    <p className="text-[#F5F3ED]/80 text-xs mb-4">
                      Verify your email before signing in to SentinelScan.
                    </p>
                    <Button
                      variant="ghost"
                      size="sm"
                      loading={resendLoading}
                      disabled={resendCooldown > 0 || resendLoading}
                      leftIcon={Mail}
                      onClick={handleResend}
                      fullWidth
                    >
                      {resendCooldown > 0
                        ? `Resend available in ${resendCooldown}s`
                        : 'Resend Verification Email'}
                    </Button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <form
            onSubmit={(e) => { e.preventDefault(); handleSubmit(onSubmit)(e); }}
            method="POST"
            action="#"
            className="space-y-5"
            noValidate
          >
            {/* Email */}
            <Input
              label="Email"
              type="email"
              placeholder="you@example.com"
              autoComplete="email"
              error={errors.email?.message}
              leftIcon={Mail}
              {...register('email')}
            />

            {/* Password */}
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

            {/* Remember me + Forgot password */}
            <div className="flex items-center justify-between gap-4">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  {...register('remember_me')}
                  type="checkbox"
                  id="remember-me"
                  className="w-4 h-4 rounded border-[#2A2A2A] bg-[#0D0D0D] accent-[#D4AF37] focus:ring-2 focus:ring-[#D4AF37]/40"
                />
                <span className="text-sm text-[#A7A39A]">Remember me</span>
              </label>
              <Link
                href="/forgot-password"
                className="text-sm text-[#D4AF37] hover:text-[#F5F3ED] transition-colors"
              >
                Forgot password?
              </Link>
            </div>

            {/* Submit */}
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={loading}
              rightIcon={loading ? undefined : ArrowRight}
              leftIcon={loading ? undefined : Zap}
              fullWidth
            >
              {loading ? 'Signing in…' : 'Sign In'}
            </Button>
          </form>

          {/* Divider */}
          <div className="relative my-6" aria-hidden>
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-[#2A2A2A]" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-[#111111] px-3 text-[#706C64] font-medium">Or continue with</span>
            </div>
          </div>

          {/* Google OAuth */}
          <a
            href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/auth/google`}
            className="w-full flex items-center justify-center gap-3 px-4 h-10 rounded-[10px] border border-[#2A2A2A] hover:bg-[#161616] text-[#F5F3ED] text-sm font-medium transition-all focus-visible:outline-2 focus-visible:outline-[#D4AF37]/50"
          >
            <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" aria-hidden>
              <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z" />
              <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.15C3.26 21.3 7.31 24 12 24z" />
              <path fill="#FBBC05" d="M5.28 14.24c-.25-.72-.38-1.49-.38-2.24s.13-1.52.38-2.24V6.61H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.39l3.99-3.15z" />
              <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.61l3.99 3.15c.95-2.85 3.6-4.96 6.72-4.96z" />
            </svg>
            Google
          </a>

          <p className="mt-6 text-center text-sm text-[#706C64]">
            Don&apos;t have an account?{' '}
            <Link href="/signup" className="text-[#D4AF37] hover:text-[#F5F3ED] font-medium transition-colors">
              Create one free
            </Link>
          </p>

          <div className="mt-5 pt-4 border-t border-[#2A2A2A] text-center">
            <p className="text-xs text-[#706C64]">
              System Administrator?{' '}
              <Link href="/admin/login?forceLogin=true" className="text-[#D4AF37] hover:underline font-medium inline-flex items-center gap-1 ml-1">
                <Shield className="w-3 h-3 text-[#D4AF37]" /> Admin Login &rarr;
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginPageInner />
    </Suspense>
  );
}
