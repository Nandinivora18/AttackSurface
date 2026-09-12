'use client';
import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion } from 'framer-motion';
import { Shield, Eye, EyeOff, CheckCircle, Mail, Lock, User } from 'lucide-react';
import api from '@/lib/api';
import { useAuthStore } from '@/store';
import { saveTokens } from '@/lib/utils';
import toast from 'react-hot-toast';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

const schema = z
  .object({
    name: z.string().min(2, 'Name must be at least 2 characters'),
    email: z.string().email('Invalid email address'),
    password: z
      .string()
      .min(8, 'At least 8 characters')
      .regex(/[A-Z]/, 'Must contain an uppercase letter')
      .regex(/[0-9]/, 'Must contain a number'),
    confirm: z.string(),
  })
  .refine((d) => d.password === d.confirm, {
    message: 'Passwords do not match',
    path: ['confirm'],
  });

type FormData = z.infer<typeof schema>;

const PASSWORD_RULES = [
  { label: '8+ characters', test: (p: string) => p.length >= 8 },
  { label: 'Uppercase letter', test: (p: string) => /[A-Z]/.test(p) },
  { label: 'Number', test: (p: string) => /[0-9]/.test(p) },
];

export default function SignupPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const router = useRouter();

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  const password = watch('password', '');

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    try {
      const res = await api.post('/api/auth/register', {
        name: data.name,
        email: data.email,
        password: data.password,
      });
      if (res.data?.is_verified) {
        const loginRes = await api.post('/api/auth/login', {
          email: data.email,
          password: data.password,
        });
        const { access_token, refresh_token, user } = loginRes.data;
        saveTokens(access_token, refresh_token);
        useAuthStore.setState({ user, isAuthenticated: true });
        toast.success(`Account created! Welcome, ${user?.name || data.name}!`);
        window.location.href = '/dashboard';
      } else {
        setDone(true);
      }
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  /* ── Email verification sent ── */
  if (done) {
    return (
      <div className="min-h-screen bg-[#070707] flex items-center justify-center px-4 hero-grid">
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.3 }}
          className="glass-card p-12 max-w-md w-full text-center border border-[#2A2A2A] bg-[#111111]"
        >
          <div className="w-16 h-16 rounded-full bg-green-500/15 border border-green-500/25 flex items-center justify-center mx-auto mb-6">
            <CheckCircle className="w-8 h-8 text-[#4FAF72]" aria-hidden />
          </div>
          <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Check your email</h1>
          <p className="text-[#A7A39A] text-sm mb-8 leading-relaxed">
            We&apos;ve sent a verification link to your email address. Click it to activate your account.
          </p>
          <Button variant="primary" size="lg" fullWidth onClick={() => router.push('/login?forceLogin=true')}>
            Go to Sign In
          </Button>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-[100dvh] bg-[#070707] flex items-center justify-center px-4 py-3 sm:py-5 hero-grid relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
        <div className="absolute top-1/4 right-1/4 w-80 h-80 bg-[#5C4A20]/10 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative z-10 page-enter my-auto">
        <Link href="/" className="flex items-center justify-center gap-2.5 mb-3 sm:mb-4" aria-label="SentinelScan home">
          <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center shadow-[0_0_15px_rgba(212,175,55,0.2)]">
            <Shield className="w-5 h-5 text-[#D4AF37]" aria-hidden />
          </div>
          <span className="text-xl font-bold text-[#F5F3ED]">
            Sentinel<span className="text-[#D4AF37]">Scan</span>
          </span>
        </Link>

        <div className="glass-card px-5 py-4 sm:px-6 sm:py-5 border border-[#2A2A2A] bg-[#111111]">
          <div className="text-center mb-3 sm:mb-4">
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F3ED] mb-0.5">Create your account</h1>
            <p className="text-[#A7A39A] text-xs sm:text-sm">Start assessing your attack surface for free</p>
          </div>

          <form
            onSubmit={(e) => { e.preventDefault(); handleSubmit(onSubmit)(e); }}
            method="POST"
            action="#"
            className="space-y-2.5 sm:space-y-3"
            noValidate
          >
            {/* Full name */}
            <Input
              label="Full Name"
              type="text"
              placeholder="Jane Smith"
              autoComplete="name"
              error={errors.name?.message}
              leftIcon={User}
              {...register('name')}
            />

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

            {/* Password with strength rules */}
            <div>
              <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••"
                autoComplete="new-password"
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

              {/* Inline password strength indicators */}
              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                {PASSWORD_RULES.map((r) => {
                  const ok = r.test(password);
                  return (
                    <div key={r.label} className="flex items-center gap-1.5">
                      <CheckCircle
                        className={`w-3 h-3 transition-colors ${ok ? 'text-[#4FAF72]' : 'text-[#706C64]'}`}
                        aria-hidden
                      />
                      <span className={`text-[11px] transition-colors ${ok ? 'text-[#4FAF72]' : 'text-[#706C64]'}`}>
                        {r.label}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Confirm password */}
            <Input
              label="Confirm Password"
              type="password"
              placeholder="••••••••"
              autoComplete="new-password"
              error={errors.confirm?.message}
              leftIcon={Lock}
              {...register('confirm')}
            />

            <Button
              type="submit"
              variant="primary"
              size="md"
              loading={loading}
              fullWidth
              className="mt-1.5 h-10 font-bold"
            >
              {loading ? 'Creating account…' : 'Create Free Account'}
            </Button>
          </form>

          {/* Divider */}
          <div className="relative my-2.5 sm:my-3" aria-hidden>
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-[#2A2A2A]" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-[#111111] px-3 text-[#706C64] font-medium">Or sign up with</span>
            </div>
          </div>

          {/* Google OAuth */}
          <a
            href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/auth/google`}
            className="w-full flex items-center justify-center gap-3 px-4 h-9 sm:h-10 rounded-[10px] border border-[#2A2A2A] hover:bg-[#161616] text-[#F5F3ED] text-sm font-medium transition-all"
          >
            <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24" aria-hidden>
              <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z" />
              <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.15C3.26 21.3 7.31 24 12 24z" />
              <path fill="#FBBC05" d="M5.28 14.24c-.25-.72-.38-1.49-.38-2.24s.13-1.52.38-2.24V6.61H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.39l3.99-3.15z" />
              <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.61l3.99 3.15c.95-2.85 3.6-4.96 6.72-4.96z" />
            </svg>
            Google
          </a>

          <p className="mt-2.5 sm:mt-3 text-center text-xs sm:text-sm text-[#706C64]">
            Already have an account?{' '}
            <Link href="/login?forceLogin=true" className="text-[#D4AF37] hover:text-[#F5F3ED] font-medium transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
