'use client';
import { useState, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion } from 'framer-motion';
import { Shield, Lock, Eye, EyeOff, CheckCircle, ArrowLeft } from 'lucide-react';
import api from '@/lib/api';
import toast from 'react-hot-toast';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

const schema = z.object({
  new_password: z
    .string()
    .min(8, 'At least 8 characters')
    .regex(/[A-Z]/, 'Needs an uppercase letter')
    .regex(/[0-9]/, 'Needs a digit'),
  confirm_password: z.string(),
}).refine((d) => d.new_password === d.confirm_password, {
  message: 'Passwords do not match',
  path: ['confirm_password'],
});

type FormData = z.infer<typeof schema>;

const PASSWORD_RULES = [
  { label: '8+ characters',    test: (p: string) => p.length >= 8 },
  { label: 'Uppercase letter', test: (p: string) => /[A-Z]/.test(p) },
  { label: 'Number',           test: (p: string) => /[0-9]/.test(p) },
];

function ResetPasswordInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [showPassword, setShowPassword] = useState(false);
  const [done, setDone] = useState(false);

  const token = searchParams.get('token') || '';

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const password = watch('new_password', '');

  const onSubmit = async (data: FormData) => {
    if (!token) {
      toast.error('Missing reset token — please use the link from your email');
      return;
    }
    try {
      await api.post('/api/auth/reset-password', { token, new_password: data.new_password });
      setDone(true);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Reset failed — the link may have expired');
    }
  };

  /* ── Invalid token ── */
  if (!token) {
    return (
      <div className="min-h-screen bg-[#070707] flex items-center justify-center px-4 hero-grid">
        <div className="glass-card p-10 max-w-md w-full text-center border border-[#2A2A2A] bg-[#111111]">
          <div className="w-16 h-16 rounded-full bg-red-500/15 border border-red-500/25 flex items-center justify-center mx-auto mb-6">
            <Lock className="w-8 h-8 text-red-400" aria-hidden />
          </div>
          <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Invalid Reset Link</h1>
          <p className="text-[#A7A39A] text-sm mb-8">No token found. Please use the link from your reset email.</p>
          <Link href="/forgot-password">
            <Button variant="primary" size="lg" fullWidth>Request New Reset Link</Button>
          </Link>
        </div>
      </div>
    );
  }

  /* ── Success state ── */
  if (done) {
    return (
      <div className="min-h-screen bg-[#070707] flex items-center justify-center px-4 hero-grid">
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="glass-card p-12 max-w-md w-full text-center border border-[#2A2A2A] bg-[#111111]"
        >
          <div className="w-16 h-16 rounded-full bg-green-500/15 border border-green-500/25 flex items-center justify-center mx-auto mb-6">
            <CheckCircle className="w-8 h-8 text-[#4FAF72]" aria-hidden />
          </div>
          <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Password Reset!</h1>
          <p className="text-[#A7A39A] text-sm mb-8 leading-relaxed">
            Your password has been updated. You can now sign in with your new credentials.
          </p>
          <Link href="/login?forceLogin=true">
            <Button variant="primary" size="lg" fullWidth>Sign In Now</Button>
          </Link>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-[100dvh] bg-[#070707] flex items-center justify-center px-4 py-3 sm:py-5 hero-grid relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
        <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-[#5C4A20]/10 rounded-full blur-3xl" />
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
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F3ED] mb-0.5">Set New Password</h1>
            <p className="text-[#A7A39A] text-xs sm:text-sm">Enter your new password below</p>
          </div>

          <form
            onSubmit={(e) => { e.preventDefault(); handleSubmit(onSubmit)(e); }}
            method="POST"
            action="#"
            className="space-y-3 sm:space-y-3.5"
            noValidate
          >
            {/* New password */}
            <div>
              <Input
                label="New Password"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••"
                autoComplete="new-password"
                leftIcon={Lock}
                error={errors.new_password?.message}
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
                {...register('new_password')}
              />

              {/* Strength indicators */}
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
              label="Confirm New Password"
              type="password"
              placeholder="••••••••"
              autoComplete="new-password"
              leftIcon={Lock}
              error={errors.confirm_password?.message}
              {...register('confirm_password')}
            />

            <Button
              type="submit"
              variant="primary"
              size="md"
              loading={isSubmitting}
              leftIcon={Lock}
              fullWidth
              className="h-10 font-bold mt-1"
            >
              {isSubmitting ? 'Resetting…' : 'Reset Password'}
            </Button>
          </form>

          <p className="mt-3 text-center text-xs sm:text-sm text-[#706C64]">
            Remember your password?{' '}
            <Link href="/login?forceLogin=true" className="text-[#D4AF37] hover:text-[#F5F3ED] font-medium transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordInner />
    </Suspense>
  );
}
