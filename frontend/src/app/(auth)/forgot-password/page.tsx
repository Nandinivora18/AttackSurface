'use client';
import { useState } from 'react';
import Link from 'next/link';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { motion } from 'framer-motion';
import { Shield, Mail, ArrowLeft, CheckCircle } from 'lucide-react';
import api from '@/lib/api';
import toast from 'react-hot-toast';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

const schema = z.object({ email: z.string().email('Invalid email address') });
type FormData = z.infer<typeof schema>;

export default function ForgotPasswordPage() {
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
    resolver: zodResolver(schema),
  });

  const onSubmit = async (data: FormData) => {
    setLoading(true);
    try {
      await api.post('/api/auth/forgot-password', data);
      setSent(true);
    } catch {
      toast.error('Something went wrong. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[100dvh] bg-[#070707] flex items-center justify-center px-4 py-3 sm:py-5 hero-grid relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
        <div className="absolute top-1/3 left-1/3 w-80 h-80 bg-[#5C4A20]/10 rounded-full blur-3xl" />
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
          {sent ? (
            <div className="text-center">
              <div className="w-12 h-12 rounded-full bg-green-500/15 border border-green-500/25 flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-6 h-6 text-[#4FAF72]" aria-hidden />
              </div>
              <h1 className="text-xl sm:text-2xl font-bold text-[#F5F3ED] mb-2">Reset Link Sent</h1>
              <p className="text-[#A7A39A] text-xs sm:text-sm mb-6 leading-relaxed">
                If an account exists with that email, you&apos;ll receive a password reset link shortly.
              </p>
              <Link href="/login?forceLogin=true">
                <Button variant="ghost" size="md" leftIcon={ArrowLeft} fullWidth>
                  Back to Sign In
                </Button>
              </Link>
            </div>
          ) : (
            <>
              <div className="text-center mb-4 sm:mb-5">
                <div className="w-10 h-10 rounded-xl bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center mx-auto mb-3">
                  <Mail className="w-5 h-5 text-[#D4AF37]" aria-hidden />
                </div>
                <h1 className="text-xl sm:text-2xl font-bold text-[#F5F3ED] mb-1">Forgot Password?</h1>
                <p className="text-[#A7A39A] text-xs sm:text-sm">Enter your email and we&apos;ll send a reset link.</p>
              </div>

              <form
                onSubmit={(e) => { e.preventDefault(); handleSubmit(onSubmit)(e); }}
                method="POST"
                action="#"
                className="space-y-3.5 sm:space-y-4"
                noValidate
              >
                <Input
                  label="Email Address"
                  type="email"
                  placeholder="you@example.com"
                  autoComplete="email"
                  leftIcon={Mail}
                  error={errors.email?.message}
                  {...register('email')}
                />

                <Button
                  type="submit"
                  variant="primary"
                  size="md"
                  loading={loading}
                  fullWidth
                  className="h-10 font-bold mt-1"
                >
                  {loading ? 'Sending…' : 'Send Reset Link'}
                </Button>
              </form>

              <div className="mt-4 text-center">
                <Link
                  href="/login?forceLogin=true"
                  className="text-xs sm:text-sm text-[#706C64] hover:text-[#F5F3ED] inline-flex items-center gap-1 transition-colors"
                >
                  <ArrowLeft className="w-3 h-3" aria-hidden /> Back to Sign In
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
