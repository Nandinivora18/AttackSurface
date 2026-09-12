'use client';
import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Shield, CheckCircle, XCircle, Loader } from 'lucide-react';
import api from '@/lib/api';

function VerifyEmailInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');

  useEffect(() => {
    const token = searchParams.get('token');
    if (!token) {
      setStatus('error');
      setMessage('No verification token found in the URL.');
      return;
    }
    api.get(`/api/auth/verify-email/${token}`)
      .then((res) => {
        setStatus('success');
        setMessage(res.data.message || 'Email verified successfully!');
        setTimeout(() => router.push('/login'), 3000);
      })
      .catch((err) => {
        setStatus('error');
        setMessage(err.response?.data?.detail || 'Verification failed. The link may have expired.');
      });
  }, [searchParams]);

  return (
    <div className="min-h-[100dvh] bg-[#070707] flex items-center justify-center px-4 py-3 sm:py-5 hero-grid relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none" aria-hidden>
        <div className="absolute top-1/3 left-1/3 w-80 h-80 bg-[#5C4A20]/10 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative z-10 page-enter my-auto">
        <Link href="/" className="flex items-center justify-center gap-2.5 mb-3 sm:mb-4">
          <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center shadow-[0_0_15px_rgba(212,175,55,0.2)]">
            <Shield className="w-4.5 h-4.5 sm:w-5 sm:h-5 text-[#D4AF37]" />
          </div>
          <span className="text-xl font-bold text-[#F5F3ED]">
            Sentinel<span className="text-[#D4AF37]">Scan</span>
          </span>
        </Link>

        <div className="glass-card px-5 py-6 sm:px-8 sm:py-8 text-center border border-[#2A2A2A] bg-[#111111]">
          {status === 'loading' && (
            <>
              <div className="w-16 h-16 rounded-full bg-[#5C4A20]/20 flex items-center justify-center mx-auto mb-6">
                <Loader className="w-8 h-8 text-[#D4AF37] animate-spin" />
              </div>
              <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Verifying Email…</h1>
              <p className="text-[#A7A39A] text-sm">Please wait while we verify your email address.</p>
            </>
          )}

          {status === 'success' && (
            <>
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: 'spring', stiffness: 200 }}
                className="w-16 h-16 rounded-full bg-green-500/15 flex items-center justify-center mx-auto mb-6"
              >
                <CheckCircle className="w-8 h-8 text-[#4FAF72]" />
              </motion.div>
              <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Email Verified!</h1>
              <p className="text-[#A7A39A] text-sm mb-6">{message}</p>
              <p className="text-xs text-[#706C64] mb-6">Redirecting to login in 3 seconds…</p>
              <Link href="/login?forceLogin=true" className="btn-cyber w-full justify-center py-3">
                <span>Sign In Now</span>
              </Link>
            </>
          )}

          {status === 'error' && (
            <>
              <div className="w-16 h-16 rounded-full bg-red-500/15 flex items-center justify-center mx-auto mb-6">
                <XCircle className="w-8 h-8 text-[#EF4444]" />
              </div>
              <h1 className="text-2xl font-bold text-[#F5F3ED] mb-3">Verification Failed</h1>
              <p className="text-[#A7A39A] text-sm mb-6">{message}</p>
              <div className="flex flex-col gap-3">
                <Link href="/signup" className="btn-cyber w-full justify-center py-3">
                  <span>Create New Account</span>
                </Link>
                <Link href="/login?forceLogin=true" className="btn-ghost w-full justify-center py-2.5">
                  Back to Sign In
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailInner />
    </Suspense>
  );
}
