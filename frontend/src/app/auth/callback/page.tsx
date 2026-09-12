'use client';
import { useEffect, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { saveTokens } from '@/lib/utils';
import { useAuthStore } from '@/store';
import toast from 'react-hot-toast';
import { Shield } from 'lucide-react';

function AuthCallbackInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    // Check query params first, then hash fragment
    const queryToken = searchParams.get('access_token') || searchParams.get('token');
    const hash = typeof window !== 'undefined' ? window.location.hash.substring(1) : '';
    const hashParams = new URLSearchParams(hash);
    const hashToken = hashParams.get('access_token') || hashParams.get('token');

    const accessToken = queryToken || hashToken;

    if (!accessToken) {
      toast.error('Authentication failed. No access token provided.');
      router.push('/login');
      return;
    }

    saveTokens(accessToken);

    // Safety timeout: never hang more than 4 seconds
    const timeout = setTimeout(() => {
      window.location.href = '/dashboard';
    }, 4000);

    useAuthStore
      .getState()
      .fetchMe()
      .then(() => {
        clearTimeout(timeout);
        toast.success('Successfully signed in with Google');
        const role = useAuthStore.getState().user?.role;
        window.location.href = role === 'admin' ? '/admin' : '/dashboard';
      })
      .catch((err) => {
        clearTimeout(timeout);
        console.error('OAuth profile load error:', err);
        toast.success('Signed in with Google');
        window.location.href = '/dashboard';
      });

    return () => clearTimeout(timeout);
  }, [router, searchParams]);

  return (
    <div className="min-h-screen bg-[#0D090A] flex flex-col items-center justify-center p-4">
      <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#8E3040] to-[#5C1D28] border border-[#D4B978]/30 flex items-center justify-center shadow-cyber mb-4 animate-pulse">
        <Shield className="w-6 h-6 text-[#D4B978]" aria-hidden />
      </div>
      <h1 className="text-xl font-bold text-[#F4EFE8] mb-2">Authenticating with Google…</h1>
      <p className="text-sm text-[#B5A8A8]">Completing sign-in, redirecting to dashboard…</p>
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense fallback={null}>
      <AuthCallbackInner />
    </Suspense>
  );
}
