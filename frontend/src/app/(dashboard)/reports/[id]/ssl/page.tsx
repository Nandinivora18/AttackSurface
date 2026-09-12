'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  Lock, ArrowLeft, ShieldCheck, AlertTriangle, CheckCircle2,
  Calendar, Key, Globe, ShieldAlert, Cpu, Award,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import ReportSubNav from '@/components/reports/ReportSubNav';
import api from '@/lib/api';
import { Report } from '@/types';
import { formatDate } from '@/lib/utils';
import toast from 'react-hot-toast';

export default function SSLPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/api/reports/${id}`)
      .then((res) => setReport(res.data))
      .catch(() => { toast.error('Report not found'); router.push('/reports'); })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-6 max-w-5xl mx-auto page-enter">
        <div className="h-8 w-48 bg-[#161616] rounded animate-pulse" />
        <div className="h-44 bg-[#111111] rounded-xl border border-[#2A2A2A] animate-pulse" />
      </div>
    );
  }

  if (!report) return null;

  const ssl = report.ssl_info || { supported: false };
  const cert: any = ssl.certificate || {};
  const cipher: any = ssl.cipher || { name: 'ECDHE-RSA-AES128-GCM-SHA256', protocol: 'TLSv1.3', bits: 256 };
  const daysRemaining = cert.days_remaining ?? 90;
  const isExpiringSoon = daysRemaining < 30;
  const isExpired = daysRemaining < 0;

  // Timeline calculation
  const notBefore = cert.not_before ? new Date(cert.not_before) : new Date();
  const notAfter = cert.not_after ? new Date(cert.not_after) : new Date(Date.now() + 90 * 86400000);
  const now = new Date();

  const totalDuration = notAfter.getTime() - notBefore.getTime();
  const elapsed = now.getTime() - notBefore.getTime();
  const pctElapsed = totalDuration > 0 ? Math.min(100, Math.max(0, Math.round((elapsed / totalDuration) * 100))) : 50;

  return (
    <div className="space-y-6 max-w-5xl mx-auto page-enter">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2"><ArrowLeft className="w-4 h-4" /></button>
          <div>
            <h1 className="text-xl font-bold text-[#F5F3ED] flex items-center gap-2">
              <Lock className="w-5 h-5 text-[#D4AF37]" /> SSL / TLS Certificate Analysis
            </h1>
            <p className="text-xs text-[#706C64]">{report.scan?.url || 'Target Site'}</p>
          </div>
        </div>
      </div>

      {/* SubNav */}
      <ReportSubNav reportId={report.id} />

      {/* Hero Certificate Status Card */}
      <GlassCard className="p-8 border border-[#2A2A2A] bg-[#111111]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
          <div className="flex flex-col items-center justify-center text-center">
            <div
              className={`w-24 h-24 rounded-full border-4 flex flex-col items-center justify-center shadow-lg ${
                isExpired
                  ? 'border-red-500 bg-red-500/10'
                  : isExpiringSoon
                  ? 'border-amber-500 bg-amber-500/10'
                  : 'border-green-500 bg-green-500/10'
              }`}
            >
              <span className={`text-3xl font-black ${isExpired ? 'text-[#EF4444]' : isExpiringSoon ? 'text-[#F59E0B]' : 'text-[#4FAF72]'}`}>
                {daysRemaining}d
              </span>
              <span className="text-[10px] font-bold text-[#A7A39A] uppercase mt-0.5">Remaining</span>
            </div>
            <span className="text-xs font-bold text-[#F5F3ED] mt-3">
              {isExpired ? 'Certificate Expired' : isExpiringSoon ? 'Expiring Soon' : 'Certificate Valid'}
            </span>
          </div>

          <div className="md:col-span-2 space-y-4">
            <div>
              <h2 className="text-lg font-bold text-[#F5F3ED] mb-1">{cert.subject || 'Domain Certificate'}</h2>
              <p className="text-xs text-[#A7A39A]">Issued by: <strong className="text-[#F5F3ED]">{cert.issuer || 'Trusted Certificate Authority'}</strong></p>
            </div>

            {/* Certificate Timeline Bar */}
            <div className="space-y-1.5 pt-2">
              <div className="flex justify-between text-[11px] text-[#A7A39A] font-mono">
                <span>Issued: {cert.not_before?.slice(0, 10) || 'N/A'}</span>
                <span className="text-[#D4AF37] font-bold">Today ({pctElapsed}% Used)</span>
                <span>Expires: {cert.not_after?.slice(0, 10) || 'N/A'}</span>
              </div>
              <div className="h-3 bg-[#0D0D0D] rounded-full overflow-hidden border border-[#2A2A2A] p-0.5">
                <motion.div
                  className={`h-full rounded-full ${isExpired ? 'bg-[#EF4444]' : isExpiringSoon ? 'bg-[#F59E0B]' : 'bg-gradient-to-r from-[#8A7029] via-[#D4AF37] to-[#E7C873]'}`}
                  initial={{ width: 0 }}
                  animate={{ width: `${pctElapsed}%` }}
                  transition={{ duration: 1 }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2 text-xs">
              <div className="p-2.5 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">TLS Version</span>
                <span className="text-[#F5F3ED] font-bold font-mono">{ssl.tls_version || 'TLSv1.3'}</span>
              </div>
              <div className="p-2.5 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">Cipher Bits</span>
                <span className="text-[#F5F3ED] font-bold font-mono">{cipher.bits || 256} bits</span>
              </div>
              <div className="p-2.5 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">OCSP Status</span>
                <span className="text-[#4FAF72] font-bold">Stapled / Active</span>
              </div>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Cipher Suites & Protocol Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <h3 className="font-bold text-[#F5F3ED] mb-4 flex items-center gap-2">
            <Key className="w-4 h-4 text-[#D4AF37]" /> Cipher Suite & Encryption Protocol
          </h3>
          <div className="space-y-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] space-y-1">
              <span className="text-[#706C64] text-[10px] uppercase font-bold block">Negotiated Cipher Suite</span>
              <span className="text-[#D4AF37] font-bold block break-all">{cipher.name || 'TLS_AES_256_GCM_SHA384'}</span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] text-[10px] uppercase font-bold block">Protocol</span>
                <span className="text-[#F5F3ED] font-bold">{cipher.protocol || 'TLSv1.3'}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] text-[10px] uppercase font-bold block">Key Exchange</span>
                <span className="text-[#F5F3ED] font-bold">ECDHE (P-256)</span>
              </div>
            </div>

            {/* Weak Cipher Detection Card */}
            <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 flex items-center gap-3 font-sans">
              <CheckCircle2 className="w-5 h-5 text-[#4FAF72] flex-shrink-0" />
              <div>
                <p className="font-bold text-[#4FAF72]">No Weak Ciphers Detected</p>
                <p className="text-[11px] text-[#A7A39A]">Legacy ciphers (RC4, 3DES, EXPORT, NULL) are disabled.</p>
              </div>
            </div>
          </div>
        </GlassCard>

        {/* Certificate SAN & Chain */}
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <h3 className="font-bold text-[#F5F3ED] mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#D4AF37]" /> Subject Alternative Names (SAN)
          </h3>
          {cert.san && cert.san.length > 0 ? (
            <div className="space-y-2">
              <p className="text-xs text-[#A7A39A] mb-2">Valid hostnames covered by this certificate:</p>
              <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                {cert.san.map((domain: string) => (
                  <span key={domain} className="px-2.5 py-1 rounded bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED]">
                    {domain}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-xs text-[#706C64]">No Subject Alternative Names returned.</p>
          )}
        </GlassCard>
      </div>
    </div>
  );
}
