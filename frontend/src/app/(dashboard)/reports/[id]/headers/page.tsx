'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  ShieldCheck, ArrowLeft, CheckCircle2, AlertTriangle, XCircle,
  ExternalLink, Download, FileText, Info, HelpCircle,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import ReportSubNav from '@/components/reports/ReportSubNav';
import api from '@/lib/api';
import { Report } from '@/types';
import { formatDate, getGradeColor, getScoreColor } from '@/lib/utils';
import toast from 'react-hot-toast';

const STANDARD_HEADERS_SPEC = [
  { name: 'Strict-Transport-Security (HSTS)', key: 'strict-transport-security', desc: 'Enforces HTTPS encryption for all browser requests, preventing SSL stripping attacks.', expected: 'max-age=31536000; includeSubDomains; preload', severity: 'high' },
  { name: 'Content-Security-Policy (CSP)', key: 'content-security-policy', desc: 'Restricts script and resource execution to prevent XSS and data injection.', expected: "default-src 'self'; script-src 'self' https:;", severity: 'high' },
  { name: 'X-Frame-Options', key: 'x-frame-options', desc: 'Prevents iframe framing to defend against clickjacking attacks.', expected: 'DENY or SAMEORIGIN', severity: 'medium' },
  { name: 'X-Content-Type-Options', key: 'x-content-type-options', desc: 'Disables browser MIME-sniffing to prevent drive-by downloads.', expected: 'nosniff', severity: 'low' },
  { name: 'Referrer-Policy', key: 'referrer-policy', desc: 'Controls referrer data sent in outgoing request headers.', expected: 'strict-origin-when-cross-origin', severity: 'low' },
  { name: 'Permissions-Policy', key: 'permissions-policy', desc: 'Controls access to camera, microphone, geolocation, and browser features.', expected: 'camera=(), microphone=(), geolocation=()', severity: 'low' },
  { name: 'Cross-Origin-Opener-Policy (COOP)', key: 'cross-origin-opener-policy', desc: 'Isolates browsing context to protect against Spectre side-channel leaks.', expected: 'same-origin', severity: 'info' },
  { name: 'Cross-Origin-Embedder-Policy (COEP)', key: 'cross-origin-embedder-policy', desc: 'Prevents loading cross-origin resources that do not explicitly grant permission.', expected: 'require-corp', severity: 'info' },
  { name: 'Cross-Origin-Resource-Policy (CORP)', key: 'cross-origin-resource-policy', desc: 'Blocks cross-origin reads of response body resources.', expected: 'same-origin', severity: 'info' },
];

export default function SecurityHeadersPage() {
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

  const rawHeaders = report.raw_headers || {};
  let passCount = 0;

  const auditItems = STANDARD_HEADERS_SPEC.map((spec) => {
    const val = rawHeaders[spec.key];
    const isPass = !!val;
    if (isPass) passCount++;

    return {
      ...spec,
      currentValue: val || 'Missing / Not Configured',
      status: isPass ? 'PASS' : spec.severity === 'high' ? 'FAIL' : 'WARN',
      risk: isPass ? 'Low / Secure' : `${spec.severity.toUpperCase()} Risk`,
    };
  });

  const headerScore = Math.round((passCount / STANDARD_HEADERS_SPEC.length) * 100);
  const headerGrade = headerScore >= 90 ? 'A+' : headerScore >= 75 ? 'A' : headerScore >= 60 ? 'B' : headerScore >= 45 ? 'C' : headerScore >= 30 ? 'D' : 'F';
  const gradeColor = getGradeColor(headerGrade);

  return (
    <div className="space-y-6 max-w-5xl mx-auto page-enter">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2"><ArrowLeft className="w-4 h-4" /></button>
          <div>
            <h1 className="text-xl font-bold text-[#F5F3ED] flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-[#D4AF37]" /> Security Headers Audit
            </h1>
            <p className="text-xs text-[#706C64]">{report.scan?.url || 'Target Site'}</p>
          </div>
        </div>
      </div>

      {/* SubNav */}
      <ReportSubNav reportId={report.id} />

      {/* Hero Grade Banner */}
      <GlassCard className="p-8 border border-[#2A2A2A] bg-[#111111]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
          <div className="flex flex-col items-center justify-center text-center">
            <div
              className="w-28 h-28 rounded-full border-4 flex flex-col items-center justify-center shadow-lg"
              style={{ borderColor: gradeColor, background: `${gradeColor}10` }}
            >
              <span className="text-4xl font-black leading-none" style={{ color: gradeColor }}>
                {headerGrade}
              </span>
              <span className="text-xs font-bold text-[#A7A39A] mt-1">Header Rating</span>
            </div>
            <span className="text-xs font-mono font-bold mt-3 text-[#F5F3ED]">
              Overall Score: {headerScore} / 100
            </span>
          </div>

          <div className="md:col-span-2 space-y-3">
            <h2 className="text-lg font-bold text-[#F5F3ED]">HTTP Security Headers Evaluation</h2>
            <p className="text-xs text-[#A7A39A] leading-relaxed">
              Automated audit of modern HTTP response headers modeled after SecurityHeaders.com standards. Proper HTTP headers protect users against Cross-Site Scripting (XSS), Clickjacking, MIME-sniffing, and MITM attacks.
            </p>

            <div className="grid grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-center">
                <span className="text-xl font-black text-[#4FAF72] block">{passCount}</span>
                <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Headers Present</span>
              </div>
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
                <span className="text-xl font-black text-[#EF4444] block">{STANDARD_HEADERS_SPEC.length - passCount}</span>
                <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Missing Headers</span>
              </div>
              <div className="p-3 rounded-lg bg-[#5C4A20]/20 border border-[#5C4A20] text-center">
                <span className="text-xl font-black text-[#D4AF37] block">{STANDARD_HEADERS_SPEC.length}</span>
                <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Total Audited</span>
              </div>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Header Audit Table */}
      <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
        <h3 className="font-bold text-[#F5F3ED] mb-4">Detailed Security Header Breakdown</h3>
        <div className="space-y-4">
          {auditItems.map((item, idx) => {
            const isPass = item.status === 'PASS';
            const isFail = item.status === 'FAIL';

            return (
              <motion.div
                key={item.key}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.04 }}
                className={`p-4 rounded-xl border transition-all ${
                  isPass
                    ? 'bg-green-500/5 border-green-500/20'
                    : isFail
                    ? 'bg-red-500/5 border-red-500/20'
                    : 'bg-amber-500/5 border-amber-500/20'
                }`}
              >
                <div className="flex items-start justify-between gap-4 flex-wrap mb-2">
                  <div className="flex items-center gap-3">
                    {isPass ? (
                      <CheckCircle2 className="w-5 h-5 text-[#4FAF72] flex-shrink-0" />
                    ) : isFail ? (
                      <XCircle className="w-5 h-5 text-[#EF4444] flex-shrink-0" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-[#F59E0B] flex-shrink-0" />
                    )}
                    <div>
                      <h4 className="font-bold text-[#F5F3ED] text-sm">{item.name}</h4>
                      <p className="text-xs text-[#A7A39A] mt-0.5">{item.desc}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-black font-mono ${
                        isPass
                          ? 'bg-green-500/20 text-[#4FAF72] border border-green-500/30'
                          : isFail
                          ? 'bg-red-500/20 text-[#EF4444] border border-red-500/30'
                          : 'bg-amber-500/20 text-[#F59E0B] border border-amber-500/30'
                      }`}
                    >
                      {item.status}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 pt-3 border-t border-[#2A2A2A]/40 text-xs font-mono">
                  <div>
                    <span className="text-[#706C64] block mb-1 font-semibold uppercase text-[10px]">Received Value:</span>
                    <code className={`p-2 rounded block break-all ${isPass ? 'bg-black/60 text-[#4FAF72]' : 'bg-black/60 text-[#EF4444]'}`}>
                      {item.currentValue}
                    </code>
                  </div>
                  <div>
                    <span className="text-[#706C64] block mb-1 font-semibold uppercase text-[10px]">Expected Recommended Value:</span>
                    <code className="p-2 rounded block break-all bg-black/60 text-[#D4AF37]">
                      {item.expected}
                    </code>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </GlassCard>
    </div>
  );
}
