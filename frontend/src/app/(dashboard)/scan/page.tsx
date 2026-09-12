'use client';
import { useState, useEffect, useRef, Suspense, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Shield, Zap, CheckCircle2, AlertTriangle,
  Clock, ArrowRight, Loader2, Globe, Server, FileText, Lock, Bug, Cpu, Award, RefreshCw
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import api from '@/lib/api';
import { ScanProgressEvent } from '@/types';
import toast from 'react-hot-toast';

const MODES = [
  {
    id: 'passive',
    name: 'Passive Assessment',
    description: 'Safe non-intrusive security headers, DNS, SSL/TLS, technology stack, lifecycle & CVE checks',
    badge: 'Default / Safe',
    icon: Shield,
  },
  {
    id: 'safe_active',
    name: 'Controlled Safe Active',
    description: 'Bounded same-origin crawler (max 20 pages, depth 2), harmless canary differential injection, CORS & SSRF verification',
    badge: 'Active / Consent Req.',
    icon: Zap,
  },
  {
    id: 'authenticated_safe_active',
    name: 'Authenticated Safe Active',
    description: 'Active crawler & differential testing using authorized test session headers. Passwords strictly redacted.',
    badge: 'Auth / Deep Testing',
    icon: Search,
  },
];

function ScanPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialUrl = searchParams.get('url') || '';
  const initialScanId = searchParams.get('id') || '';

  const [url, setUrl] = useState(initialUrl);
  const [profile, setProfile] = useState('passive');
  const [consentAcknowledged, setConsentAcknowledged] = useState(false);
  const [authIdentityLabel, setAuthIdentityLabel] = useState('test_user');
  const [authHeaderName, setAuthHeaderName] = useState('Authorization');
  const [authHeaderValue, setAuthHeaderValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState<string | null>(initialScanId || null);
  const [progress, setProgress] = useState<number>(0);
  const [currentStage, setCurrentStage] = useState<string>('Initializing');
  const [stageDetails, setStageDetails] = useState<string>('Preparing security evaluation modules…');
  const [findingsCount, setFindingsCount] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isNavigatingRef = useRef<boolean>(false);

  const cleanupStreams = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  const handleScanCompleted = useCallback((targetReportId?: string | null, targetScanId?: string) => {
    if (isNavigatingRef.current) return;
    isNavigatingRef.current = true;
    cleanupStreams();
    setProgress(100);
    setCurrentStage('Scan Completed');
    setStageDetails('Assessment finalized and report generated.');
    setLoading(false);
    toast.success('Security scan completed successfully!');

    if (targetReportId) {
      setTimeout(() => {
        router.push(`/reports/${targetReportId}`);
      }, 1000);
    } else if (targetScanId) {
      // Look up report for this scan
      api.get(`/api/reports?scan_id=${targetScanId}`)
        .then((res) => {
          const rep = Array.isArray(res.data) && res.data.length > 0 ? res.data[0] : null;
          if (rep?.id) {
            router.push(`/reports/${rep.id}`);
          } else {
            router.push('/reports');
          }
        })
        .catch(() => router.push('/reports'));
    } else {
      router.push('/reports');
    }
  }, [cleanupStreams, router]);

  const handleScanFailed = useCallback((errorMsg?: string) => {
    cleanupStreams();
    setLoading(false);
    const msg = errorMsg || 'Security assessment failed. Please verify the target and try again.';
    setErrorMessage(msg);
    toast.error(msg);
  }, [cleanupStreams]);

  const startProgressStream = useCallback(async (id: string) => {
    cleanupStreams();
    isNavigatingRef.current = false;
    setErrorMessage(null);

    // 1. Obtain an opaque single-use SSE ticket (prevents JWT in URL)
    let sseTicket: string | null = null;
    try {
      const ticketRes = await api.post(`/api/scans/${id}/sse-ticket`);
      sseTicket = ticketRes.data?.ticket || null;
    } catch (ticketErr) {
      console.warn('Could not acquire SSE ticket, relying on polling fallback:', ticketErr);
    }

    const apiHost = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    if (sseTicket) {
      const sseUrl = `${apiHost}/api/scans/${id}/stream?ticket=${encodeURIComponent(sseTicket)}`;
      const es = new EventSource(sseUrl);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const data: ScanProgressEvent = JSON.parse(event.data);
          if (data.progress != null) {
            setProgress((prev) => Math.max(prev, data.progress));
          }
          if (data.stage) setCurrentStage(data.stage);
          if (data.message) setStageDetails(data.message);
          if (data.findings_count != null) setFindingsCount(data.findings_count);

          if (data.status === 'completed' || data.progress === 100) {
            handleScanCompleted(data.report_id, id);
          } else if (data.status === 'failed' || data.status === 'cancelled') {
            handleScanFailed(data.message || data.error);
          }
        } catch (err) {
          console.error('SSE JSON error', err);
        }
      };

      es.onerror = () => {
        // SSE disconnected or errored; close it and let polling fallback take over seamlessly
        if (eventSourceRef.current) {
          eventSourceRef.current.close();
          eventSourceRef.current = null;
        }
      };
    }

    // 2. Database-backed polling fallback (prevents UI freezing if SSE is interrupted)
    pollIntervalRef.current = setInterval(async () => {
      try {
        const scanRes = await api.get(`/api/scans/${id}`);
        const scanData = scanRes.data;
        if (!scanData) return;

        if (scanData.progress != null) {
          setProgress((prev) => Math.max(prev, scanData.progress));
        }
        if (scanData.current_stage) {
          setCurrentStage(scanData.current_stage);
        }

        if (scanData.status === 'completed' || scanData.progress === 100) {
          handleScanCompleted(scanData.report_id, id);
        } else if (scanData.status === 'failed' || scanData.status === 'cancelled') {
          handleScanFailed(scanData.error_message || 'Scan terminated with an error');
        }
      } catch (pollErr) {
        console.debug('Polling check error:', pollErr);
      }
    }, 1500);
  }, [cleanupStreams, handleScanCompleted, handleScanFailed]);

  // If scan ID is provided in query, attach to progress stream immediately
  useEffect(() => {
    if (initialScanId) {
      setLoading(true);
      startProgressStream(initialScanId);
    }
    return () => {
      cleanupStreams();
    };
  }, [initialScanId, startProgressStream, cleanupStreams]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      toast.error('Please enter a target URL');
      return;
    }

    if (profile !== 'passive' && !consentAcknowledged) {
      toast.error('Please confirm authorization and consent before launching an active assessment.');
      return;
    }

    setErrorMessage(null);
    setLoading(true);
    setProgress(5);
    setCurrentStage('Queuing Scan');
    setStageDetails('Registering scan with assessment worker queue…');

    try {
      let targetUrl = url.trim();
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = `https://${targetUrl}`;
      }

      const payload: Record<string, any> = {
        url: targetUrl,
        scan_mode: profile,
        consent_acknowledged: profile === 'passive' ? true : consentAcknowledged,
      };

      if (profile === 'authenticated_safe_active' && authHeaderValue.trim()) {
        payload.auth_context = {
          identity_label: authIdentityLabel || 'test_user',
          headers: { [authHeaderName || 'Authorization']: authHeaderValue.trim() },
        };
      }

      const res = await api.post('/api/scans', payload);

      const newScanId = res.data.id;
      setScanId(newScanId);
      toast.success('Scan queued — streaming real-time assessment');
      startProgressStream(newScanId);
    } catch (err: any) {
      setLoading(false);
      const detail = err.response?.data?.detail;
      const msg = typeof detail === 'string' ? detail : 'Failed to start scan';
      setErrorMessage(msg);
      toast.error(msg);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 page-enter">
      {/* Header */}
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-[#F5F3ED] flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-[#D4AF37]" /> New Security Assessment
        </h1>
        <p className="text-xs text-[#A7A39A]">
          Safe passive reconnaissance scanning with 7-category risk posture scoring.
        </p>
      </div>

      {/* Main Scan Form */}
      <GlassCard className="p-6 md:p-8 space-y-6 border border-[#2A2A2A] bg-[#111111]">
        <form onSubmit={handleStartScan} className="space-y-6">
          {/* Target URL Input */}
          <div className="space-y-2">
            <label className="block text-xs font-bold uppercase tracking-wider text-[#A7A39A]">
              Target Host / URL
            </label>
            <div className="relative">
              <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#706C64] pointer-events-none" />
              <input
                id="target-url"
                name="url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                disabled={loading}
                className="cyber-input !pl-11 text-sm h-12 bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED] focus:border-[#D4AF37] font-mono [font-variant-ligatures:none] [font-feature-settings:'liga'_0,'calt'_0]"
              />
            </div>
            <p className="text-[11px] text-[#706C64]">
              Passive scan adheres to non-intrusive observation. We never execute active attacks against targets.
            </p>
          </div>

          {/* Scan Profiles */}
          <div className="space-y-3">
            <label className="block text-xs font-bold uppercase tracking-wider text-[#A7A39A]">
              Assessment Mode
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {MODES.map((p) => {
                const Icon = p.icon;
                const isSelected = profile === p.id;
                return (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => !loading && setProfile(p.id)}
                    className={`p-4 rounded-xl border text-left transition-all relative ${
                      isSelected
                        ? 'border-[#5C4A20] bg-[#5C4A20]/15 shadow-[0_0_16px_rgba(212,175,55,0.15)]'
                        : 'border-[#2A2A2A] bg-[#0D0D0D] hover:border-[#5C4A20]/50'
                    } ${loading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
                        isSelected ? 'bg-[#5C4A20]/30 border-[#D4AF37]/50 text-[#D4AF37]' : 'bg-[#161616] border-[#2A2A2A] text-[#706C64]'
                      }`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${
                        isSelected ? 'bg-[#5C4A20]/40 text-[#D4AF37] border-[#D4AF37]/40' : 'bg-[#161616] text-[#706C64] border-[#2A2A2A]'
                      }`}>
                        {p.badge}
                      </span>
                    </div>
                    <p className="text-xs font-bold text-[#F5F3ED] mb-1">{p.name}</p>
                    <p className="text-[11px] text-[#A7A39A] leading-relaxed">{p.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Authorization & Consent Confirmation (for active modes) */}
          {profile !== 'passive' && (
            <div className="p-4 rounded-xl bg-[#141414] border border-[#5C4A20] space-y-3">
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  id="consent-check"
                  checked={consentAcknowledged}
                  onChange={(e) => setConsentAcknowledged(e.target.checked)}
                  className="mt-1 accent-[#D4AF37] w-4 h-4 rounded cursor-pointer"
                />
                <label htmlFor="consent-check" className="text-xs text-[#F5F3ED] cursor-pointer leading-relaxed">
                  <strong className="text-[#D4AF37] block mb-0.5">Authorization &amp; Safety Confirmation:</strong>
                  I confirm that I am authorized to conduct security assessments against this target. SentinelScan uses controlled, non-destructive differential testing with strict same-origin bounds.
                </label>
              </div>

              {profile === 'authenticated_safe_active' && (
                <div className="pt-3 border-t border-[#2A2A2A] space-y-2.5">
                  <p className="text-[11px] text-[#A7A39A]">
                    <strong className="text-[#D4AF37]">Test Identity Credentials:</strong> Only enter credentials or session tokens for test accounts on systems you are explicitly authorized to test. Sensitive credentials will be redacted before report persistence.
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                    <input
                      type="text"
                      placeholder="Identity Label (e.g. test_user)"
                      value={authIdentityLabel}
                      onChange={(e) => setAuthIdentityLabel(e.target.value)}
                      className="cyber-input text-xs h-9 bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED]"
                    />
                    <input
                      type="text"
                      placeholder="Header Name (e.g. Authorization)"
                      value={authHeaderName}
                      onChange={(e) => setAuthHeaderName(e.target.value)}
                      className="cyber-input text-xs h-9 bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED]"
                    />
                    <input
                      type="text"
                      placeholder="Header Value (e.g. Bearer token...)"
                      value={authHeaderValue}
                      onChange={(e) => setAuthHeaderValue(e.target.value)}
                      className="cyber-input text-xs h-9 bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED]"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error Banner if scan failed */}
          {errorMessage && !loading && (
            <div className="p-4 rounded-xl border border-red-500/30 bg-red-950/20 text-red-400 text-xs flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="font-bold">Scan Execution Issue</p>
                <p className="text-red-300/80 leading-relaxed">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading || !url.trim() || (profile !== 'passive' && !consentAcknowledged)}
            className="btn-cyber w-full py-3.5 text-sm font-bold flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Running Security Assessment ({progress}%)…</span>
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                <span>Start Security Scan</span>
              </>
            )}
          </button>
        </form>

        {/* Live Progress Pipeline Bar */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="space-y-4 pt-4 border-t border-[#2A2A2A]"
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-[#F5F3ED] flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 text-[#D4AF37] animate-spin" />
                  {currentStage}
                </span>
                <span className="font-mono text-[#D4AF37] font-bold">{progress}%</span>
              </div>

              <div className="scan-progress-bar h-2 bg-[#1A1A1A] rounded-full overflow-hidden">
                <div
                  className="scan-progress-fill h-full bg-gradient-to-r from-[#8A7029] via-[#D4AF37] to-[#E7C873]"
                  style={{ width: `${progress}%` }}
                />
              </div>

              <p className="text-[11px] text-[#A7A39A] font-mono leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#2A2A2A]">
                &gt; {stageDetails}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </GlassCard>
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={null}>
      <ScanPageInner />
    </Suspense>
  );
}
