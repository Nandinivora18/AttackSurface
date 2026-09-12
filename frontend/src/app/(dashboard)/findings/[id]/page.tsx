'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Shield, AlertTriangle, CheckCircle, ExternalLink,
  Clock, Globe, Code, FileText, Check, Copy, HelpCircle, Flame,
  ShieldCheck, ShieldAlert, BookOpen, Layers
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import api from '@/lib/api';
import { Severity } from '@/types';
import { formatDate, timeAgo, resolveFindingLocation, formatConfidence } from '@/lib/utils';
import toast from 'react-hot-toast';

interface FindingDetail {
  id: string;
  report_id: string;
  asset_url: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  status: string;
  confidence: string;
  cvss_score: number | null;
  cve_id: string | null;
  cwe_id: string | null;
  endpoint: string | null;
  published_date: string | null;
  recommendation: string | null;
  problem: string | null;
  impact: string | null;
  risk_analysis: string | null;
  technical_details: string | null;
  fix_steps: string[] | null;
  configuration_example: string | null;
  best_practices: string | null;
  official_documentation: string | null;
  references: string[] | null;
  evidence: string | null;
  owasp_mapping: { id: string; title: string; reference: string } | null;
  mitre_mapping: { technique_id: string; technique_name: string; reference: string } | null;
  is_passed_control: boolean;
  first_seen: string;
  last_seen: string | null;
  occurrences: number;
  created_at: string;
}

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  { value: 'accepted_risk', label: 'Accepted Risk', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  { value: 'resolved', label: 'Resolved', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  { value: 'false_positive', label: 'False Positive', color: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
];

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const findingId = params.id as string;

  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchFinding = async () => {
      try {
        const res = await api.get<FindingDetail>(`/api/reports/findings/${findingId}`);
        setFinding(res.data);
      } catch {
        toast.error('Failed to load finding details');
      } finally {
        setLoading(false);
      }
    };
    if (findingId) fetchFinding();
  }, [findingId]);

  const handleStatusChange = async (newStatus: string) => {
    if (!finding) return;
    setUpdatingStatus(true);
    try {
      await api.patch(`/api/reports/findings/${findingId}/status`, { status: newStatus });
      setFinding({ ...finding, status: newStatus });
      toast.success(`Finding status updated to ${newStatus.replace('_', ' ')}`);
    } catch {
      toast.error('Failed to update finding status');
    } finally {
      setUpdatingStatus(false);
    }
  };

  const copyEvidence = () => {
    if (finding?.evidence) {
      navigator.clipboard.writeText(finding.evidence);
      setCopied(true);
      toast.success('Evidence copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto space-y-6 page-enter">
        <div className="h-8 w-48 bg-[#161616] rounded animate-pulse" />
        <div className="h-64 bg-[#111111] rounded-xl border border-[#2A2A2A] animate-pulse" />
        <div className="h-96 bg-[#111111] rounded-xl border border-[#2A2A2A] animate-pulse" />
      </div>
    );
  }

  if (!finding) return null;

  return (
    <div className="max-w-5xl mx-auto space-y-6 page-enter">
      {/* Navigation Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <button onClick={() => router.back()} className="btn-ghost py-2 px-3 text-xs flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <Link
          href={`/reports/${finding.report_id}`}
          className="btn-cyber py-2 px-4 text-xs flex items-center gap-1.5"
        >
          View Full Report <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Hero Card */}
      <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
        <div className="space-y-4">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div className="space-y-2 flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={finding.severity as any} size="md" />
                <span className="text-xs px-2.5 py-1 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] font-bold tracking-wider">
                  Confidence: {formatConfidence(finding.confidence)}
                </span>
                {finding.cve_id && (
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded-full bg-red-500/15 text-[#EF4444] border border-red-500/30">
                    {finding.cve_id}
                  </span>
                )}
                {finding.cwe_id && (
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded-full bg-purple-500/15 text-purple-300 border border-purple-500/30">
                    {finding.cwe_id}
                  </span>
                )}
              </div>
              <h1 className="text-2xl font-bold text-[#F5F3ED] leading-tight">{finding.title}</h1>
              <p className="text-xs text-[#A7A39A] flex items-center gap-2 flex-wrap">
                <span className="flex items-center gap-1 text-[#D4AF37] font-medium">
                  <Globe className="w-3.5 h-3.5" /> {finding.asset_url}
                </span>
                <span>•</span>
                <span>Category: {finding.category}</span>
              </p>
            </div>

            {/* Status Workflow Selector */}
            <div className="flex items-end gap-3 flex-wrap sm:flex-nowrap">
              <div className="space-y-1">
                <label className="block text-[10px] uppercase font-bold text-[#A7A39A]">Workflow Status</label>
                <select
                  value={finding.status}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  disabled={updatingStatus}
                  className="cyber-input text-xs py-2 px-3 bg-[#0D0D0D] font-semibold text-[#F5F3ED] border-[#2A2A2A] focus:border-[#D4AF37]"
                >
                  {STATUS_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-[#2A2A2A]/60">
            <div>
              <p className="text-[10px] text-[#706C64] uppercase font-semibold">First Seen</p>
              <p className="text-xs font-semibold text-[#F5F3ED] mt-0.5">{formatDate(finding.first_seen)}</p>
            </div>
            <div>
              <p className="text-[10px] text-[#706C64] uppercase font-semibold">Last Seen</p>
              <p className="text-xs font-semibold text-[#F5F3ED] mt-0.5">{timeAgo(finding.last_seen || finding.created_at)}</p>
            </div>
            <div>
              <p className="text-[10px] text-[#706C64] uppercase font-semibold">Occurrences</p>
              <p className="text-xs font-semibold text-[#F5F3ED] mt-0.5">{finding.occurrences} scans</p>
            </div>
            <div>
              <p className="text-[10px] text-[#706C64] uppercase font-semibold">CVSS Rating</p>
              <p className="text-xs font-semibold text-[#F5F3ED] mt-0.5">
                {finding.cvss_score != null ? `${finding.cvss_score} / 10.0` : 'N/A'}
              </p>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Left 2 Cols: Beginner-First Sections */}
        <div className="md:col-span-2 space-y-6">

          {/* 1. WHAT'S WRONG? */}
          <GlassCard className="p-6 space-y-3 border border-[#2A2A2A] bg-[#111111]">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center">
                <FileText className="w-4 h-4 text-[#D4AF37]" />
              </div>
              <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#D4AF37]">
                WHAT&apos;S WRONG?
              </h2>
            </div>
            <p className="text-sm text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-4 rounded-xl border border-[#2A2A2A] font-medium">
              {finding.problem || finding.description}
            </p>
          </GlassCard>

          {/* 2. WHERE WE FOUND IT */}
          {(() => {
            const loc = resolveFindingLocation(finding, finding.asset_url);
            return (
              <GlassCard className="p-6 space-y-3 border border-[#2A2A2A] bg-[#111111]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded-lg bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center">
                      <Globe className="w-4 h-4 text-[#D4AF37]" />
                    </div>
                    <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#A7A39A]">
                      WHERE WE FOUND IT
                    </h2>
                  </div>
                  <span className="text-[10px] uppercase font-mono font-bold px-2.5 py-0.5 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20]">
                    {loc.badge}
                  </span>
                </div>

                <div className="p-3.5 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-[10px] text-[#706C64] uppercase font-semibold">{loc.label}</p>
                    <p className="text-xs font-mono font-bold text-[#D4AF37] truncate mt-0.5">
                      {loc.value}
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(loc.value);
                      toast.success('Location copied to clipboard');
                    }}
                    className="btn-ghost py-1.5 px-2.5 text-xs flex items-center gap-1 text-[#A7A39A] hover:text-[#F5F3ED]"
                  >
                    <Copy className="w-3.5 h-3.5" /> Copy
                  </button>
                </div>
              </GlassCard>
            );
          })()}

          {/* 3. WHY IT MATTERS */}
          <GlassCard className="p-6 space-y-3 border border-[#2A2A2A] bg-[#111111]">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-orange-500/15 border border-orange-500/25 flex items-center justify-center">
                <Flame className="w-4 h-4 text-[#F97316]" />
              </div>
              <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#F97316]">
                WHY IT MATTERS
              </h2>
            </div>
            <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20">
              <p className="text-sm text-[#F5F3ED] leading-relaxed">
                {finding.impact || "Without this setting, someone on an unsafe network could potentially interfere with a visitor's connection before it is securely established."}
              </p>
            </div>
          </GlassCard>

          {/* 4. HOW TO FIX IT */}
          <GlassCard className="p-6 space-y-4 border border-[#2A2A2A] bg-[#111111]">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-green-500/15 border border-green-500/25 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 text-[#4FAF72]" />
              </div>
              <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#4FAF72]">
                HOW TO FIX IT
              </h2>
            </div>

            {finding.recommendation && (
              <p className="text-sm text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-3.5 rounded-xl border border-[#2A2A2A]">
                {finding.recommendation}
              </p>
            )}

            {finding.fix_steps && finding.fix_steps.length > 0 && (
              <div className="space-y-2 pt-1">
                <p className="text-xs font-bold uppercase tracking-wider text-[#D4AF37]">
                  Step-by-Step Instructions
                </p>
                <div className="space-y-2">
                  {finding.fix_steps.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-3 p-2.5 rounded-lg bg-[#161616] border border-[#2A2A2A] text-xs text-[#F5F3ED]">
                      <span className="w-5 h-5 rounded-full bg-[#5C4A20]/30 text-[#D4AF37] font-mono font-bold text-[11px] flex items-center justify-center flex-shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {finding.configuration_example && (
              <div className="space-y-2 pt-2">
                <p className="text-xs font-bold uppercase tracking-wider text-[#D4AF37] flex items-center gap-1.5">
                  <Code className="w-3.5 h-3.5" /> Recommended Configuration
                </p>
                <pre className="p-4 rounded-xl bg-[#070707] border border-[#5C4A20]/30 font-mono text-xs text-[#D4AF37] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {finding.configuration_example}
                </pre>
              </div>
            )}
          </GlassCard>

          {/* 5. HOW TO CHECK THE FIX */}
          <GlassCard className="p-6 space-y-3 border-green-500/20 bg-green-500/5">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-green-500/20 border border-green-500/30 flex items-center justify-center">
                  <CheckCircle className="w-4 h-4 text-[#4FAF72]" />
                </div>
                <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#4FAF72]">
                  HOW TO CHECK THE FIX
                </h2>
              </div>
              <span className="text-[11px] font-mono font-bold text-[#4FAF72]">
                DETECT → FIX → RESCAN → VERIFY
              </span>
            </div>
            <p className="text-xs text-[#A7A39A] leading-relaxed">
              After applying the recommended configuration change to your server or DNS panel, run a follow-up SentinelScan scan. This finding will automatically disappear once the required setting is verified active.
            </p>
            <div className="pt-2">
              <Link
                href={`/scan?url=${encodeURIComponent(finding.asset_url)}`}
                className="btn-cyber py-2 px-4 text-xs inline-flex items-center gap-2"
              >
                <Shield className="w-3.5 h-3.5" /> Rescan {finding.asset_url}
              </Link>
            </div>
          </GlassCard>

          {/* 6. ASSESSMENT EVIDENCE */}
          <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-extrabold uppercase tracking-wider text-[#A7A39A] flex items-center gap-2">
                  <Code className="w-4 h-4 text-[#D4AF37]" /> ASSESSMENT EVIDENCE
                </h2>
                <p className="text-[10px] text-[#706C64] mt-0.5">Evidence &amp; Confidence</p>
              </div>
              {finding.evidence && (
                <button
                  onClick={copyEvidence}
                  className="text-xs text-[#A7A39A] hover:text-[#F5F3ED] flex items-center gap-1"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-[#4FAF72]" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              )}
            </div>
            <pre className="p-4 rounded-xl bg-[#070707] border border-[#2A2A2A] font-mono text-xs text-[#D4AF37] overflow-x-auto whitespace-pre-wrap">
              {finding.evidence || 'No technical evidence recorded for this check.'}
            </pre>
          </GlassCard>

        </div>

        {/* Right 1 Col: Standards, Mappings & References (Secondary) */}
        <div className="space-y-6">
          {/* Mappings */}
          <GlassCard className="p-5 space-y-4 border border-[#2A2A2A] bg-[#111111]">
            <h2 className="text-xs font-bold uppercase tracking-wider text-[#F5F3ED]">
              Security Standards &amp; Mappings
            </h2>

            {/* OWASP */}
            {finding.owasp_mapping ? (
              <div className="p-3.5 rounded-xl bg-orange-500/10 border border-orange-500/20 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#F97316]">{finding.owasp_mapping.id}</span>
                  <a
                    href={finding.owasp_mapping.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] text-[#F97316] hover:underline flex items-center gap-0.5"
                  >
                    OWASP Top 10 <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
                <p className="text-xs font-bold text-[#F5F3ED]">{finding.owasp_mapping.title}</p>
                <p className="text-[11px] text-[#A7A39A] leading-relaxed">
                  Mapped to OWASP Top 10 (2025) standard categories.
                </p>
              </div>
            ) : (
              <div className="text-xs text-[#706C64]">No direct OWASP mapping for this check.</div>
            )}

            {/* MITRE */}
            {finding.mitre_mapping && (
              <div className="p-3.5 rounded-xl bg-purple-500/10 border border-purple-500/20 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-[#D4AF37]">{finding.mitre_mapping.technique_id}</span>
                  <a
                    href={finding.mitre_mapping.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] text-[#D4AF37] hover:underline flex items-center gap-0.5"
                  >
                    MITRE ATT&amp;CK <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
                <p className="text-xs font-bold text-[#F5F3ED]">{finding.mitre_mapping.technique_name}</p>
                <p className="text-[11px] text-[#A7A39A] leading-relaxed">
                  Adversary technique classification under MITRE framework.
                </p>
              </div>
            )}

            {/* Best Practices */}
            {finding.best_practices && (
              <div className="pt-2 border-t border-[#2A2A2A]/60 space-y-1">
                <p className="text-[10px] uppercase font-bold text-[#706C64]">Security Best Practice</p>
                <p className="text-xs text-[#A7A39A] leading-relaxed">{finding.best_practices}</p>
              </div>
            )}
          </GlassCard>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <GlassCard className="p-5 space-y-3 border border-[#2A2A2A] bg-[#111111]">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[#F5F3ED] flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-[#D4AF37]" /> Official References
              </h2>
              <div className="space-y-2">
                {finding.references.map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-[#D4AF37] hover:underline flex items-center gap-1 truncate block"
                  >
                    <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    <span className="truncate">{ref}</span>
                  </a>
                ))}
              </div>
            </GlassCard>
          )}
        </div>
      </div>
    </div>
  );
}
