'use client';
import Link from 'next/link';
import { ArrowRight, Terminal } from 'lucide-react';
import { Finding, Severity } from '@/types';

const SEV_CONFIG: Record<Severity, { bg: string; border: string; text: string; label: string }> = {
  critical: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/35',
    text: 'text-red-400',
    label: 'Critical',
  },
  high: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/35',
    text: 'text-orange-400',
    label: 'High',
  },
  medium: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    label: 'Medium',
  },
  low: {
    bg: 'bg-emerald-500/8',
    border: 'border-emerald-500/25',
    text: 'text-emerald-400',
    label: 'Low',
  },
  info: {
    bg: 'bg-slate-500/8',
    border: 'border-slate-500/20',
    text: 'text-slate-400',
    label: 'Info',
  },
};

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface FindingSpotlightProps {
  findings: Finding[];
}

export default function FindingSpotlight({ findings }: FindingSpotlightProps) {
  // Pick the single highest-priority open finding
  const spotlight = findings
    .filter((f) => !f.is_passed_control && (!f.status || f.status === 'open'))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))[0];

  if (!spotlight) return null;

  const sev = spotlight.severity as Severity;
  const cfg = SEV_CONFIG[sev] || SEV_CONFIG.info;

  // Trim long evidence/recommendation text
  const evidenceText = spotlight.evidence?.slice(0, 300) ?? null;
  const recommendationText = spotlight.recommendation?.slice(0, 280) ?? spotlight.fix_steps?.[0]?.slice(0, 280) ?? null;

  return (
    <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
          Finding Spotlight
        </p>
        <Link
          href={`/findings/${spotlight.id}`}
          className="text-[11px] text-[#A1A1A1] hover:text-[#D4AF37] flex items-center gap-1 transition-colors group"
          aria-label={`View full details for: ${spotlight.title}`}
        >
          Full Details
          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </Link>
      </div>

      {/* Severity + title */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center px-2.5 py-1 rounded-[6px] text-[10px] font-black uppercase tracking-wider border ${cfg.bg} ${cfg.border} ${cfg.text}`}
          >
            {cfg.label}
          </span>
          <span className="text-[11px] text-[#6F6F6F]">{spotlight.category}</span>
        </div>
        <h3 className="text-sm font-bold text-[#F5F5F5] leading-snug">
          {spotlight.title}
        </h3>
        {spotlight.description && (
          <p className="text-[11px] text-[#A1A1A1] leading-relaxed line-clamp-2">
            {spotlight.description}
          </p>
        )}
      </div>

      {/* Evidence block */}
      {evidenceText && (
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5">
            <Terminal className="w-3 h-3 text-[#6F6F6F]" aria-hidden="true" />
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Evidence</span>
          </div>
          <div className="rounded-[8px] bg-[#080808] border border-[rgba(255,255,255,0.06)] p-3">
            <p className="font-mono text-[11px] text-[#94A3B8] leading-relaxed whitespace-pre-wrap break-words line-clamp-4">
              {evidenceText}
              {spotlight.evidence && spotlight.evidence.length > 300 && '…'}
            </p>
          </div>
        </div>
      )}

      {/* Recommendation */}
      {recommendationText && (
        <div className="space-y-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Recommendation</span>
          <p className="text-[11px] text-[#A1A1A1] leading-relaxed line-clamp-3">
            {recommendationText}
            {spotlight.recommendation && spotlight.recommendation.length > 280 && '…'}
          </p>
        </div>
      )}

      {/* OWASP / MITRE tags */}
      <div className="flex flex-wrap gap-2 pt-1">
        {spotlight.owasp_mapping && (
          <span className="px-2 py-0.5 rounded-[5px] text-[10px] font-semibold bg-[#D4AF37]/10 border border-[#D4AF37]/25 text-[#D4AF37]">
            OWASP {spotlight.owasp_mapping.id}
          </span>
        )}
        {spotlight.cve_id && (
          <span className="px-2 py-0.5 rounded-[5px] text-[10px] font-semibold bg-red-500/10 border border-red-500/25 text-red-400">
            {spotlight.cve_id}
          </span>
        )}
        {spotlight.cwe_id && (
          <span className="px-2 py-0.5 rounded-[5px] text-[10px] font-semibold bg-slate-500/10 border border-slate-500/20 text-slate-400">
            {spotlight.cwe_id}
          </span>
        )}
        {spotlight.cvss_score != null && (
          <span className="px-2 py-0.5 rounded-[5px] text-[10px] font-semibold bg-orange-500/10 border border-orange-500/20 text-orange-400">
            CVSS {spotlight.cvss_score.toFixed(1)}
          </span>
        )}
      </div>

      {/* CTA */}
      <Link
        href={`/findings/${spotlight.id}`}
        className="flex items-center justify-center gap-2 w-full py-2.5 rounded-[10px] bg-[#141414] hover:bg-[#1C1C1C] border border-[rgba(255,255,255,0.08)] hover:border-[#D4AF37]/30 text-[#A1A1A1] hover:text-[#F5F5F5] text-xs font-semibold transition-all group"
      >
        View Full Finding Details
        <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
      </Link>
    </div>
  );
}
