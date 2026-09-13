'use client';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { Finding, Severity } from '@/types';

const SEV_COLORS: Record<Severity, { bg: string; border: string; text: string; dot: string }> = {
  critical: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    dot: 'bg-red-500',
  },
  high: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    dot: 'bg-orange-500',
  },
  medium: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    dot: 'bg-amber-500',
  },
  low: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/25',
    text: 'text-emerald-400',
    dot: 'bg-emerald-500',
  },
  info: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/25',
    text: 'text-slate-400',
    dot: 'bg-slate-400',
  },
};

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface PriorityFindingsProps {
  findings: Finding[];
  reportId?: string;
}

export default function PriorityFindings({ findings, reportId }: PriorityFindingsProps) {
  // Sort by severity priority, then take top 5 non-passed open findings
  const open = findings
    .filter((f) => !f.is_passed_control && (!f.status || f.status === 'open'))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
    .slice(0, 5);

  if (open.length === 0) {
    return (
      <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6">
        <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37] mb-4">
          What Needs Attention?
        </p>
        <div className="flex flex-col items-center justify-center py-6 text-center gap-2">
          <span className="text-2xl">✓</span>
          <p className="text-xs text-[#4FAF72] font-semibold">No open high/critical findings</p>
          <p className="text-[11px] text-[#6F6F6F]">Latest assessment found no priority issues</p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
          What Needs Attention?
        </p>
        {reportId && (
          <Link
            href={`/reports/${reportId}`}
            className="text-[11px] text-[#A1A1A1] hover:text-[#D4AF37] flex items-center gap-1 transition-colors group"
            aria-label="Review all priority findings"
          >
            Review All
            <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
          </Link>
        )}
      </div>

      {/* Findings list */}
      <div className="space-y-2" role="list" aria-label="Priority security findings">
        {open.map((finding) => {
          const sev = finding.severity as Severity;
          const cfg = SEV_COLORS[sev] || SEV_COLORS.info;
          return (
            <div
              key={finding.id}
              role="listitem"
              className="flex items-center gap-3 p-3 rounded-[10px] bg-[#0A0A0A] border border-[rgba(255,255,255,0.05)] hover:border-[rgba(255,255,255,0.10)] transition-colors group"
            >
              {/* Severity indicator */}
              <div className="flex-shrink-0">
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded-[5px] text-[9px] font-black uppercase tracking-wider border ${cfg.bg} ${cfg.border} ${cfg.text}`}
                >
                  {sev}
                </span>
              </div>

              {/* Title + category */}
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-[#F5F5F5] truncate leading-tight">
                  {finding.title}
                </p>
                <p className="text-[10px] text-[#6F6F6F] mt-0.5 truncate">{finding.category}</p>
              </div>

              {/* View link */}
              <Link
                href={`/findings/${finding.id}`}
                className="flex-shrink-0 text-[10px] text-[#6F6F6F] hover:text-[#D4AF37] flex items-center gap-0.5 transition-colors opacity-0 group-hover:opacity-100"
                aria-label={`View finding: ${finding.title}`}
              >
                View <ArrowRight className="w-2.5 h-2.5" aria-hidden="true" />
              </Link>
            </div>
          );
        })}
      </div>

      {open.length >= 5 && reportId && (
        <Link
          href={`/reports/${reportId}`}
          className="text-center text-[11px] text-[#A1A1A1] hover:text-[#D4AF37] transition-colors py-1 border-t border-[rgba(255,255,255,0.05)] pt-3 flex items-center justify-center gap-1 group"
        >
          View all findings in report
          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </Link>
      )}
    </div>
  );
}
