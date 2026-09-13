'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Globe, Clock, RefreshCw, FileText } from 'lucide-react';
import { Scan, Report, Severity } from '@/types';
import { timeAgo, getScoreColor, getGradeColor, getDomainFromUrl } from '@/lib/utils';

const SEV_COLORS: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#4FAF72',
  info: '#94A3B8',
};

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface ScoreRingProps {
  score: number;
  grade: string;
  color: string;
  gradeColor: string;
}

function ScoreRing({ score, grade, color, gradeColor }: ScoreRingProps) {
  const [animated, setAnimated] = useState(false);
  const r = 64;
  const circ = 2 * Math.PI * r;
  const offset = animated ? circ * (1 - score / 100) : circ;

  useEffect(() => {
    const t = setTimeout(() => setAnimated(true), 80);
    return () => clearTimeout(t);
  }, [score]);

  return (
    <div
      className="relative flex-shrink-0"
      style={{ width: 168, height: 168 }}
      role="img"
      aria-label={`Security score: ${score} out of 100, grade ${grade}`}
    >
      {/* Subtle glow ring */}
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: `radial-gradient(circle, ${color}18 0%, transparent 70%)`,
          filter: 'blur(8px)',
        }}
        aria-hidden="true"
      />
      <svg
        className="-rotate-90 absolute inset-0"
        width="168"
        height="168"
        viewBox="0 0 168 168"
        aria-hidden="true"
      >
        {/* Track */}
        <circle cx="84" cy="84" r={r} fill="none" stroke="#1C1C1C" strokeWidth="10" />
        {/* Score arc */}
        <circle
          cx="84"
          cy="84"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${circ} ${circ}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-black text-[#F5F5F5] leading-none tabular-nums" aria-hidden="true">
          {score}
        </span>
        <span className="text-[11px] text-[#5A5A5A] font-medium mt-0.5" aria-hidden="true">/ 100</span>
        <span
          className="text-sm font-black uppercase tracking-widest mt-1.5 px-2.5 py-0.5 rounded-md"
          style={{ color: gradeColor, backgroundColor: `${gradeColor}18` }}
          aria-hidden="true"
        >
          Grade {grade}
        </span>
      </div>
    </div>
  );
}

interface LatestAssessmentCardProps {
  scan: Scan;
  report: Report | null;
  loading?: boolean;
}

export default function LatestAssessmentCard({ scan, report, loading }: LatestAssessmentCardProps) {
  const score = scan.overall_score ?? report?.overall_score ?? 0;
  const grade = (scan.grade ?? report?.grade ?? 'F') as string;
  const color = getScoreColor(score);
  const gradeColor = getGradeColor(grade);
  const reportId = scan.report_id ?? report?.id;
  const domain = getDomainFromUrl(scan.url);

  // Build severity breakdown from report findings (preferred) or scan.findings_breakdown
  const breakdown: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  if (report?.findings) {
    for (const f of report.findings) {
      if (!f.is_passed_control && f.severity in breakdown) {
        breakdown[f.severity as Severity]++;
      }
    }
  } else if (scan.findings_breakdown) {
    for (const [k, v] of Object.entries(scan.findings_breakdown)) {
      if (k in breakdown) breakdown[k as Severity] = v;
    }
  }

  const totalFindings = Object.values(breakdown).reduce((a, b) => a + b, 0);

  return (
    <div
      className="relative rounded-[16px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] overflow-hidden"
      aria-labelledby="latest-assessment-title"
    >
      {/* Subtle gold top border accent */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#D4AF37]/40 to-transparent" />

      <div className="p-6 sm:p-8">
        {/* Header row */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37] mb-1">
              Latest Security Assessment
            </p>
            <div className="flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-[#6F6F6F] flex-shrink-0" aria-hidden="true" />
              <h2
                id="latest-assessment-title"
                className="font-mono text-sm font-semibold text-[#F5F5F5] truncate max-w-[220px] sm:max-w-none"
                title={scan.url}
              >
                {scan.url}
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2 text-[10px] text-[#6F6F6F] flex-shrink-0">
            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
              scan.status === 'completed'
                ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
            }`}>
              {scan.status}
            </span>
            <Clock className="w-3 h-3" aria-hidden="true" />
            <span>{timeAgo(scan.completed_at ?? scan.created_at)}</span>
          </div>
        </div>

        {/* Main content grid */}
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-8">
          {/* Score ring */}
          <ScoreRing score={score} grade={grade} color={color} gradeColor={gradeColor} />

          {/* Right side: severity + actions */}
          <div className="flex-1 min-w-0 space-y-5 sm:pt-2">
            {/* Severity chips */}
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F] mb-3">
                {totalFindings > 0 ? `${totalFindings} Open Finding${totalFindings !== 1 ? 's' : ''}` : 'No Actionable Findings'}
              </p>
              <div className="flex flex-wrap gap-2">
                {SEV_ORDER.map((sev) => {
                  const count = breakdown[sev];
                  if (count === 0) return null;
                  return (
                    <div
                      key={sev}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] border text-xs font-bold"
                      style={{
                        borderColor: `${SEV_COLORS[sev]}40`,
                        backgroundColor: `${SEV_COLORS[sev]}12`,
                        color: SEV_COLORS[sev],
                      }}
                      role="img"
                      aria-label={`${count} ${sev} severity finding${count !== 1 ? 's' : ''}`}
                    >
                      <span className="font-black text-sm">{count}</span>
                      <span className="capitalize opacity-80">{sev}</span>
                    </div>
                  );
                })}
                {totalFindings === 0 && (
                  <span className="text-xs text-[#4FAF72] font-semibold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#4FAF72]" />
                    Assessment completed cleanly
                  </span>
                )}
              </div>

              {/* Severity bar */}
              {totalFindings > 0 && (
                <div
                  className="h-1.5 rounded-full overflow-hidden flex bg-[#1A1A1A] mt-4"
                  role="img"
                  aria-label="Finding severity distribution"
                >
                  {SEV_ORDER.map((sev) => {
                    const count = breakdown[sev];
                    if (count === 0) return null;
                    const pct = (count / totalFindings) * 100;
                    return (
                      <div
                        key={sev}
                        style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }}
                        title={`${sev}: ${count} (${pct.toFixed(0)}%)`}
                        className="h-full"
                      />
                    );
                  })}
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div className="flex items-center gap-3 flex-wrap">
              {reportId ? (
                <Link
                  href={`/reports/${reportId}`}
                  id="view-full-report-btn"
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-[10px] bg-[#D4AF37] hover:bg-[#E4C35A] text-[#050505] font-bold text-xs transition-all shadow-[0_2px_12px_rgba(212,175,55,0.25)] hover:shadow-[0_4px_20px_rgba(212,175,55,0.35)] hover:-translate-y-0.5 group"
                >
                  <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                  View Full Report
                  <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                </Link>
              ) : null}
              <Link
                href={`/scan?url=${encodeURIComponent(scan.url)}`}
                id="scan-again-btn"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-[10px] bg-[#141414] hover:bg-[#1C1C1C] border border-[rgba(255,255,255,0.08)] hover:border-[#D4AF37]/30 text-[#A1A1A1] hover:text-[#F5F5F5] font-semibold text-xs transition-all group"
              >
                <RefreshCw className="w-3 h-3 transition-transform group-hover:rotate-180 duration-500" aria-hidden="true" />
                Scan Again
              </Link>
            </div>
          </div>
        </div>

        {/* Category score micro-bars if score_breakdown available */}
        {report?.score_breakdown && Object.keys(report.score_breakdown).length > 0 && (
          <div className="mt-6 pt-5 border-t border-[rgba(255,255,255,0.06)]">
            <p className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F] mb-3">Score Breakdown</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {Object.entries(report.score_breakdown).slice(0, 8).map(([key, cat]) => (
                <div key={key} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-[#6F6F6F] truncate">{cat.label || key}</span>
                    <span className="text-[10px] font-bold text-[#A1A1A1]">{cat.score}/{cat.max}</span>
                  </div>
                  <div className="h-1 rounded-full bg-[#1A1A1A] overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${cat.pct}%`,
                        backgroundColor:
                          cat.color === 'green' ? '#4FAF72' :
                          cat.color === 'yellow' ? '#F59E0B' :
                          cat.color === 'orange' ? '#F97316' : '#EF4444',
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
