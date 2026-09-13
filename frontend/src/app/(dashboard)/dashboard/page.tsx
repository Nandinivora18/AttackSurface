'use client';
import { useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield, Zap, AlertTriangle, Activity, Layers,
  ArrowRight, Clock, RefreshCw, TriangleAlert,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import { PageHeader } from '@/components/ui/PageHeader';
import SecurityStatusBanner from '@/components/dashboard/SecurityStatusBanner';
import LatestAssessmentCard from '@/components/dashboard/LatestAssessmentCard';
import PriorityFindings from '@/components/dashboard/PriorityFindings';
import FindingSpotlight from '@/components/dashboard/FindingSpotlight';
import AssessmentCoverage from '@/components/dashboard/AssessmentCoverage';
import ActiveScanPanel from '@/components/dashboard/ActiveScanPanel';
import api from '@/lib/api';
import { DashboardStats, Scan, Report, Severity } from '@/types';
import { timeAgo, getScoreColor, getGradeColor } from '@/lib/utils';
import toast from 'react-hot-toast';

// ─── Severity colors (semantic — never gold) ──────────────────────────────
const SEV_COLORS: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#4FAF72',
  info: '#94A3B8',
};
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ─── Loading skeleton ─────────────────────────────────────────────────────
function DashboardSkeleton() {
  return (
    <div className="space-y-6 page-enter" aria-busy="true" aria-label="Loading dashboard">
      {/* Status banner skeleton */}
      <div className="h-10 rounded-[12px] skeleton" />
      {/* Hero card skeleton */}
      <div className="h-72 rounded-[16px] skeleton" />
      {/* Stat row skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => <div key={i} className="h-24 rounded-[14px] skeleton" />)}
      </div>
      {/* Two-col skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="h-64 rounded-[14px] skeleton" />
        <div className="h-64 rounded-[14px] skeleton" />
      </div>
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center space-y-6">
      <div className="w-16 h-16 rounded-2xl bg-[#101010] border border-[rgba(212,175,55,0.2)] flex items-center justify-center shadow-[0_0_24px_rgba(212,175,55,0.08)]">
        <Shield className="w-8 h-8 text-[#D4AF37]" aria-hidden="true" />
      </div>
      <div className="space-y-2 max-w-sm">
        <h2 className="text-lg font-bold text-[#F5F5F5]">No Assessments Yet</h2>
        <p className="text-sm text-[#A1A1A1] leading-relaxed">
          Start your first security assessment to see your security posture, findings,
          and recommendations here.
        </p>
      </div>
      <Link
        href="/scan"
        id="start-first-scan-btn"
        className="inline-flex items-center gap-2 px-6 py-3 rounded-[10px] bg-[#D4AF37] hover:bg-[#E4C35A] text-[#050505] font-bold text-sm transition-all shadow-[0_2px_16px_rgba(212,175,55,0.25)] hover:shadow-[0_4px_24px_rgba(212,175,55,0.35)] hover:-translate-y-0.5"
      >
        <Zap className="w-4 h-4 fill-current" aria-hidden="true" />
        Start Your First Scan
      </Link>
    </div>
  );
}

// ─── Error state ──────────────────────────────────────────────────────────
function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center space-y-4">
      <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/25 flex items-center justify-center">
        <TriangleAlert className="w-6 h-6 text-red-400" aria-hidden="true" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-semibold text-[#F5F5F5]">Unable to load dashboard data</p>
        <p className="text-xs text-[#6F6F6F]">Check your connection and try again</p>
      </div>
      <button
        onClick={onRetry}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-[10px] bg-[#141414] border border-[rgba(255,255,255,0.10)] hover:border-[#D4AF37]/30 text-xs font-semibold text-[#A1A1A1] hover:text-[#F5F5F5] transition-all"
      >
        <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
        Try Again
      </button>
    </div>
  );
}

// ─── Severity distribution chart ─────────────────────────────────────────
function SeverityChart({
  breakdown,
  total,
  reportId,
}: {
  breakdown: Record<string, number>;
  total: number;
  reportId?: string;
}) {
  return (
    <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
          Findings by Severity
        </p>
        <span className="text-[11px] text-[#6F6F6F] font-mono">
          {total} open finding{total !== 1 ? 's' : ''}
        </span>
      </div>

      {total === 0 ? (
        <div className="flex flex-col items-center justify-center py-6 gap-1">
          <span className="text-emerald-400 font-semibold text-xs">✓ No open findings</span>
          <p className="text-[11px] text-[#6F6F6F]">Latest assessment found no actionable issues</p>
        </div>
      ) : (
        <>
          {/* Grid of severity counts */}
          <div className="grid grid-cols-5 gap-1.5" role="list" aria-label="Finding count by severity">
            {SEV_ORDER.map((sev) => {
              const count = breakdown[sev] ?? 0;
              return (
                <div
                  key={sev}
                  role="listitem"
                  className="flex flex-col items-center p-3 rounded-[10px] border border-[rgba(255,255,255,0.05)] bg-[#080808] transition-colors hover:border-[rgba(255,255,255,0.10)]"
                  aria-label={`${count} ${sev} findings`}
                >
                  <span className="text-lg font-black tabular-nums" style={{ color: SEV_COLORS[sev] }}>
                    {count}
                  </span>
                  <span className="text-[9px] text-[#5A5A5A] capitalize font-semibold mt-0.5">{sev}</span>
                </div>
              );
            })}
          </div>

          {/* Proportional bar */}
          <div
            className="h-2 rounded-full overflow-hidden flex bg-[#141414]"
            role="img"
            aria-label="Severity distribution bar chart"
          >
            {SEV_ORDER.map((sev) => {
              const count = breakdown[sev] ?? 0;
              if (count === 0) return null;
              const pct = (count / total) * 100;
              return (
                <div
                  key={sev}
                  style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }}
                  className="h-full transition-all"
                  title={`${sev}: ${count} (${pct.toFixed(0)}%)`}
                />
              );
            })}
          </div>

          {reportId && (
            <Link
              href={`/reports/${reportId}`}
              className="flex items-center justify-center gap-1.5 text-[11px] text-[#6F6F6F] hover:text-[#D4AF37] transition-colors group pt-1"
              aria-label="View all findings in the full report"
            >
              View findings in report
              <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
            </Link>
          )}
        </>
      )}
    </div>
  );
}

// ─── Recent scans table ───────────────────────────────────────────────────
function RecentScansTable({ scans }: { scans: Scan[] }) {
  if (scans.length === 0) return null;

  return (
    <GlassCard className="p-6 space-y-4 border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] rounded-[14px]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="w-3.5 h-3.5 text-[#D4AF37]" aria-hidden="true" />
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
            Scan History
          </h2>
        </div>
        <Link
          href="/history"
          className="text-[11px] text-[#6F6F6F] hover:text-[#D4AF37] flex items-center gap-1 transition-colors group"
          aria-label="View all scans in scan history"
        >
          View All
          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </Link>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full" aria-label="Recent security assessments">
          <thead>
            <tr className="border-b border-[rgba(255,255,255,0.06)]">
              {['Target', 'Status', 'Score', 'Open Findings', 'Time', 'Action'].map((h) => (
                <th
                  key={h}
                  scope="col"
                  className="pb-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-[#4A4A4A] pr-4 whitespace-nowrap"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[rgba(255,255,255,0.04)]">
            {scans.map((scan) => {
              const score = scan.overall_score ?? scan.report?.overall_score;
              const grade = scan.grade ?? scan.report?.grade;
              const reportId = scan.report_id ?? scan.report?.id;
              const findingsBreakdown = scan.findings_breakdown ?? {};
              const findingsCount = scan.findings_count ?? scan.report?.findings_count ?? 0;

              // Build severity breakdown string: "2H · 3M · 5L"
              const sevParts: string[] = [];
              if (findingsBreakdown.critical > 0) sevParts.push(`${findingsBreakdown.critical}C`);
              if (findingsBreakdown.high > 0) sevParts.push(`${findingsBreakdown.high}H`);
              if (findingsBreakdown.medium > 0) sevParts.push(`${findingsBreakdown.medium}M`);
              if (findingsBreakdown.low > 0) sevParts.push(`${findingsBreakdown.low}L`);
              if (findingsBreakdown.info > 0) sevParts.push(`${findingsBreakdown.info}I`);

              return (
                <tr key={scan.id} className="hover:bg-[#0A0A0A] transition-colors">
                  {/* Target */}
                  <td className="py-3 pr-4">
                    <span
                      className="font-mono text-xs font-semibold text-[#F5F5F5] truncate block max-w-[180px]"
                      title={scan.url}
                    >
                      {scan.url.replace(/^https?:\/\//, '')}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-3 pr-4">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                        scan.status === 'completed'
                          ? 'bg-emerald-500/12 text-emerald-400 border border-emerald-500/25'
                          : scan.status === 'running'
                          ? 'bg-[#D4AF37]/12 text-[#D4AF37] border border-[#D4AF37]/25 animate-pulse'
                          : scan.status === 'failed'
                          ? 'bg-red-500/12 text-red-400 border border-red-500/25'
                          : scan.status === 'cancelled'
                          ? 'bg-slate-500/12 text-[#6F6F6F] border border-slate-500/20'
                          : 'bg-slate-500/12 text-[#94A3B8] border border-slate-500/20'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>

                  {/* Score */}
                  <td className="py-3 pr-4">
                    {typeof score === 'number' ? (
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-black text-sm" style={{ color: getScoreColor(score) }}>
                          {score}
                        </span>
                        {grade && (
                          <span
                            className="text-[9px] font-black px-1.5 py-0.5 rounded bg-[#141414]"
                            style={{ color: getGradeColor(String(grade)) }}
                          >
                            {grade}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-[#4A4A4A] font-mono text-xs">—</span>
                    )}
                  </td>

                  {/* Findings */}
                  <td className="py-3 pr-4">
                    {scan.status === 'completed' ? (
                      sevParts.length > 0 ? (
                        <span className="text-[11px] text-[#A1A1A1] font-mono">
                          {sevParts.map((p, i) => {
                            const sev =
                              p.endsWith('C') ? '#EF4444' :
                              p.endsWith('H') ? '#F97316' :
                              p.endsWith('M') ? '#F59E0B' :
                              p.endsWith('L') ? '#4FAF72' : '#94A3B8';
                            return (
                              <span key={i}>
                                {i > 0 && <span className="text-[#3A3A3A] mx-1">·</span>}
                                <span style={{ color: sev }}>{p}</span>
                              </span>
                            );
                          })}
                        </span>
                      ) : (
                        <span className="text-[11px] text-[#4FAF72] font-semibold">None</span>
                      )
                    ) : (
                      <span className="text-[#4A4A4A] text-xs">—</span>
                    )}
                  </td>

                  {/* Time */}
                  <td className="py-3 pr-4">
                    <span className="text-[11px] text-[#4A4A4A] whitespace-nowrap">
                      {timeAgo(scan.completed_at ?? scan.created_at)}
                    </span>
                  </td>

                  {/* Action */}
                  <td className="py-3">
                    {reportId ? (
                      <Link
                        href={`/reports/${reportId}`}
                        className="inline-flex items-center gap-1 text-[11px] text-[#D4AF37] hover:text-[#E4C35A] font-semibold transition-colors group whitespace-nowrap"
                        aria-label={`View report for ${scan.url}`}
                      >
                        View Report
                        <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                      </Link>
                    ) : scan.status === 'running' ? (
                      <Link
                        href={`/scan?id=${scan.id}`}
                        className="inline-flex items-center gap-1 text-[11px] text-[#D4AF37] hover:text-[#E4C35A] font-semibold transition-colors group whitespace-nowrap"
                        aria-label={`View live scan progress for ${scan.url}`}
                      >
                        Live Progress
                        <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                      </Link>
                    ) : (
                      <span className="text-[#3A3A3A] text-xs">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </GlassCard>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────

interface DashboardData {
  stats: DashboardStats;
  recentScans: Scan[];
  latestReport: Report | null;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchDashboard = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const [statsRes, scansRes] = await Promise.all([
        api.get<DashboardStats>('/api/scans/stats'),
        api.get<Scan[]>('/api/scans', { params: { limit: 5 } }),
      ]);

      const scansList: Scan[] = Array.isArray(scansRes.data)
        ? scansRes.data
        : ((scansRes.data as any)?.items ?? []);

      // Fetch latest completed scan's full report for findings detail
      const latestCompleted = scansList.find((s) => s.status === 'completed' && (s.report_id ?? s.report?.id));
      let latestReport: Report | null = null;
      if (latestCompleted) {
        const reportId = latestCompleted.report_id ?? latestCompleted.report?.id;
        if (reportId) {
          try {
            const reportRes = await api.get<Report>(`/api/reports/${reportId}`);
            latestReport = reportRes.data;
          } catch {
            // Non-critical — dashboard works without full report data
          }
        }
      }

      setData({ stats: statsRes.data, recentScans: scansList, latestReport });
    } catch (err: any) {
      setError(true);
      const detail = err.response?.data?.detail;
      const msg = typeof detail === 'string' ? detail : 'Failed to load dashboard data';
      toast.error(msg, { id: 'dashboard-error' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  // Derived values
  const { stats, recentScans, latestReport } = data ?? {
    stats: null as any,
    recentScans: [],
    latestReport: null,
  };

  const latestScan = recentScans[0] ?? null;
  const activeScan = recentScans.find((s) => s.status === 'running' || s.status === 'pending') ?? null;

  // Findings for the latest COMPLETED scan (from full report if available, else from scan breakdown)
  const latestFindings = useMemo(() => {
    if (latestReport?.findings) {
      return latestReport.findings.filter((f) => !f.is_passed_control);
    }
    return [];
  }, [latestReport]);

  // Latest scan's severity breakdown (for status banner + cards)
  const latestBreakdown = useMemo<Record<Severity, number>>(() => {
    const zero: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (latestReport?.findings) {
      for (const f of latestReport.findings) {
        if (!f.is_passed_control && f.severity in zero) {
          zero[f.severity as Severity]++;
        }
      }
      return zero;
    }
    // Fallback to scan's pre-computed breakdown
    const latestCompleted = recentScans.find((s) => s.status === 'completed');
    if (latestCompleted?.findings_breakdown) {
      for (const [k, v] of Object.entries(latestCompleted.findings_breakdown)) {
        if (k in zero) zero[k as Severity] = v;
      }
    }
    return zero;
  }, [latestReport, recentScans]);

  const totalLatestFindings = Object.values(latestBreakdown).reduce((a, b) => a + b, 0);
  const hasScans = (stats?.total_scans ?? 0) > 0 || recentScans.length > 0;

  // Latest completed scan (may be behind activeScan in the list)
  const latestCompletedScan = recentScans.find((s) => s.status === 'completed') ?? null;
  const reportId = latestCompletedScan?.report_id ?? latestCompletedScan?.report?.id ?? latestReport?.id;

  if (loading) return <DashboardSkeleton />;
  if (error) return <ErrorState onRetry={fetchDashboard} />;
  if (!hasScans) return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      <PageHeader
        title="Security Dashboard"
        subtitle="Your security posture, latest assessment, and priority findings"
        actions={
          <Link
            href="/scan"
            id="new-scan-btn-header"
            className="h-10 px-5 rounded-[10px] bg-[#D4AF37] hover:bg-[#E4C35A] text-[#050505] font-bold text-xs flex items-center gap-2 shadow-[0_2px_12px_rgba(212,175,55,0.2)] transition-all hover:-translate-y-0.5 hover:shadow-[0_4px_20px_rgba(212,175,55,0.3)]"
          >
            <Zap className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
            New Scan
          </Link>
        }
      />
      <EmptyState />
    </div>
  );

  return (
    <div className="space-y-5 page-enter max-w-7xl mx-auto">

      {/* ── Page Header ────────────────────────────────────────────── */}
      <PageHeader
        title="Security Dashboard"
        subtitle="Your security posture, latest assessment, and priority findings"
        actions={
          <Link
            href="/scan"
            id="new-scan-btn-header"
            className="h-10 px-5 rounded-[10px] bg-[#D4AF37] hover:bg-[#E4C35A] text-[#050505] font-bold text-xs flex items-center gap-2 shadow-[0_2px_12px_rgba(212,175,55,0.2)] transition-all hover:-translate-y-0.5 hover:shadow-[0_4px_20px_rgba(212,175,55,0.3)]"
          >
            <Zap className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
            New Scan
          </Link>
        }
      />

      {/* ── Security Status Banner ─────────────────────────────────── */}
      <SecurityStatusBanner
        critical={latestBreakdown.critical}
        high={latestBreakdown.high}
        medium={latestBreakdown.medium}
        low={latestBreakdown.low}
        info={latestBreakdown.info}
        hasScans={hasScans}
      />

      {/* ── Latest Assessment Hero / Active Scan ──────────────────── */}
      {activeScan ? (
        <ActiveScanPanel scan={activeScan} />
      ) : latestCompletedScan ? (
        <LatestAssessmentCard
          scan={latestCompletedScan}
          report={latestReport}
        />
      ) : null}

      {/* ── Top Stat Row ───────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">

        {/* Open Findings (latest assessment) */}
        <GlassCard hover className="p-5 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Open Findings</span>
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              latestBreakdown.critical > 0 || latestBreakdown.high > 0
                ? 'bg-red-500/10 border border-red-500/20'
                : 'bg-[#161616] border border-[rgba(255,255,255,0.08)]'
            }`}>
              <AlertTriangle className={`w-4 h-4 ${
                latestBreakdown.critical > 0 ? 'text-red-400' :
                latestBreakdown.high > 0 ? 'text-orange-400' : 'text-[#D4AF37]'
              }`} aria-hidden="true" />
            </div>
          </div>
          <p className="text-[28px] font-black text-[#F5F5F5] leading-none tabular-nums">
            {totalLatestFindings}
          </p>
          <div className="flex items-center gap-1.5 flex-wrap">
            {latestBreakdown.critical > 0 && (
              <span className="text-[10px] font-bold text-red-400">{latestBreakdown.critical} crit</span>
            )}
            {latestBreakdown.high > 0 && (
              <>
                {latestBreakdown.critical > 0 && <span className="text-[#3A3A3A]">·</span>}
                <span className="text-[10px] font-bold text-orange-400">{latestBreakdown.high} high</span>
              </>
            )}
            {latestBreakdown.medium > 0 && (
              <>
                {(latestBreakdown.critical > 0 || latestBreakdown.high > 0) && <span className="text-[#3A3A3A]">·</span>}
                <span className="text-[10px] font-bold text-amber-400">{latestBreakdown.medium} med</span>
              </>
            )}
            {totalLatestFindings === 0 && (
              <span className="text-[10px] text-[#4FAF72] font-semibold">No open findings</span>
            )}
          </div>
          <p className="text-[10px] text-[#5A5A5A]">Latest assessment</p>
        </GlassCard>

        {/* Total Assessments */}
        <GlassCard hover className="p-5 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Total Assessments</span>
            <div className="w-8 h-8 rounded-lg bg-[#161616] border border-[rgba(255,255,255,0.08)] flex items-center justify-center">
              <Activity className="w-4 h-4 text-[#D4AF37]" aria-hidden="true" />
            </div>
          </div>
          <p className="text-[28px] font-black text-[#F5F5F5] leading-none tabular-nums">
            {stats?.total_scans ?? 0}
          </p>
          <p className="text-[10px] text-[#5A5A5A]">
            {stats?.completed_scans ?? 0} completed
            {(stats?.running_scans ?? 0) > 0 && ` · ${stats.running_scans} running`}
          </p>
        </GlassCard>

        {/* Security Detectors */}
        <GlassCard hover className="p-5 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Security Detectors</span>
            <div className="w-8 h-8 rounded-lg bg-[#161616] border border-[rgba(255,255,255,0.08)] flex items-center justify-center">
              <Layers className="w-4 h-4 text-[#D4AF37]" aria-hidden="true" />
            </div>
          </div>
          <p className="text-[28px] font-black text-[#F5F5F5] leading-none tabular-nums">37</p>
          <p className="text-[10px] text-[#5A5A5A]">
            Passive analysis rules
          </p>
        </GlassCard>
      </div>

      {/* ── Priority Findings + Severity Chart ─────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <PriorityFindings findings={latestFindings} reportId={reportId?.toString()} />
        <SeverityChart
          breakdown={latestBreakdown}
          total={totalLatestFindings}
          reportId={reportId?.toString()}
        />
      </div>

      {/* ── Assessment Coverage ────────────────────────────────────── */}
      {latestReport && <AssessmentCoverage report={latestReport} />}

      {/* ── Finding Spotlight ─────────────────────────────────────── */}
      {latestFindings.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <FindingSpotlight findings={latestFindings} />

          {/* Security Assessment Pipeline — compact visual */}
          <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6 flex flex-col gap-4">
            <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
              Assessment Pipeline
            </p>
            <div className="flex flex-col gap-2" role="list" aria-label="Security assessment pipeline stages">
              {[
                { icon: '🌐', label: 'DNS Analysis', sub: 'SPF · DMARC · NS · MX' },
                { icon: '🔐', label: 'TLS / SSL', sub: 'Certificate · Cipher · Protocol' },
                { icon: '🛡️', label: 'Security Headers', sub: 'HSTS · CSP · X-Frame · Permissions' },
                { icon: '🍪', label: 'Cookie Security', sub: 'Secure · HttpOnly · SameSite' },
                { icon: '⚙️', label: 'Technology Detection', sub: 'Frameworks · Servers · Libraries' },
                { icon: '🔍', label: 'CVE Correlation', sub: 'Component inventory · EOL · NVD' },
                { icon: '📋', label: 'OWASP A01–A10', sub: 'Top 10:2025 assessment' },
                { icon: '📄', label: 'Report Generation', sub: 'Score · Findings · Evidence · PDF' },
              ].map((stage, i, arr) => (
                <div key={stage.label} role="listitem" className="flex items-start gap-3">
                  <div className="flex flex-col items-center flex-shrink-0">
                    <div className="w-7 h-7 rounded-lg bg-[#0A0A0A] border border-[rgba(255,255,255,0.08)] flex items-center justify-center text-sm">
                      {stage.icon}
                    </div>
                    {i < arr.length - 1 && (
                      <div className="w-px h-full min-h-[14px] mt-1 bg-[rgba(255,255,255,0.05)]" aria-hidden="true" />
                    )}
                  </div>
                  <div className="pb-2 min-w-0">
                    <p className="text-[11px] font-semibold text-[#F5F5F5] leading-tight">{stage.label}</p>
                    <p className="text-[10px] text-[#4A4A4A] mt-0.5">{stage.sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Recent Scans Table ─────────────────────────────────────── */}
      <RecentScansTable scans={recentScans} />

    </div>
  );
}
