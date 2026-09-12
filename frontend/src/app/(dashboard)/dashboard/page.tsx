'use client';
import { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  Shield, Search, AlertTriangle, FileText, CheckCircle,
  TrendingUp, Clock, ArrowRight, Activity, Zap, ShieldCheck,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { PageHeader } from '@/components/ui/PageHeader';
import api from '@/lib/api';
import { DashboardStats, Scan, Severity } from '@/types';
import { formatDate, timeAgo, getScoreColor, getGradeColor } from '@/lib/utils';
import toast from 'react-hot-toast';

const SEV_COLORS: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#4FAF72',
  info: '#94A3B8',
};

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const color = getScoreColor(score);
  const gradeColor = getGradeColor(grade);
  const r = 58;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);

  return (
    <div className="relative w-36 h-36 mx-auto flex-shrink-0">
      <svg className="w-36 h-36 -rotate-90" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1A1A1A" strokeWidth="10" />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${circ} ${circ}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-black text-[#F5F3ED] leading-none">{score}</span>
        <span className="text-[11px] text-[#A7A39A] font-medium mt-0.5">/ 100</span>
        <span className="text-xs font-black uppercase tracking-wider mt-1" style={{ color: gradeColor }}>
          Grade {grade}
        </span>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    const fetchDashboard = async () => {
      try {
        const [statsRes, scansRes] = await Promise.all([
          api.get<DashboardStats>('/api/scans/stats'),
          api.get<Scan[]>('/api/scans', { params: { limit: 5 } }),
        ]);
        if (isMounted) {
          setStats(statsRes.data);
          const scansList = Array.isArray(scansRes.data)
            ? scansRes.data
            : ((scansRes.data as any)?.items || []);
          setRecentScans(scansList);
        }
      } catch (err: any) {
        if (isMounted) {
          const detail = err.response?.data?.detail;
          const msg = typeof detail === 'string' ? detail : 'Failed to load dashboard data';
          toast.error(msg);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };
    fetchDashboard();
    return () => {
      isMounted = false;
    };
  }, []);

  const totalFindings: number = useMemo(() => {
    const sevMap = stats?.findings_by_severity;
    if (!sevMap) return 0;
    return Object.values(sevMap).reduce((a: number, b: number) => a + b, 0);
  }, [stats]);

  if (loading) {
    return (
      <div className="space-y-6 page-enter">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="stat-card h-28 skeleton" />
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 glass-card h-64 skeleton" />
          <div className="glass-card h-64 skeleton" />
        </div>
      </div>
    );
  }

  const latestScan = recentScans[0];
  const overallScore = stats?.average_score ?? (latestScan?.overall_score ?? latestScan?.report?.overall_score ?? (stats?.total_scans === 0 ? 100 : 74));
  const latestGrade = stats?.latest_grade ?? (latestScan?.grade ?? latestScan?.report?.grade ?? (stats?.total_scans === 0 ? 'A' : 'B'));

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      {/* Page Header */}
      <PageHeader
        title="Security Dashboard"
        subtitle="Overview of your website security posture and active attack surface"
        actions={
          <Link
            href="/scan"
            className="h-11 px-5 rounded-[10px] bg-[#D4AF37] hover:bg-[#E4C35A] text-[#050505] font-bold text-xs flex items-center gap-2 shadow-[0_2px_12px_rgba(212,175,55,0.2)] transition-all"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>New Scan</span>
          </Link>
        }
      />

      {/* 3 Core Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Total Scans */}
        <GlassCard hover className="p-6 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Total Scans</span>
            <div className="w-8 h-8 rounded-lg bg-[#161616] border border-[rgba(255,255,255,0.08)] flex items-center justify-center">
              <Activity className="w-4 h-4 text-[#D4AF37]" />
            </div>
          </div>
          <p className="text-[28px] font-bold text-[#F5F5F5] leading-none">{stats?.total_scans ?? 0}</p>
          <p className="text-[11px] text-[#A1A1A1]">Across all monitored domains</p>
        </GlassCard>

        {/* Security Score */}
        <GlassCard hover className="p-6 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Average Score</span>
            <div className="w-8 h-8 rounded-lg bg-[#161616] border border-[rgba(255,255,255,0.08)] flex items-center justify-center">
              <Shield className="w-4 h-4 text-[#D4AF37]" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <p className="text-[28px] font-bold text-[#F5F5F5] leading-none">{overallScore}</p>
            <span className="text-xs font-bold text-[#6F6F6F]">/ 100</span>
            <span className="text-xs font-bold uppercase ml-auto" style={{ color: getGradeColor(latestGrade) }}>
              Grade {latestGrade}
            </span>
          </div>
          <p className="text-[11px] text-[#A1A1A1]">Average posture across scans</p>
        </GlassCard>

        {/* Total Findings */}
        <GlassCard hover className="p-6 space-y-3 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#6F6F6F]">Total Findings</span>
            <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-[#EF4444]" />
            </div>
          </div>
          <p className="text-[28px] font-bold text-[#F5F5F5] leading-none">{totalFindings}</p>
          <div className="flex items-center gap-2 text-[10px] text-[#A1A1A1]">
            <span className="text-[#EF4444] font-bold">{stats?.findings_by_severity?.critical || 0} crit</span>
            <span className="text-[#6F6F6F]">•</span>
            <span className="text-[#F97316] font-bold">{stats?.findings_by_severity?.high || 0} high</span>
            <span className="text-[#6F6F6F]">•</span>
            <span className="text-[#F59E0B] font-bold">{stats?.findings_by_severity?.medium || 0} med</span>
          </div>
        </GlassCard>
      </div>

      {/* Main Grid: Posture Overview + Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Posture Score Gauge & Assessment Summary */}
        <GlassCard className="p-6 space-y-5 lg:col-span-1 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-bold uppercase tracking-wider text-[#D4AF37]">Security Posture</h2>
            <span className="text-[10px] font-mono text-[#6F6F6F]">Latest Assessment</span>
          </div>

          <ScoreRing score={overallScore} grade={latestGrade} />

          <div className="space-y-2.5 pt-4 border-t border-[rgba(255,255,255,0.06)]">
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#A1A1A1]">System Health</span>
              <span className="font-semibold text-[#4FAF72] flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#4FAF72] shadow-[0_0_6px_rgba(79,175,114,0.6)]" /> Operational
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-[#A1A1A1]">Scan Engine</span>
              <span className="font-semibold text-[#F5F5F5]">Passive Recon</span>
            </div>
          </div>

          <Link
            href="/scan"
            className="w-full py-2.5 rounded-[10px] bg-[#161616] hover:bg-[#1C1C1C] border border-[rgba(255,255,255,0.08)] hover:border-[#D4AF37]/40 text-[#F5F5F5] font-semibold text-xs flex items-center justify-center gap-2 transition-all mt-4"
          >
            <Shield className="w-4 h-4 text-[#D4AF37]" /> Start New Scan
          </Link>
        </GlassCard>

        {/* Severity Distribution & Remediation Widget */}
        <div className="lg:col-span-2 space-y-6">
          {/* Findings Breakdown by Severity */}
          <GlassCard className="p-6 space-y-4 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
            <div className="flex items-center justify-between">
              <h2 className="text-[11px] font-bold uppercase tracking-wider text-[#D4AF37]">Findings by Severity</h2>
              <span className="text-[10px] text-[#6F6F6F] font-mono">{totalFindings} Total Issues</span>
            </div>

            <div className="grid grid-cols-5 gap-2.5 pt-2">
              {SEV_ORDER.map((sev) => {
                const count = stats?.findings_by_severity?.[sev] || 0;
                return (
                  <div key={sev} className="text-center p-3 rounded-[12px] border border-[rgba(255,255,255,0.06)] bg-[#0B0B0B]">
                    <p className="text-xl font-black" style={{ color: SEV_COLORS[sev] }}>{count}</p>
                    <p className="text-[10px] text-[#6F6F6F] capitalize font-bold mt-1">{sev}</p>
                  </div>
                );
              })}
            </div>

            {/* Severity Breakdown Bar Visual */}
            {totalFindings > 0 && (
              <div className="h-2 rounded-full overflow-hidden flex bg-[#161616] mt-3">
                {SEV_ORDER.map((sev) => {
                  const count = stats?.findings_by_severity?.[sev] || 0;
                  if (count === 0) return null;
                  const pct = (count / totalFindings) * 100;
                  return (
                    <div
                      key={sev}
                      style={{ width: `${pct}%`, backgroundColor: SEV_COLORS[sev] }}
                      className="h-full"
                      title={`${sev}: ${count} (${pct.toFixed(0)}%)`}
                    />
                  );
                })}
              </div>
            )}
          </GlassCard>
        </div>
      </div>

      {/* Recent Scans Table */}
      <GlassCard className="p-6 space-y-4 border border-[rgba(255,255,255,0.08)] bg-[#101010] rounded-[14px]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#D4AF37]" />
            <h2 className="text-[11px] font-bold uppercase tracking-wider text-[#D4AF37]">Recent Scans</h2>
          </div>
          <Link href="/history" className="text-xs text-[#A1A1A1] hover:text-[#D4AF37] flex items-center gap-1 transition-colors">
            View All Scans <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {recentScans.length === 0 ? (
          <div className="text-center py-12 px-4 space-y-3">
            <div className="w-12 h-12 rounded-xl bg-[#141414] border border-[rgba(255,255,255,0.08)] flex items-center justify-center mx-auto text-[#6F6F6F]">
              <Shield className="w-6 h-6" />
            </div>
            <p className="text-xs text-[#A1A1A1] max-w-sm mx-auto">
              No scans performed yet. Click &quot;New Scan&quot; above to initiate your first passive security assessment.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Status</th>
                  <th>Score / Grade</th>
                  <th>Findings</th>
                  <th>Date</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => {
                  const score = scan.overall_score ?? scan.report?.overall_score ?? '—';
                  const grade = scan.grade ?? scan.report?.grade ?? '—';
                  const findingsCount = scan.report?.findings_count ?? (scan.report?.findings?.length ?? 0);
                  const reportId = scan.report_id ?? scan.report?.id;

                  return (
                    <tr key={scan.id} className="transition-colors">
                      <td className="font-mono text-xs text-[#F5F5F5] font-semibold max-w-xs truncate">
                        {scan.url}
                      </td>
                      <td>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          scan.status === 'completed' ? 'bg-green-500/15 text-[#4FAF72] border border-green-500/30' :
                          scan.status === 'running' ? 'bg-[#8F7420]/20 text-[#D4AF37] border border-[#D4AF37]/30 animate-pulse' :
                          scan.status === 'failed' ? 'bg-red-500/15 text-[#EF4444] border border-red-500/30' :
                          'bg-slate-500/15 text-[#94A3B8] border border-slate-500/30'
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        {typeof score === 'number' ? (
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold" style={{ color: getScoreColor(score) }}>{score}</span>
                            <span className="text-[10px] font-extrabold px-1.5 py-0.5 rounded bg-[#161616]" style={{ color: getGradeColor(String(grade)) }}>
                              Grade {grade}
                            </span>
                          </div>
                        ) : (
                          <span className="text-[#6F6F6F] font-mono">—</span>
                        )}
                      </td>
                      <td className="text-xs text-[#A1A1A1]">
                        {findingsCount} issues
                      </td>
                      <td className="text-xs text-[#6F6F6F]">
                        {timeAgo(scan.created_at)}
                      </td>
                      <td>
                        {reportId ? (
                          <Link
                            href={`/reports/${reportId}`}
                            className="inline-flex items-center gap-1 text-xs text-[#D4AF37] hover:underline font-semibold"
                          >
                            View Report <ArrowRight className="w-3 h-3" />
                          </Link>
                        ) : scan.status === 'running' ? (
                          <Link
                            href={`/scan?id=${scan.id}`}
                            className="inline-flex items-center gap-1 text-xs text-[#D4AF37] hover:underline font-semibold"
                          >
                            Live Progress <ArrowRight className="w-3 h-3" />
                          </Link>
                        ) : (
                          <span className="text-[#6F6F6F] text-xs">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
