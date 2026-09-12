'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  FileText, Search, Download, ArrowRight, Shield, RefreshCw, Calendar, ExternalLink,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { Button } from '@/components/ui/Button';
import { ScanCardSkeleton } from '@/components/shared/LoadingSkeleton';
import api from '@/lib/api';
import { Report } from '@/types';
import { formatDate, timeAgo, truncateUrl, getScoreColor } from '@/lib/utils';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await api.get<Report[]>('/api/reports?limit=50');
      setReports(res.data);
    } catch {
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const filtered = reports.filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    const url = r.scan?.url || '';
    const grade = (r.grade || '').toLowerCase();
    const risk = (r.risk_level || '').toLowerCase();
    return url.toLowerCase().includes(q) || grade.includes(q) || risk.includes(q);
  });

  const downloadPdf = async (reportId: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      const res = await api.get(`/api/reports/${reportId}/pdf`, { responseType: 'blob' });
      const blob = res.data instanceof Blob ? res.data : new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelscan-report-${reportId.substring(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success('PDF download started');
    } catch {
      toast.error('Failed to download PDF');
    }
  };

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#F5F3ED] mb-1">Security Assessment Reports</h1>
          <p className="text-[#A7A39A] text-sm">Detailed vulnerability analysis, risk ratings, and remediation recommendations.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchReports} className="btn-ghost py-2 px-4 gap-2 text-sm" disabled={loading}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Search */}
      <GlassCard className="p-4 border border-[#2A2A2A] bg-[#111111]">
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#706C64] pointer-events-none" />
          <input
            type="text"
            placeholder="Search reports by URL, grade, or risk level…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="cyber-input !pl-11 py-2.5 text-sm bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED] focus:border-[#D4AF37]"
          />
        </div>
      </GlassCard>

      {/* List */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => <ScanCardSkeleton key={i} />)}
        </div>
      ) : filtered.length === 0 ? (
        <GlassCard className="p-16 text-center border border-[#2A2A2A] bg-[#111111]">
          <FileText className="w-12 h-12 text-[#706C64] mx-auto mb-4" />
          <p className="text-[#F5F3ED] font-semibold mb-1">No reports found</p>
          <p className="text-[#A7A39A] text-sm mb-6">
            {search ? 'No matching reports for your search criteria.' : 'Run a security scan to generate detailed reports.'}
          </p>
          {!search && (
            <Link href="/scan">
              <Button variant="primary" size="md" leftIcon={FileText}>Run New Scan</Button>
            </Link>
          )}
        </GlassCard>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filtered.map((report, i) => {
            const scoreColor = getScoreColor(report.overall_score);
            const targetUrl = report.scan?.url || 'Target Site';

            return (
              <motion.div
                key={report.id}
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <Link href={`/reports/${report.id}`}>
                  <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111] hover:border-[#5C4A20]/60 transition-all group flex flex-col justify-between h-full">
                    <div>
                      {/* Top row */}
                      <div className="flex items-start justify-between gap-3 mb-3">
                        <div className="flex-1 min-w-0">
                          <h3 className="font-bold text-[#F5F3ED] group-hover:text-[#D4AF37] transition-colors truncate">
                            {truncateUrl(targetUrl, 45)}
                          </h3>
                          <div className="flex items-center gap-2 mt-1 text-xs text-[#706C64]">
                            <Calendar className="w-3 h-3" />
                            {timeAgo(report.created_at)}
                          </div>
                        </div>

                        {/* Score Badge */}
                        <div
                          className="flex flex-col items-center justify-center w-14 h-14 rounded-xl border-2 flex-shrink-0"
                          style={{ borderColor: `${scoreColor}40`, background: `${scoreColor}10` }}
                        >
                          <span className="text-lg font-black leading-none" style={{ color: scoreColor }}>
                            {report.overall_score}
                          </span>
                          <span className="text-[10px] font-bold" style={{ color: scoreColor }}>
                            {report.grade}
                          </span>
                        </div>
                      </div>

                      {/* Summary */}
                      {report.summary && (
                        <p className="text-xs text-[#A7A39A] line-clamp-2 leading-relaxed mb-4">
                          {report.summary}
                        </p>
                      )}

                      {/* Findings Badges */}
                      <div className="flex items-center gap-2 flex-wrap mb-4">
                        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                          const count = report.findings?.filter((f) => f.severity === sev).length || 0;
                          if (!count) return null;
                          return (
                            <SeverityBadge key={sev} severity={sev} count={count} size="sm" />
                          );
                        })}
                      </div>
                    </div>

                    {/* Bottom actions */}
                    <div className="flex items-center justify-between pt-3 border-t border-[#2A2A2A]/60 mt-2">
                      <span className="text-xs font-semibold text-[#D4AF37] flex items-center gap-1 group-hover:underline">
                        View Report <ArrowRight className="w-3.5 h-3.5" />
                      </span>
                      <button
                        onClick={(e) => downloadPdf(report.id, e)}
                        className="p-1.5 rounded-lg border border-[#2A2A2A] hover:border-[#5C4A20] text-[#A7A39A] hover:text-[#F5F3ED] transition-all bg-[#0D0D0D]"
                        title="Download PDF Report"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                    </div>
                  </GlassCard>
                </Link>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
