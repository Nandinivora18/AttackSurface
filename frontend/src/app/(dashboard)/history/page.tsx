'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Trash2, ArrowRight, AlertTriangle,
  CheckCircle, Clock, XCircle, RefreshCw, ChevronDown, Globe,
  SortAsc, SortDesc, Calendar, History,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ScanCardSkeleton } from '@/components/shared/LoadingSkeleton';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { PageHeader } from '@/components/ui/PageHeader';
import { EmptyState } from '@/components/ui/EmptyState';
import { Spinner } from '@/components/ui/Spinner';
import api from '@/lib/api';
import { Scan, Report } from '@/types';
import { formatDate, timeAgo, truncateUrl, getScoreColor } from '@/lib/utils';
import toast from 'react-hot-toast';

type ScanWithReport = Scan & { report?: Report };
type SortKey = 'date' | 'score' | 'url';
type SortDir = 'asc' | 'desc';
type StatusFilter = 'all' | 'completed' | 'failed' | 'running' | 'cancelled';

/* ── Score Badge ── */
function ScoreBadge({ score, grade }: { score: number; grade: string }) {
  const color = getScoreColor(score);
  return (
    <div
      className="flex flex-col items-center justify-center w-14 h-14 rounded-xl border-2 flex-shrink-0"
      style={{ borderColor: `${color}40`, background: `${color}10` }}
      aria-label={`Score ${score}, grade ${grade}`}
    >
      <span className="text-lg font-black leading-none" style={{ color }}>{score}</span>
      <span className="text-[10px] font-bold" style={{ color }}>{grade}</span>
    </div>
  );
}

/* ── Status Chip ── */
const STATUS_CFG: Record<string, { variant: any; icon: React.ElementType; label: string }> = {
  completed:  { variant: 'success',  icon: CheckCircle, label: 'Completed'  },
  running:    { variant: 'champagne', icon: RefreshCw,   label: 'Running'    },
  failed:     { variant: 'red',      icon: XCircle,     label: 'Failed'     },
  pending:    { variant: 'warning',  icon: Clock,       label: 'Pending'    },
  cancelled:  { variant: 'slate',    icon: XCircle,     label: 'Cancelled'  },
};

function StatusChip({ status }: { status: string }) {
  const cfg = STATUS_CFG[status] ?? STATUS_CFG.pending;
  return (
    <Badge variant={cfg.variant} dot>
      {cfg.label}
    </Badge>
  );
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanWithReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [sortKey, setSortKey] = useState<SortKey>('date');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [showClearModal, setShowClearModal] = useState(false);
  const [clearingAll, setClearingAll] = useState(false);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 20;

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const [scansRes, reportsRes] = await Promise.all([
        api.get('/api/scans?limit=100&offset=0'),
        api.get('/api/reports?limit=100'),
      ]);
      const reports: Report[] = reportsRes.data;
      const merged: ScanWithReport[] = scansRes.data.map((s: Scan) => ({
        ...s,
        report: reports.find((r) => r.scan_id === s.id),
      }));
      setScans(merged);
    } catch {
      toast.error('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  const deleteScan = async (id: string) => {
    setDeletingId(id);
    try {
      await api.delete(`/api/scans/${id}`);
      setScans((prev) => prev.filter((s) => s.id !== id));
      toast.success('Scan deleted');
    } catch {
      toast.error('Failed to delete scan');
    } finally {
      setDeletingId(null);
    }
  };

  const clearAllScans = async () => {
    setClearingAll(true);
    try {
      await api.delete('/api/scans/clear-all');
      setScans([]);
      setShowClearModal(false);
      toast.success('All scan history cleared');
    } catch {
      toast.error('Failed to clear scan history');
    } finally {
      setClearingAll(false);
    }
  };

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const filtered = scans
    .filter((s) => {
      if (statusFilter !== 'all' && s.status !== statusFilter) return false;
      if (search) return s.url.toLowerCase().includes(search.toLowerCase());
      return true;
    })
    .sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'date') cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      else if (sortKey === 'score') cmp = (a.report?.overall_score ?? -1) - (b.report?.overall_score ?? -1);
      else if (sortKey === 'url') cmp = a.url.localeCompare(b.url);
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);

  const SortBtn = ({ label, k }: { label: string; k: SortKey }) => (
    <button
      onClick={() => toggleSort(k)}
      aria-label={`Sort by ${label}`}
      className={`flex items-center gap-1.5 text-xs font-semibold transition-colors ${sortKey === k ? 'text-[#D4AF37]' : 'text-[#706C64] hover:text-[#A7A39A]'}`}
    >
      {label}
      {sortKey === k
        ? sortDir === 'desc' ? <SortDesc className="w-3 h-3" aria-hidden /> : <SortAsc className="w-3 h-3" aria-hidden />
        : <ChevronDown className="w-3 h-3 opacity-40" aria-hidden />}
    </button>
  );

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      <PageHeader
        title="Scan History"
        subtitle={`${scans.length} total scan${scans.length !== 1 ? 's' : ''} — ${scans.filter((s) => s.status === 'completed').length} completed`}
        actions={
          <>
            <Button
              variant="ghost"
              size="sm"
              leftIcon={RefreshCw}
              loading={loading}
              onClick={fetchHistory}
            >
              Refresh
            </Button>
            {scans.length > 0 && (
              <Button
                variant="danger"
                size="sm"
                leftIcon={Trash2}
                onClick={() => setShowClearModal(true)}
              >
                Clear History
              </Button>
            )}
          </>
        }
      />

      {/* ── Filters ── */}
      <GlassCard className="p-4 border border-[#2A2A2A] bg-[#111111]">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search */}
          <Input
            type="text"
            placeholder="Search by URL…"
            leftIcon={Search}
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            wrapperClassName="flex-1"
            inputSize="sm"
            aria-label="Search scan history by URL"
          />

          {/* Status filters */}
          <div role="group" aria-label="Filter by status" className="flex gap-2 flex-wrap">
            {(['all', 'completed', 'running', 'failed', 'cancelled'] as StatusFilter[]).map((s) => (
              <button
                key={s}
                onClick={() => { setStatusFilter(s); setPage(0); }}
                aria-pressed={statusFilter === s}
                className={`text-xs px-3 py-2 rounded-lg capitalize font-medium transition-all ${
                  statusFilter === s
                    ? 'bg-[#5C4A20]/25 text-[#F5F3ED] border border-[#5C4A20] shadow-[0_0_10px_rgba(212,175,55,0.15)]'
                    : 'text-[#706C64] border border-[#2A2A2A] hover:text-[#A7A39A] bg-[#0D0D0D]'
                }`}
              >
                {s === 'all' ? `All (${scans.length})` : `${s} (${scans.filter((sc) => sc.status === s).length})`}
              </button>
            ))}
          </div>
        </div>
      </GlassCard>

      {/* ── Content ── */}
      {loading ? (
        <div className="space-y-3" aria-busy="true" aria-label="Loading scan history">
          {[1, 2, 3, 4, 5].map((i) => <ScanCardSkeleton key={i} />)}
        </div>
      ) : filtered.length === 0 ? (
        <GlassCard className="border border-[#2A2A2A] bg-[#111111]">
          <EmptyState
            icon={History}
            title="No scans found"
            description={
              search || statusFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Run your first scan to see results here'
            }
            action={
              !search && statusFilter === 'all' ? (
                <Link href="/scan">
                  <Button variant="primary" size="md">Start a Scan</Button>
                </Link>
              ) : undefined
            }
          />
        </GlassCard>
      ) : (
        <>
          {/* Column headers */}
          <div className="flex items-center gap-4 px-4 pb-1" aria-hidden>
            <div className="w-14 flex-shrink-0" />
            <div className="flex-1"><SortBtn label="URL / Target" k="url" /></div>
            <div className="w-28 hidden md:block"><SortBtn label="Severity" k="score" /></div>
            <div className="w-32 hidden sm:block"><SortBtn label="Date" k="date" /></div>
            <div className="w-24 hidden lg:block text-xs font-semibold text-[#706C64]">Status</div>
            <div className="w-20 flex-shrink-0" />
          </div>

          <div className="space-y-2" role="list" aria-label="Scan history items">
            <AnimatePresence>
              {paginated.map((scan, i) => (
                <motion.div
                  key={scan.id}
                  role="listitem"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ delay: i * 0.04 }}
                >
                  <GlassCard className="p-4 border border-[#2A2A2A] bg-[#111111] hover:border-[#5C4A20]/50 transition-all duration-200">
                    <div className="flex items-center gap-4">
                      {/* Score */}
                      {scan.report ? (
                        <ScoreBadge score={scan.report.overall_score} grade={scan.report.grade} />
                      ) : (
                        <div className="w-14 h-14 rounded-xl border border-[#2A2A2A] flex items-center justify-center flex-shrink-0 bg-[#0D0D0D]">
                          {scan.status === 'running'
                            ? <Spinner size="sm" className="text-[#D4AF37]" />
                            : <AlertTriangle className="w-5 h-5 text-[#706C64]" aria-hidden />}
                        </div>
                      )}

                      {/* URL info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="font-semibold text-[#F5F3ED] text-sm truncate">{truncateUrl(scan.url, 60)}</p>
                        </div>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                          <span className="text-xs text-[#706C64] flex items-center gap-1">
                            <Calendar className="w-3 h-3" aria-hidden />
                            {timeAgo(scan.created_at)}
                          </span>
                          {scan.status === 'running' && (
                            <span className="text-xs text-[#D4AF37]">{scan.progress}% — {scan.current_stage}</span>
                          )}
                          {scan.report?.findings && scan.status === 'completed' && (
                            <span className="text-xs text-[#706C64]">
                              {scan.report.findings.length} finding{scan.report.findings.length !== 1 ? 's' : ''}
                            </span>
                          )}
                        </div>
                        {scan.status === 'running' && (
                          <div className="mt-2 scan-progress-bar">
                            <div className="scan-progress-fill" style={{ width: `${scan.progress}%` }} />
                          </div>
                        )}
                      </div>

                      {/* Severity badges */}
                      <div className="w-28 hidden md:flex flex-col gap-1">
                        {scan.report && (
                          <div className="flex gap-1 flex-wrap">
                            {(['critical', 'high', 'medium'] as const).map((sev) => {
                              const cnt = scan.report!.findings?.filter((f) => f.severity === sev).length || 0;
                              if (!cnt) return null;
                              return <SeverityBadge key={sev} severity={sev} size="sm" />;
                            })}
                          </div>
                        )}
                      </div>

                      {/* Date */}
                      <div className="w-32 hidden sm:block text-xs text-[#706C64] flex-shrink-0">
                        {formatDate(scan.created_at).split(',')[0]}
                      </div>

                      {/* Status */}
                      <div className="w-24 hidden lg:block flex-shrink-0">
                        <StatusChip status={scan.status} />
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <button
                          onClick={() => deleteScan(scan.id)}
                          disabled={deletingId === scan.id}
                          aria-label="Delete scan"
                          className="p-2 rounded-lg text-[#706C64] hover:text-[#EF4444] hover:bg-red-500/10 transition-all"
                        >
                          {deletingId === scan.id
                            ? <Spinner size="sm" className="text-[#EF4444]" />
                            : <Trash2 className="w-4 h-4" aria-hidden />}
                        </button>
                        {scan.report && (
                          <Link
                            href={`/reports/${scan.report.id}`}
                            aria-label="View report"
                            className="p-2 rounded-lg text-[#706C64] hover:text-[#D4AF37] hover:bg-[#5C4A20]/15 transition-all"
                          >
                            <ArrowRight className="w-4 h-4" aria-hidden />
                          </Link>
                        )}
                      </div>
                    </div>
                  </GlassCard>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3 pt-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
              >
                Previous
              </Button>
              <span className="text-sm text-[#A7A39A]">
                Page {page + 1} of {totalPages}
              </span>
              <Button
                variant="ghost"
                size="sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}

      {/* ── Clear All Confirmation Modal ── */}
      <AnimatePresence>
        {showClearModal && (
          <div
            className="fixed inset-0 z-[400] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-modal-title"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-md bg-[#111111] border border-red-500/30 rounded-2xl p-6 space-y-4 shadow-2xl"
            >
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 flex-shrink-0">
                  <AlertTriangle className="w-6 h-6 text-[#EF4444]" aria-hidden />
                </div>
                <div>
                  <h3 id="clear-modal-title" className="text-lg font-bold text-[#F5F3ED]">Clear All Scan History?</h3>
                  <p className="text-xs text-[#A7A39A]">This action cannot be undone.</p>
                </div>
              </div>

              <p className="text-sm text-[#A7A39A]">
                Are you sure you want to permanently delete all <strong className="text-[#F5F3ED]">{scans.length}</strong> previous scan(s), along with their reports and findings?
              </p>

              <div className="flex items-center justify-end gap-3 pt-2">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={clearingAll}
                  onClick={() => setShowClearModal(false)}
                >
                  Cancel
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  loading={clearingAll}
                  leftIcon={Trash2}
                  onClick={clearAllScans}
                  className="bg-red-600 hover:bg-red-500 text-white border-0"
                >
                  {clearingAll ? 'Clearing…' : 'Yes, Clear All Scans'}
                </Button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
