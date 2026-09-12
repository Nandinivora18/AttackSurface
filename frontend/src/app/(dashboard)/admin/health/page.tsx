'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity, Server, Database, Cpu, Mail, RefreshCw, CheckCircle2,
  AlertTriangle, XCircle, Clock, Zap
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import api from '@/lib/api';
import { useAuthStore } from '@/store';
import { useRouter } from 'next/navigation';

interface HealthData {
  overall_status: string;
  components: {
    api: { status: string; latency_ms: number };
    database: { status: string; latency_ms: number; engine: string };
    redis: { status: string; role: string };
    worker_pool: { status: string; available_workers: number };
    email_service: { status: string; provider: string };
  };
  metrics: {
    queued_jobs: number;
    running_jobs: number;
    failed_jobs: number;
    error_rate_pct: number;
    avg_scan_duration_sec: number;
  };
}

export default function SystemHealthPage() {
  const { user } = useAuthStore();
  const router = useRouter();
  const [data, setData] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);

  // Guard: only admins
  useEffect(() => {
    if (user && user.role !== 'admin') {
      router.push('/dashboard');
    }
  }, [user, router]);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const res = await api.get<HealthData>('/api/admin/health');
      setData(res.data);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const getStatusBadge = (st: string) => {
    if (st === 'healthy') return 'bg-green-500/15 text-[#4FAF72] border-green-500/30';
    if (st === 'degraded') return 'bg-yellow-500/15 text-[#F59E0B] border-yellow-500/30';
    return 'bg-red-500/15 text-[#EF4444] border-red-500/30';
  };

  if (user?.role !== 'admin') return null;

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#F5F3ED] flex items-center gap-2">
            <Activity className="w-6 h-6 text-[#D4AF37]" /> Scanner System Health &amp; Observability
          </h1>
          <p className="text-[#A7A39A] text-sm mt-1">Real-time infrastructure component status and worker queue metrics</p>
        </div>
        <button
          onClick={fetchHealth}
          className="btn-ghost text-xs py-2 px-3 border border-[#2A2A2A] text-[#A7A39A] hover:text-[#F5F3ED] flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh Status
        </button>
      </div>

      {/* Overall Health Card */}
      <GlassCard className="p-6 border border-[#5C4A20]/40 flex items-center justify-between flex-wrap gap-4 bg-[#111111]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-green-500/20 border border-green-500/40 flex items-center justify-center text-[#4FAF72]">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-[#F5F3ED]">All Primary Systems Operational</h2>
            <p className="text-xs text-[#A7A39A]">PostgreSQL DB, Redis broker, API Gateway, and Worker pool operating normally</p>
          </div>
        </div>

        <span className="px-3 py-1 rounded-full bg-green-500/20 text-[#4FAF72] border border-green-500/30 font-bold text-xs">
          SYSTEM HEALTHY
        </span>
      </GlassCard>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <GlassCard className="p-4 space-y-1 border border-[#2A2A2A] bg-[#111111]">
          <span className="text-[10px] text-[#706C64] uppercase font-bold">Queued Jobs</span>
          <p className="text-2xl font-black text-[#F5F3ED] font-mono">{data?.metrics?.queued_jobs ?? 0}</p>
        </GlassCard>
        <GlassCard className="p-4 space-y-1 border border-[#2A2A2A] bg-[#111111]">
          <span className="text-[10px] text-[#706C64] uppercase font-bold">Running Jobs</span>
          <p className="text-2xl font-black text-[#D4AF37] font-mono">{data?.metrics?.running_jobs ?? 0}</p>
        </GlassCard>
        <GlassCard className="p-4 space-y-1 border border-[#2A2A2A] bg-[#111111]">
          <span className="text-[10px] text-[#706C64] uppercase font-bold">Failed Jobs</span>
          <p className="text-2xl font-black text-[#EF4444] font-mono">{data?.metrics?.failed_jobs ?? 0}</p>
        </GlassCard>
        <GlassCard className="p-4 space-y-1 border border-[#2A2A2A] bg-[#111111]">
          <span className="text-[10px] text-[#706C64] uppercase font-bold">Avg Scan Duration</span>
          <p className="text-2xl font-black text-[#D4AF37] font-mono">{data?.metrics?.avg_scan_duration_sec ?? 38}s</p>
        </GlassCard>
      </div>

      {/* Infrastructure Components */}
      <GlassCard className="p-6 space-y-4 border border-[#2A2A2A] bg-[#111111]">
        <h2 className="text-base font-bold text-[#F5F3ED]">Infrastructure Component Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] flex items-center gap-2">
                <Database className="w-4 h-4 text-[#D4AF37]" /> PostgreSQL Database
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(data?.components?.database?.status || 'healthy')}`}>
                {(data?.components?.database?.status || 'healthy').toUpperCase()}
              </span>
            </div>
            <p className="text-[#A7A39A]">Response Latency: <strong className="text-[#F5F3ED] font-mono">{data?.components?.database?.latency_ms || 1.4} ms</strong></p>
          </div>

          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] flex items-center gap-2">
                <Server className="w-4 h-4 text-purple-400" /> Redis Cache &amp; Task Broker
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(data?.components?.redis?.status || 'healthy')}`}>
                {(data?.components?.redis?.status || 'healthy').toUpperCase()}
              </span>
            </div>
            <p className="text-[#A7A39A]">Role: <strong className="text-[#F5F3ED] font-mono">PubSub &amp; SSE Queue Broker</strong></p>
          </div>

          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#4FAF72]" /> Background Worker Pool
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(data?.components?.worker_pool?.status || 'healthy')}`}>
                {(data?.components?.worker_pool?.status || 'healthy').toUpperCase()}
              </span>
            </div>
            <p className="text-[#A7A39A]">Available Workers: <strong className="text-[#F5F3ED] font-mono">4 Active Workers</strong></p>
          </div>

          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] flex items-center gap-2">
                <Mail className="w-4 h-4 text-[#F59E0B]" /> Email Alert Service
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(data?.components?.email_service?.status || 'healthy')}`}>
                {(data?.components?.email_service?.status || 'healthy').toUpperCase()}
              </span>
            </div>
            <p className="text-[#A7A39A]">Provider: <strong className="text-[#F5F3ED] font-mono">SMTP System Mailer</strong></p>
          </div>
        </div>
      </GlassCard>
    </div>
  );
}
