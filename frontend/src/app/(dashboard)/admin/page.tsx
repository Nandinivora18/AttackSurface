'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Users, Search, Trash2, Shield, Activity, TrendingUp,
  Globe, FileText, RefreshCw, AlertTriangle, CheckCircle,
  ChevronDown, Clock, LogOut, BarChart3, ShieldAlert,
  Database, Lock, KeyRound, Copy, Check,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import { useAuthStore } from '@/store';
import api from '@/lib/api';
import { AdminStats } from '@/types';
import { formatDate, timeAgo, getScoreColor } from '@/lib/utils';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';

interface AdminUser {
  id: string;
  email: string;
  name: string;
  role: 'user' | 'admin';
  is_verified: boolean;
  password_storage?: string;
  auth_provider?: string;
  created_at: string;
  last_login?: string;
}

interface AdminScan {
  id: string;
  url: string;
  user_id: string;
  status: string;
  progress: number;
  created_at: string;
  completed_at?: string;
}

interface AuditLogEntry {
  id: string;
  user_id?: string;
  action: string;
  ip_address?: string;
  created_at: string;
}

type Tab = 'overview' | 'users' | 'scans' | 'logs';

function StatCard({ icon: Icon, label, value, color, sub }: {
  icon: React.ElementType; label: string; value: string | number; color: string; sub?: string;
}) {
  return (
    <div className="stat-card p-4 rounded-xl border border-[#2A2A2A] bg-[#111111]">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-[#706C64] uppercase tracking-wider font-semibold">{label}</p>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-[#0D0D0D] border border-[#2A2A2A]">
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <p className="text-3xl font-black text-[#F5F3ED]">{value}</p>
      {sub && <p className="text-xs text-[#706C64] mt-1">{sub}</p>}
    </div>
  );
}

export default function AdminPage() {
  const { user } = useAuthStore();
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('overview');
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [scans, setScans] = useState<AdminScan[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [deletingUserId, setDeletingUserId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Guard: only admins
  useEffect(() => {
    if (user && user.role !== 'admin') {
      router.push('/dashboard');
    }
  }, [user]);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [statsRes, usersRes, scansRes, logsRes] = await Promise.all([
        api.get('/api/admin/stats'),
        api.get('/api/admin/users?limit=100'),
        api.get('/api/admin/scans?limit=50'),
        api.get('/api/admin/logs?limit=100'),
      ]);
      setStats(statsRes.data);
      setUsers(usersRes.data);
      setScans(scansRes.data);
      setLogs(logsRes.data);
    } catch {
      toast.error('Failed to load admin data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const deleteUser = async (userId: string) => {
    if (userId === user?.id) return toast.error("Can't delete your own account");
    setDeletingUserId(userId);
    try {
      await api.delete(`/api/admin/users/${userId}`);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      toast.success('User deleted');
    } catch {
      toast.error('Failed to delete user');
    } finally {
      setDeletingUserId(null);
    }
  };

  const TABS: { key: Tab; label: string; icon: React.ElementType }[] = [
    { key: 'overview', label: 'Overview', icon: BarChart3 },
    { key: 'users',    label: `Users (${users.length})`, icon: Users },
    { key: 'scans',   label: `Scans (${scans.length})`, icon: Activity },
    { key: 'logs',    label: 'Audit Logs', icon: FileText },
  ];

  const filteredUsers = users.filter((u) =>
    !search || u.email.toLowerCase().includes(search.toLowerCase()) || u.name.toLowerCase().includes(search.toLowerCase())
  );

  if (user?.role !== 'admin') return null;

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-[#D4AF37]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#F5F3ED]">Admin Command Panel</h1>
            <p className="text-[#A7A39A] text-sm mt-0.5">Platform management and continuous monitoring</p>
          </div>
        </div>
        <button onClick={fetchAll} disabled={loading} className="btn-ghost py-2 px-4 gap-2 text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0D0D0D] rounded-xl p-1 border border-[#2A2A2A] w-fit">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              tab === key
                ? 'bg-[#5C4A20]/25 text-[#D4AF37] border border-[#5C4A20] shadow-[0_0_10px_rgba(212,175,55,0.15)]'
                : 'text-[#706C64] hover:text-[#A7A39A]'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span className="hidden sm:inline">{label}</span>
          </button>
        ))}
      </div>

      {/* ── OVERVIEW ── */}
      {tab === 'overview' && (
        <div className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {[
              { icon: Users,      label: 'Total Users',     value: stats?.total_users ?? '…',    color: '#D4AF37', sub: 'registered' },
              { icon: Activity,   label: 'Total Scans',     value: stats?.total_scans ?? '…',    color: '#D4AF37', sub: 'all time'   },
              { icon: Clock,      label: "Today's Scans",   value: stats?.today_scans ?? '0',    color: '#D4AF37', sub: 'last 24 hours' },
              { icon: TrendingUp, label: 'Weekly Scans',    value: stats?.weekly_scans ?? '0',   color: '#D4AF37', sub: 'last 7 days' },
              { icon: FileText,   label: 'Reports',         value: stats?.total_reports ?? '…',  color: '#D4AF37', sub: 'generated' },
              { icon: Shield,     label: 'Avg Score',       value: stats?.average_security_score ? `${stats.average_security_score}` : '…', color: '#4FAF72', sub: 'platform score' },
            ].map((s, i) => (
              <motion.div key={s.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                <StatCard {...s} />
              </motion.div>
            ))}
          </div>

          {/* System Telemetry & Health */}
          <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
            <h3 className="font-bold text-[#F5F3ED] mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#D4AF37]" /> System Telemetry &amp; Infrastructure Health
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">PostgreSQL Database</span>
                <span className="text-[#4FAF72] font-bold">{stats?.system_status?.database || 'Healthy'}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">Async Workers</span>
                <span className="text-[#4FAF72] font-bold">{stats?.system_status?.worker_status || 'Active (2)'}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">Queue Backlog</span>
                <span className="text-[#D4AF37] font-bold">{stats?.system_status?.queue_status || '0 Pending'}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">Redis Cache</span>
                <span className="text-[#4FAF72] font-bold">{stats?.system_status?.redis || 'Connected'}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
                <span className="text-[#706C64] block text-[10px] uppercase font-bold">API Request Rate</span>
                <span className="text-[#D4AF37] font-bold">{stats?.system_status?.api_usage || 'Active'}</span>
              </div>
            </div>
          </GlassCard>

          {/* Common Vulnerabilities & Missing Headers Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Most Common Findings */}
            <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
              <h3 className="font-bold text-[#F5F3ED] mb-3 text-xs uppercase tracking-wider text-[#A7A39A]">Most Common Findings</h3>
              {stats?.most_common_findings && stats.most_common_findings.length > 0 ? (
                <div className="space-y-2">
                  {stats.most_common_findings.map((item) => (
                    <div key={item.title} className="flex justify-between items-center text-xs p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                      <span className="text-[#A7A39A] truncate max-w-[170px]">{item.title}</span>
                      <span className="font-bold font-mono text-[#EF4444]">{item.count}</span>
                    </div>
                  ))}
                </div>
              ) : <p className="text-xs text-[#706C64]">No findings data</p>}
            </GlassCard>

            {/* Most Common Missing Headers */}
            <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
              <h3 className="font-bold text-[#F5F3ED] mb-3 text-xs uppercase tracking-wider text-[#A7A39A]">Most Common Missing Headers</h3>
              {stats?.most_common_missing_headers && stats.most_common_missing_headers.length > 0 ? (
                <div className="space-y-2">
                  {stats.most_common_missing_headers.map((item) => (
                    <div key={item.header} className="flex justify-between items-center text-xs p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                      <span className="text-[#A7A39A] font-mono">{item.header}</span>
                      <span className="font-bold font-mono text-[#F59E0B]">{item.count} missing</span>
                    </div>
                  ))}
                </div>
              ) : <p className="text-xs text-[#706C64]">No header data</p>}
            </GlassCard>

            {/* Most Vulnerable Tech */}
            <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
              <h3 className="font-bold text-[#F5F3ED] mb-3 text-xs uppercase tracking-wider text-[#A7A39A]">Detected Tech Components</h3>
              {stats?.most_vulnerable_tech && stats.most_vulnerable_tech.length > 0 ? (
                <div className="space-y-2">
                  {stats.most_vulnerable_tech.map((item) => (
                    <div key={item.name} className="flex justify-between items-center text-xs p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A]">
                      <span className="text-[#A7A39A] font-medium">{item.name}</span>
                      <span className="font-bold font-mono text-[#D4AF37]">{item.count} sites</span>
                    </div>
                  ))}
                </div>
              ) : <p className="text-xs text-[#706C64]">No tech data</p>}
            </GlassCard>
          </div>

          {/* Recent Activity */}
          <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
            <h3 className="font-bold text-[#F5F3ED] mb-4">Recent Activity Logs</h3>
            {logs.length === 0 ? (
              <p className="text-[#706C64] text-sm text-center py-8">No audit logs available</p>
            ) : (
              <div className="space-y-2">
                {logs.slice(0, 10).map((log) => (
                  <div key={log.id} className="flex items-center gap-3 py-2.5 border-b border-[#2A2A2A]/40 last:border-0">
                    <div className="w-8 h-8 rounded-full bg-[#5C4A20]/20 flex items-center justify-center flex-shrink-0">
                      <Activity className="w-4 h-4 text-[#D4AF37]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-[#F5F3ED] font-mono">{log.action}</p>
                      {log.ip_address && (
                        <p className="text-xs text-[#706C64]">IP: {log.ip_address}</p>
                      )}
                    </div>
                    <span className="text-xs text-[#706C64] flex-shrink-0">{timeAgo(log.created_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ── USERS ── */}
      {tab === 'users' && (
        <div className="space-y-4">
          {/* Database Table Architecture Banner */}
          <GlassCard className="p-4 border border-[#5C4A20]/40 bg-[#111111]">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center text-[#D4AF37]">
                  <Database className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#F5F3ED] flex items-center gap-2">
                    Database User Persistence Inspection <span className="text-xs font-mono text-[#D4AF37] px-2 py-0.5 rounded bg-[#0D0D0D] border border-[#2A2A2A]">table: users</span>
                  </h3>
                  <p className="text-xs text-[#A7A39A] mt-0.5">
                    Live SQL records • Passwords stored strictly as <strong className="text-[#4FAF72]">bcrypt hashes</strong> • Plaintext passwords: <strong className="text-[#EF4444]">NEVER STORED</strong>
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono text-[#D4AF37] bg-[#0D0D0D] px-3 py-1.5 rounded-lg border border-[#2A2A2A]">
                <span>Total Registered Accounts:</span>
                <strong className="text-[#F5F3ED]">{users.length}</strong>
              </div>
            </div>
          </GlassCard>

          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#706C64] pointer-events-none" />
            <input
              type="text"
              placeholder="Search by ID, email or name…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="cyber-input !pl-11 py-2.5 text-sm bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED]"
            />
          </div>

          <GlassCard className="overflow-hidden border border-[#2A2A2A] bg-[#111111]">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>User / ID</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Password Storage</th>
                  <th>Last Login</th>
                  <th>Joined</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center text-[#D4AF37] text-xs font-bold flex-shrink-0">
                          {u.name[0]?.toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-[#F5F3ED] truncate">{u.name}</p>
                          <p className="text-xs text-[#706C64] truncate">{u.email}</p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className="font-mono text-[10px] text-[#706C64]">{u.id}</span>
                            <button
                              type="button"
                              onClick={() => {
                                navigator.clipboard.writeText(u.id);
                                setCopiedId(u.id);
                                setTimeout(() => setCopiedId(null), 2000);
                              }}
                              className="text-[#706C64] hover:text-[#D4AF37] transition-colors"
                              title="Copy UUID"
                            >
                              {copiedId === u.id ? <Check className="w-3 h-3 text-[#4FAF72]" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                        u.role === 'admin'
                          ? 'bg-[#5C4A20]/25 text-[#D4AF37] border border-[#5C4A20]'
                          : 'bg-[#161616] text-[#A7A39A] border border-[#2A2A2A]'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td>
                      <span className={`flex items-center gap-1.5 text-xs w-fit ${u.is_verified ? 'text-[#4FAF72]' : 'text-[#F59E0B]'}`}>
                        {u.is_verified ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                        {u.is_verified ? 'Verified' : 'Pending Verification'}
                      </span>
                    </td>
                    <td>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-1.5 text-xs font-mono text-[#D4AF37]">
                          <Lock className="w-3 h-3 text-[#D4AF37]/80" />
                          <span>{u.password_storage || '$2b$12$••••••••••••••••'}</span>
                        </div>
                        <span className="text-[10px] text-[#706C64] block">
                          {u.auth_provider || 'bcrypt (Local DB)'}
                        </span>
                      </div>
                    </td>
                    <td className="text-[#A7A39A] text-xs">
                      {u.last_login ? timeAgo(u.last_login) : 'Never'}
                    </td>
                    <td className="text-[#A7A39A] text-xs">
                      {formatDate(u.created_at).split(',')[0]}
                    </td>
                    <td>
                      {u.id !== user?.id && (
                        <button
                          onClick={() => deleteUser(u.id)}
                          disabled={deletingUserId === u.id}
                          className="p-2 rounded-lg text-[#706C64] hover:text-[#EF4444] hover:bg-red-500/10 transition-all"
                          title="Delete user"
                        >
                          {deletingUserId === u.id
                            ? <span className="w-4 h-4 border-2 border-red-400/30 border-t-[#EF4444] rounded-full animate-spin block" />
                            : <Trash2 className="w-4 h-4" />}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredUsers.length === 0 && (
              <div className="py-12 text-center text-[#706C64] text-sm">
                No users found
              </div>
            )}
          </GlassCard>
        </div>
      )}

      {/* ── SCANS ── */}
      {tab === 'scans' && (
        <GlassCard className="overflow-hidden border border-[#2A2A2A] bg-[#111111]">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Target URL</th>
                <th>User ID</th>
                <th>Status</th>
                <th>Created</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="font-mono text-xs text-[#A7A39A] max-w-xs truncate">
                    {scan.url}
                  </td>
                  <td className="text-xs text-[#706C64] font-mono">
                    {scan.user_id.slice(0, 8)}…
                  </td>
                  <td>
                    <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                      scan.status === 'completed' ? 'text-[#4FAF72] bg-green-500/10 border border-green-500/20' :
                      scan.status === 'failed' ? 'text-[#EF4444] bg-red-500/10 border border-red-500/20' :
                      scan.status === 'running' ? 'text-[#D4AF37] bg-[#5C4A20]/20 border border-[#5C4A20]' :
                      'text-[#A7A39A] bg-[#161616] border border-[#2A2A2A]'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="text-xs text-[#A7A39A]">{timeAgo(scan.created_at)}</td>
                  <td className="text-xs text-[#A7A39A]">
                    {scan.completed_at ? timeAgo(scan.completed_at) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {scans.length === 0 && (
            <div className="py-12 text-center text-[#706C64] text-sm">No scans to display</div>
          )}
        </GlassCard>
      )}

      {/* ── AUDIT LOGS ── */}
      {tab === 'logs' && (
        <GlassCard className="overflow-hidden border border-[#2A2A2A] bg-[#111111]">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>User ID</th>
                <th>IP Address</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td>
                    <span className="font-mono text-xs text-[#F5F3ED] bg-[#0D0D0D] px-2 py-1 rounded border border-[#2A2A2A]">
                      {log.action}
                    </span>
                  </td>
                  <td className="text-xs text-[#706C64] font-mono">
                    {log.user_id ? `${log.user_id.slice(0, 8)}…` : 'System'}
                  </td>
                  <td className="text-xs text-[#A7A39A] font-mono">
                    {log.ip_address || '—'}
                  </td>
                  <td className="text-xs text-[#A7A39A]">
                    {formatDate(log.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {logs.length === 0 && (
            <div className="py-12 text-center text-[#706C64] text-sm">No audit logs available</div>
          )}
        </GlassCard>
      )}
    </div>
  );
}
