'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Users, Search, Trash2, Database, Lock, Copy, Check,
  RefreshCw, AlertTriangle, CheckCircle, ArrowLeft, ShieldAlert
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import { useAuthStore } from '@/store';
import api from '@/lib/api';
import { formatDate, timeAgo } from '@/lib/utils';
import toast from 'react-hot-toast';

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

export default function AdminUsersPage() {
  const { user } = useAuthStore();
  const router = useRouter();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [deletingUserId, setDeletingUserId] = useState<string | null>(null);

  // Guard: only admins
  useEffect(() => {
    if (user && user.role !== 'admin') {
      router.push('/dashboard');
    }
  }, [user, router]);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await api.get<AdminUser[]>('/api/admin/users?limit=100');
      setUsers(res.data);
    } catch {
      toast.error('Failed to load users from database');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const deleteUser = async (userId: string) => {
    if (userId === user?.id) return toast.error("Cannot delete your own administrator account");
    setDeletingUserId(userId);
    try {
      await api.delete(`/api/admin/users/${userId}`);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
      toast.success('User account removed from database');
    } catch {
      toast.error('Failed to delete user');
    } finally {
      setDeletingUserId(null);
    }
  };

  const filteredUsers = users.filter((u) =>
    !search ||
    u.id.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase()) ||
    u.name.toLowerCase().includes(search.toLowerCase())
  );

  if (user?.role !== 'admin') return null;

  return (
    <div className="space-y-6 page-enter max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Link
            href="/admin"
            className="w-10 h-10 rounded-xl bg-[#111111] border border-[#2A2A2A] flex items-center justify-center text-[#706C64] hover:text-[#D4AF37] hover:border-[#5C4A20] transition-all"
            title="Back to Admin Center"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-[#F5F3ED] flex items-center gap-2">
              <Database className="w-6 h-6 text-[#D4AF37]" />
              Database Users Inspection
            </h1>
            <p className="text-[#A7A39A] text-sm mt-0.5">
              Live inspection of registered user records in the SentinelScan SQL database
            </p>
          </div>
        </div>
        <button
          onClick={fetchUsers}
          disabled={loading}
          className="btn-ghost py-2 px-4 gap-2 text-sm flex items-center border border-[#2A2A2A] text-[#F5F3ED] hover:border-[#5C4A20]"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh Database
        </button>
      </div>

      {/* Database Persistence Architecture Banner */}
      <GlassCard className="p-5 border border-[#5C4A20]/40 bg-[#111111]">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center text-[#D4AF37] flex-shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-[#F5F3ED]">Users Database Table</h3>
                <span className="text-xs font-mono text-[#D4AF37] px-2.5 py-0.5 rounded-full bg-[#0D0D0D] border border-[#5C4A20]/40">
                  SQL Table: users
                </span>
              </div>
              <p className="text-xs text-[#A7A39A] mt-1">
                Authentication Storage: Passwords cryptographically hashed using <strong className="text-[#4FAF72]">bcrypt</strong> (work factor 12) • Plaintext passwords: <strong className="text-[#EF4444]">NEVER STORED</strong>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="bg-[#0D0D0D] px-3.5 py-2 rounded-xl border border-[#2A2A2A] flex items-center gap-2">
              <span className="text-[#706C64]">Total Database Rows:</span>
              <strong className="text-[#D4AF37] font-bold text-sm">{users.length}</strong>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Search Input */}
      <div className="relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[#706C64] pointer-events-none" />
        <input
          type="text"
          placeholder="Filter by UUID, email, or name…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="cyber-input !pl-11 py-2.5 text-sm bg-[#0D0D0D] border-[#2A2A2A] text-[#F5F3ED] w-full rounded-xl"
        />
      </div>

      {/* Users Database Table */}
      <GlassCard className="overflow-hidden border border-[#2A2A2A] bg-[#111111]">
        <div className="overflow-x-auto">
          <table className="cyber-table w-full">
            <thead>
              <tr>
                <th>ID (UUID)</th>
                <th>Name &amp; Email</th>
                <th>Role</th>
                <th>Account Status</th>
                <th>Password Storage</th>
                <th>Last Login</th>
                <th>Created At</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((u) => (
                <tr key={u.id}>
                  {/* UUID Column */}
                  <td className="font-mono text-xs text-[#A7A39A]">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate max-w-[140px]" title={u.id}>
                        {u.id}
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(u.id);
                          setCopiedId(u.id);
                          setTimeout(() => setCopiedId(null), 2000);
                        }}
                        className="text-[#706C64] hover:text-[#D4AF37] transition-colors p-1"
                        title="Copy complete UUID"
                      >
                        {copiedId === u.id ? (
                          <Check className="w-3.5 h-3.5 text-[#4FAF72]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </td>

                  {/* Name and Email */}
                  <td>
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] flex items-center justify-center text-[#D4AF37] text-xs font-bold flex-shrink-0">
                        {u.name[0]?.toUpperCase() || 'U'}
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-[#F5F3ED] truncate">{u.name}</p>
                        <p className="text-xs text-[#706C64] truncate">{u.email}</p>
                      </div>
                    </div>
                  </td>

                  {/* Role */}
                  <td>
                    <span
                      className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                        u.role === 'admin'
                          ? 'bg-[#5C4A20]/25 text-[#D4AF37] border border-[#5C4A20]'
                          : 'bg-[#161616] text-[#A7A39A] border border-[#2A2A2A]'
                      }`}
                    >
                      {u.role}
                    </span>
                  </td>

                  {/* Account Status */}
                  <td>
                    <span
                      className={`flex items-center gap-1.5 text-xs w-fit ${
                        u.is_verified ? 'text-[#4FAF72]' : 'text-[#F59E0B]'
                      }`}
                    >
                      {u.is_verified ? (
                        <CheckCircle className="w-3.5 h-3.5" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      )}
                      {u.is_verified ? 'Verified' : 'Pending Verification'}
                    </span>
                  </td>

                  {/* Password Storage Representation */}
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

                  {/* Last Login */}
                  <td className="text-[#A7A39A] text-xs">
                    {u.last_login ? timeAgo(u.last_login) : 'Never'}
                  </td>

                  {/* Created At */}
                  <td className="text-[#A7A39A] text-xs">
                    {formatDate(u.created_at).split(',')[0]}
                  </td>

                  {/* Actions */}
                  <td>
                    {u.id !== user?.id && (
                      <button
                        onClick={() => deleteUser(u.id)}
                        disabled={deletingUserId === u.id}
                        className="p-2 rounded-lg text-[#706C64] hover:text-[#EF4444] hover:bg-red-500/10 transition-all"
                        title="Delete user record from database"
                      >
                        {deletingUserId === u.id ? (
                          <span className="w-4 h-4 border-2 border-red-400/30 border-t-[#EF4444] rounded-full animate-spin block" />
                        ) : (
                          <Trash2 className="w-4 h-4" />
                        )}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredUsers.length === 0 && (
          <div className="py-12 text-center text-[#706C64] text-sm">
            No registered users found in the database.
          </div>
        )}
      </GlassCard>
    </div>
  );
}
