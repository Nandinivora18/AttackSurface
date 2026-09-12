'use client';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  User, Key, Lock, Eye, EyeOff, Save,
  Globe, Trash2
} from 'lucide-react';
import { useAuthStore } from '@/store';
import api from '@/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import { PageHeader } from '@/components/ui/PageHeader';
import { SectionCard } from '@/components/ui/SectionCard';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

/* ── Schemas ── */
const profileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
});

const passwordSchema = z.object({
  current_password: z.string().min(1, 'Current password is required'),
  new_password: z.string().min(8, 'At least 8 characters')
    .regex(/[A-Z]/, 'Needs an uppercase letter')
    .regex(/[0-9]/, 'Needs a digit'),
  confirm_password: z.string(),
}).refine((d) => d.new_password === d.confirm_password, {
  message: 'Passwords do not match', path: ['confirm_password'],
});

const setPasswordSchema = z.object({
  new_password: z.string().min(8, 'At least 8 characters')
    .regex(/[A-Z]/, 'Needs an uppercase letter')
    .regex(/[0-9]/, 'Needs a digit'),
  confirm_password: z.string(),
}).refine((d) => d.new_password === d.confirm_password, {
  message: 'Passwords do not match', path: ['confirm_password'],
});

type ProfileForm = z.infer<typeof profileSchema>;
type PasswordForm = z.infer<typeof passwordSchema>;
type SetPasswordForm = z.infer<typeof setPasswordSchema>;

function getInitials(name: string): string {
  const parts = name.trim().split(' ');
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return parts[0].slice(0, 2).toUpperCase();
}

export default function ProfilePage() {
  const { user, setUser, logout } = useAuthStore();
  const router = useRouter();

  const [showPassword, setShowPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [deletingAccount, setDeletingAccount] = useState(false);

  const profileForm = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: { name: user?.name || '' },
  });

  const passwordForm = useForm<PasswordForm>({ resolver: zodResolver(passwordSchema) });
  const setPasswordForm = useForm<SetPasswordForm>({ resolver: zodResolver(setPasswordSchema) });

  const onSaveProfile = async (data: ProfileForm) => {
    try {
      const res = await api.put('/api/users/me', { name: data.name });
      setUser(res.data);
      toast.success('Profile updated successfully');
    } catch {
      toast.error('Failed to update profile');
    }
  };

  const onChangePassword = async (data: PasswordForm) => {
    try {
      await api.put('/api/users/me/password', {
        current_password: data.current_password,
        new_password: data.new_password,
      });
      toast.success('Password changed successfully');
      passwordForm.reset();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to change password');
    }
  };

  const onSetPassword = async (data: SetPasswordForm) => {
    try {
      await api.post('/api/users/me/password/set', { new_password: data.new_password });
      toast.success('Password configured!');
      setPasswordForm.reset();
      const meRes = await api.get('/api/users/me');
      setUser(meRes.data);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to configure password');
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteConfirm !== 'DELETE') return;
    setDeletingAccount(true);
    try {
      await api.delete('/api/users/me');
      await logout();
      toast.success('Account deleted');
      router.push('/');
    } catch {
      toast.error('Failed to delete account');
      setDeletingAccount(false);
    }
  };

  const isGoogleAccount = Boolean(user?.google_id);
  const hasPassword = !isGoogleAccount;

  return (
    <div className="max-w-4xl mx-auto space-y-8 page-enter">
      <PageHeader
        title="Profile & Account Settings"
        icon={User}
        subtitle="Manage your personal identity and security credentials."
      />

      {/* ── 1. Personal Information ── */}
      <SectionCard icon={User} title="Personal Information" subtitle="User identity and account email">
        {/* User Identity Display */}
        <div className="flex items-center gap-5 p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] mb-6">
          <div className="w-14 h-14 rounded-full bg-gradient-to-br from-[#1A1A1A] to-[#0D0D0D] border border-[#5C4A20] text-[#D4AF37] font-black text-xl flex items-center justify-center flex-shrink-0 shadow-[0_0_12px_rgba(212,175,55,0.25)]">
            {getInitials(user?.name || 'U')}
          </div>
          <div className="space-y-1 min-w-0">
            <h3 className="font-bold text-[#F5F3ED] text-base truncate">{user?.name || 'Security Auditor'}</h3>
            <p className="text-xs text-[#A7A39A] font-mono truncate">{user?.email}</p>
            <div className="flex items-center gap-2 pt-0.5">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[#161616] border border-[#2A2A2A] text-[#D4AF37]">
                {user?.role || 'user'}
              </span>
            </div>
          </div>
        </div>

        {/* Profile name form */}
        <form onSubmit={profileForm.handleSubmit(onSaveProfile)} className="space-y-4 max-w-md">
          <Input
            label="Display Name"
            type="text"
            error={profileForm.formState.errors.name?.message}
            {...profileForm.register('name')}
          />
          <Input
            label="Email Address"
            type="email"
            value={user?.email || ''}
            disabled
            hint="Email cannot be modified directly."
          />
          <Button type="submit" variant="primary" size="sm" leftIcon={Save}>
            Save Changes
          </Button>
        </form>
      </SectionCard>

      {/* ── 2. Security & Authentication ── */}
      <SectionCard icon={Key} title="Account Security & Authentication" subtitle="Manage credentials and authentication methods">
        {/* Auth method status */}
        <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] mb-6 space-y-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#A7A39A]">Authentication Methods</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-[#111111] border border-[#2A2A2A] flex items-center justify-between">
              <span className="text-sm font-medium text-[#F5F3ED] flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#D4AF37]" aria-hidden /> Google OAuth
              </span>
              {isGoogleAccount
                ? <Badge variant="success">Connected</Badge>
                : <span className="text-xs text-[#706C64]">Not linked</span>
              }
            </div>
            <div className="p-3 rounded-lg bg-[#111111] border border-[#2A2A2A] flex items-center justify-between">
              <span className="text-sm font-medium text-[#F5F3ED] flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#D4AF37]" aria-hidden /> Password
              </span>
              {hasPassword
                ? <Badge variant="champagne">Configured</Badge>
                : <Badge variant="warning">Not Configured</Badge>
              }
            </div>
          </div>
        </div>

        {/* Password form */}
        {hasPassword ? (
          <form onSubmit={passwordForm.handleSubmit(onChangePassword)} className="space-y-4 max-w-md" noValidate>
            <p className="text-xs font-semibold uppercase tracking-wider text-[#A7A39A] mb-4">Change Password</p>
            <Input
              label="Current Password"
              type={showPassword ? 'text' : 'password'}
              error={passwordForm.formState.errors.current_password?.message}
              autoComplete="current-password"
              rightElement={
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="text-[#706C64] hover:text-[#F5F3ED] transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              }
              {...passwordForm.register('current_password')}
            />
            <Input
              label="New Password"
              type={showNewPassword ? 'text' : 'password'}
              error={passwordForm.formState.errors.new_password?.message}
              autoComplete="new-password"
              rightElement={
                <button
                  type="button"
                  onClick={() => setShowNewPassword((s) => !s)}
                  className="text-[#706C64] hover:text-[#F5F3ED] transition-colors"
                  aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}
                >
                  {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              }
              {...passwordForm.register('new_password')}
            />
            <Input
              label="Confirm New Password"
              type="password"
              error={passwordForm.formState.errors.confirm_password?.message}
              autoComplete="new-password"
              {...passwordForm.register('confirm_password')}
            />
            <Button type="submit" variant="primary" size="sm" leftIcon={Key}>
              Update Password
            </Button>
          </form>
        ) : (
          <form onSubmit={setPasswordForm.handleSubmit(onSetPassword)} className="space-y-4 max-w-md" noValidate>
            <div className="p-3 rounded-lg bg-[#5C4A20]/20 border border-[#5C4A20] text-xs text-[#D4AF37] mb-4">
              Your account authenticates via Google OAuth. You can optionally set a local password.
            </div>
            <Input
              label="New Password"
              type="password"
              error={setPasswordForm.formState.errors.new_password?.message}
              autoComplete="new-password"
              {...setPasswordForm.register('new_password')}
            />
            <Input
              label="Confirm Password"
              type="password"
              error={setPasswordForm.formState.errors.confirm_password?.message}
              autoComplete="new-password"
              {...setPasswordForm.register('confirm_password')}
            />
            <Button type="submit" variant="primary" size="sm" leftIcon={Key}>
              Set Password
            </Button>
          </form>
        )}
      </SectionCard>

      {/* ── 3. Danger Zone ── */}
      <SectionCard icon={Trash2} title="Danger Zone" subtitle="Irreversible account deletion" accent="red">
        <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20 space-y-4">
          <div>
            <h3 className="font-semibold text-[#F5F3ED] text-sm">Delete Account</h3>
            <p className="text-xs text-[#A7A39A] mt-1">
              Permanently delete your account, saved targets, reports, and scan history.
            </p>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <Input
              type="text"
              placeholder='Type "DELETE" to confirm'
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              inputSize="sm"
              wrapperClassName="w-56"
              aria-label='Type DELETE to confirm account deletion'
            />
            <Button
              variant="danger"
              size="sm"
              loading={deletingAccount}
              disabled={deleteConfirm !== 'DELETE'}
              onClick={handleDeleteAccount}
              className="bg-red-600 hover:bg-red-500 text-white border-0"
            >
              {deletingAccount ? 'Deleting…' : 'Delete My Account'}
            </Button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
