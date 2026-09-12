'use client';
import { useState } from 'react';
import {
  Bell, Moon, Sun, Monitor, Sliders,
  CheckCircle,
} from 'lucide-react';
import { useUIStore, ThemeMode } from '@/store';
import { PageHeader } from '@/components/ui/PageHeader';
import { SectionCard } from '@/components/ui/SectionCard';
import { Button } from '@/components/ui/Button';
import toast from 'react-hot-toast';

/* ── Reusable Toggle Row ── */
interface ToggleRowProps {
  id: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description: string;
  disabled?: boolean;
}

function ToggleRow({
  id, enabled, onChange, label, description, disabled,
}: ToggleRowProps) {
  return (
    <div className={`flex items-center justify-between py-4 first:pt-0 last:pb-0 ${disabled ? 'opacity-60' : ''}`}>
      <div className="flex-1 mr-6">
        <label htmlFor={id} className="text-sm font-medium text-[#F5F3ED] cursor-pointer block">
          {label}
        </label>
        <p className="text-xs text-[#706C64] mt-0.5">{description}</p>
      </div>
      <button
        id={id}
        role="switch"
        aria-checked={enabled}
        onClick={() => !disabled && onChange(!enabled)}
        disabled={disabled}
        className={[
          'toggle-track flex-shrink-0',
          disabled ? 'cursor-not-allowed opacity-40' : 'cursor-pointer',
        ].join(' ')}
        aria-label={label}
      >
        <span className="toggle-thumb" />
      </button>
    </div>
  );
}

export default function SettingsPage() {
  const { theme, setTheme } = useUIStore();

  const [emailScanComplete, setEmailScanComplete] = useState(true);
  const [emailSecurityAlerts, setEmailSecurityAlerts] = useState(true);

  const handleSaveSettings = () => toast.success('Settings saved successfully');

  return (
    <div className="max-w-4xl mx-auto space-y-8 page-enter">
      <PageHeader
        title="Settings & Preferences"
        icon={Sliders}
        subtitle="Customize platform appearance and automated notification triggers."
        actions={
          <Button variant="primary" size="md" leftIcon={CheckCircle} onClick={handleSaveSettings}>
            Save Settings
          </Button>
        }
      />

      {/* ── 1. Appearance ── */}
      <SectionCard icon={Sun} title="Appearance & Theme Mode" subtitle="Choose your preferred interface theme">
        <div className="py-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-[#A7A39A] mb-3">Theme Mode</p>
          <div className="grid grid-cols-3 gap-3">
            {[
              { id: 'light' as ThemeMode, label: 'Light', icon: Sun },
              { id: 'dark'  as ThemeMode, label: 'Dark',  icon: Moon },
              { id: 'system' as ThemeMode, label: 'System', icon: Monitor },
            ].map((mode) => {
              const active = theme === mode.id;
              return (
                <button
                  key={mode.id}
                  onClick={() => setTheme(mode.id)}
                  aria-pressed={active}
                  className={[
                    'h-12 rounded-[10px] border text-sm font-semibold flex items-center justify-center gap-2 transition-all',
                    active
                      ? 'bg-[#5C4A20]/25 text-[#F5F3ED] border-[#5C4A20] shadow-[0_0_12px_rgba(212,175,55,0.15)]'
                      : 'bg-[#0D0D0D] text-[#706C64] border-[#2A2A2A] hover:text-[#F5F3ED] hover:border-[#5C4A20]/50',
                  ].join(' ')}
                >
                  <mode.icon className={`w-4 h-4 ${active ? 'text-[#D4AF37]' : 'text-[#706C64]'}`} aria-hidden />
                  {mode.label}
                </button>
              );
            })}
          </div>
        </div>
      </SectionCard>

      {/* ── 2. Notifications ── */}
      <SectionCard icon={Bell} title="Notifications & Alert Channels" subtitle="Control email notifications and vulnerability alert triggers">
        <div className="divide-y divide-[#2A2A2A]/60">
          <ToggleRow
            id="email-complete"
            enabled={emailScanComplete}
            onChange={setEmailScanComplete}
            label="Scan Completion Emails"
            description="Receive an email summary whenever an automated scan completes"
          />
          <ToggleRow
            id="email-alerts"
            enabled={emailSecurityAlerts}
            onChange={setEmailSecurityAlerts}
            label="Critical Vulnerability Alerts"
            description="Immediate email notification when a new Critical or High severity issue is detected"
          />
        </div>
      </SectionCard>
    </div>
  );
}
