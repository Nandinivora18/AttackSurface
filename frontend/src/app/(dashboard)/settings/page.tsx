'use client';
import { useState } from 'react';
import {
  Bell, Moon, Sliders,
  CheckCircle,
} from 'lucide-react';
import { useUIStore } from '@/store';
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
  const { sidebarOpen } = useUIStore();

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
      <SectionCard icon={Moon} title="Appearance" subtitle="Interface theme configuration">
        <div className="py-2 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] flex items-center justify-center">
            <Moon className="w-4 h-4 text-[#D4AF37]" aria-hidden />
          </div>
          <div>
            <p className="text-sm font-semibold text-[#F5F3ED]">Dark Mode</p>
            <p className="text-xs text-[#706C64]">SentinelScan uses a permanent dark theme. No other mode is available.</p>
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
