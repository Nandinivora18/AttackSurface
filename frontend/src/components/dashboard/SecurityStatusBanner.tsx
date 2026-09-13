'use client';
import { AlertTriangle, ShieldCheck, ShieldAlert, AlertCircle } from 'lucide-react';

interface SecurityStatusBannerProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  hasScans: boolean;
}

export default function SecurityStatusBanner({
  critical,
  high,
  medium,
  low,
  info,
  hasScans,
}: SecurityStatusBannerProps) {
  if (!hasScans) return null;

  const total = critical + high + medium + low + info;

  type StatusConfig = {
    label: string;
    sublabel: string;
    color: string;
    bg: string;
    border: string;
    dot: string;
    Icon: React.ElementType;
  };

  let cfg: StatusConfig;

  if (critical > 0) {
    cfg = {
      label: 'Critical Risk',
      sublabel: `${critical} critical finding${critical > 1 ? 's' : ''} require immediate attention`,
      color: 'text-red-400',
      bg: 'bg-red-500/8',
      border: 'border-red-500/25',
      dot: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.7)]',
      Icon: ShieldAlert,
    };
  } else if (high > 0) {
    cfg = {
      label: 'Attention Required',
      sublabel: `${high} high-severity finding${high > 1 ? 's' : ''} need review`,
      color: 'text-orange-400',
      bg: 'bg-orange-500/8',
      border: 'border-orange-500/25',
      dot: 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)]',
      Icon: AlertTriangle,
    };
  } else if (medium > 0) {
    cfg = {
      label: 'Review Recommended',
      sublabel: `${medium} medium-severity finding${medium > 1 ? 's' : ''} identified`,
      color: 'text-amber-400',
      bg: 'bg-amber-500/8',
      border: 'border-amber-500/25',
      dot: 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]',
      Icon: AlertCircle,
    };
  } else {
    cfg = {
      label: 'No High/Critical Findings',
      sublabel: total > 0
        ? `${low + info} low/informational finding${low + info > 1 ? 's' : ''} — security posture is acceptable`
        : 'Latest assessment found no significant issues',
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/8',
      border: 'border-emerald-500/20',
      dot: 'bg-emerald-500 shadow-[0_0_8px_rgba(79,175,114,0.5)]',
      Icon: ShieldCheck,
    };
  }

  const { label, sublabel, color, bg, border, dot, Icon } = cfg;

  return (
    <div
      role="status"
      aria-label={`Security status: ${label}`}
      className={`flex items-center gap-3 px-4 py-3 rounded-[12px] border ${bg} ${border} transition-all`}
    >
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dot}`} aria-hidden="true" />
      <Icon className={`w-3.5 h-3.5 ${color} flex-shrink-0`} aria-hidden="true" />
      <div className="flex items-center gap-2 min-w-0">
        <span className={`text-xs font-bold ${color} uppercase tracking-wider flex-shrink-0`}>
          Security Status
        </span>
        <span className="text-[#4A4A4A] hidden sm:block" aria-hidden="true">·</span>
        <span className={`text-xs font-semibold ${color} flex-shrink-0`}>{label}</span>
        <span className="text-[#4A4A4A] hidden md:block" aria-hidden="true">—</span>
        <span className="text-xs text-[#6F6F6F] truncate hidden md:block">{sublabel}</span>
      </div>
    </div>
  );
}
