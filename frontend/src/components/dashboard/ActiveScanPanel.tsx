'use client';
import Link from 'next/link';
import { ArrowRight, Activity } from 'lucide-react';
import { Scan } from '@/types';
import { timeAgo } from '@/lib/utils';

const STAGE_ORDER = [
  { key: 'dns', label: 'DNS Analysis' },
  { key: 'ssl', label: 'TLS / SSL' },
  { key: 'headers', label: 'Security Headers' },
  { key: 'technology', label: 'Technology Detection' },
  { key: 'owasp', label: 'OWASP Assessment' },
  { key: 'report', label: 'Report Generation' },
];

interface ActiveScanPanelProps {
  scan: Scan;
}

export default function ActiveScanPanel({ scan }: ActiveScanPanelProps) {
  // Build stage status from timeline
  const timeline = scan.timeline ?? [];
  const getStageStatus = (key: string) => {
    const item = timeline.find(
      (t) => t.stage?.toLowerCase().includes(key) || t.label?.toLowerCase().includes(key)
    );
    return item?.status ?? 'pending';
  };

  return (
    <div className="relative rounded-[16px] border border-[#D4AF37]/25 bg-[#0C0C0C] overflow-hidden">
      {/* Animated top accent */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#D4AF37]/60 to-transparent animate-pulse" />

      <div className="p-6 sm:p-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#D4AF37]/15 border border-[#D4AF37]/30 flex items-center justify-center">
              <Activity className="w-4 h-4 text-[#D4AF37] animate-pulse" aria-hidden="true" />
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
                Scan In Progress
              </p>
              <p className="font-mono text-sm font-semibold text-[#F5F5F5] mt-0.5 truncate max-w-[280px]">
                {scan.url}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-[#6F6F6F]">
            <span>{timeAgo(scan.created_at)}</span>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-[#6F6F6F]">{scan.current_stage ?? 'Processing…'}</span>
            <span className="text-[10px] font-bold text-[#D4AF37]">{scan.progress ?? 0}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[#1A1A1A] overflow-hidden">
            <div
              className="h-full rounded-full bg-[#D4AF37] transition-all duration-700"
              style={{ width: `${scan.progress ?? 0}%` }}
              role="progressbar"
              aria-valuenow={scan.progress ?? 0}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Scan progress"
            />
          </div>
        </div>

        {/* Stage pipeline */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-6">
          {STAGE_ORDER.map((stage) => {
            const stageStatus = getStageStatus(stage.key);
            return (
              <div
                key={stage.key}
                className={`flex items-center gap-2 p-2.5 rounded-[8px] border text-[11px] ${
                  stageStatus === 'completed'
                    ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400'
                    : stageStatus === 'running'
                    ? 'border-[#D4AF37]/30 bg-[#D4AF37]/8 text-[#D4AF37]'
                    : stageStatus === 'failed'
                    ? 'border-red-500/20 bg-red-500/8 text-red-400'
                    : 'border-[rgba(255,255,255,0.05)] bg-[#080808] text-[#4A4A4A]'
                }`}
              >
                <span aria-hidden="true">
                  {stageStatus === 'completed' ? '✓' : stageStatus === 'running' ? '◉' : stageStatus === 'failed' ? '✗' : '○'}
                </span>
                <span className="font-medium truncate">{stage.label}</span>
              </div>
            );
          })}
        </div>

        <Link
          href={`/scan?id=${scan.id}`}
          className="flex items-center justify-center gap-2 w-full py-2.5 rounded-[10px] bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-bold transition-all group"
          aria-label="View scan progress in detail"
        >
          View Live Progress
          <ArrowRight className="w-3 h-3 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </Link>
      </div>
    </div>
  );
}
