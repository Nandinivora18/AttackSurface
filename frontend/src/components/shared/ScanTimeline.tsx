'use client';
import { motion } from 'framer-motion';
import {
  Clock, CheckCircle2, AlertTriangle, Loader2,
  Globe, Lock, ShieldCheck, Cpu, Bug, Search, Award, Flag,
} from 'lucide-react';
import { StageTimelineItem } from '@/types';

const STAGE_ICONS: Record<string, any> = {
  queued: Clock,
  initializing: Loader2,
  dns: Globe,
  ssl: Lock,
  headers: ShieldCheck,
  technology: Cpu,
  cve: Bug,
  content: Search,
  scoring: Award,
  completed: Flag,
};

interface ScanTimelineProps {
  timeline?: StageTimelineItem[];
  currentStage?: string;
  progress?: number;
}

const DEFAULT_STAGES: StageTimelineItem[] = [
  { stage: 'queued', label: 'Queued', status: 'completed', duration_ms: 120 },
  { stage: 'initializing', label: 'Initializing Engine', status: 'completed', duration_ms: 250 },
  { stage: 'dns', label: 'DNS Analysis', status: 'completed', duration_ms: 410 },
  { stage: 'ssl', label: 'SSL / TLS Handshake', status: 'completed', duration_ms: 820 },
  { stage: 'headers', label: 'Security Headers Inspection', status: 'completed', duration_ms: 350 },
  { stage: 'technology', label: 'Technology Stack Detection', status: 'completed', duration_ms: 680 },
  { stage: 'cve', label: 'CVE Database Query', status: 'completed', duration_ms: 940 },
  { stage: 'content', label: 'Content & Endpoint Probing', status: 'completed', duration_ms: 530 },
  { stage: 'scoring', label: '7-Category Scoring Engine', status: 'completed', duration_ms: 180 },
  { stage: 'completed', label: 'Report Generation Complete', status: 'completed', duration_ms: 90 },
];

export default function ScanTimeline({ timeline, currentStage, progress = 100 }: ScanTimelineProps) {
  const items = (timeline && timeline.length > 0) ? timeline : DEFAULT_STAGES;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-bold text-[#F5F3ED] text-sm flex items-center gap-2">
          <Clock className="w-4 h-4 text-[#D4AF37]" /> Scan Execution Timeline
        </h3>
        <span className="text-xs text-[#706C64] font-mono">10 Assessment Stages</span>
      </div>

      <div className="relative border-l-2 border-[#2A2A2A] ml-4 space-y-4 py-1">
        {items.map((item, idx) => {
          const Icon = STAGE_ICONS[item.stage] || Clock;
          const isDone = item.status === 'completed' || (progress === 100);
          const isCurrent = !isDone && (item.status === 'running' || currentStage?.toLowerCase().includes(item.stage));

          return (
            <motion.div
              key={item.stage || idx}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.04 }}
              className="relative pl-6 flex items-center justify-between group"
            >
              {/* Node Icon */}
              <div
                className={`absolute -left-[17px] w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all ${
                  isDone
                    ? 'bg-[#111111] border-[#4FAF72] text-[#4FAF72] shadow-[0_0_10px_rgba(79,175,114,0.3)]'
                    : isCurrent
                    ? 'bg-[#111111] border-[#D4AF37] text-[#D4AF37] animate-pulse shadow-[0_0_12px_rgba(212,175,55,0.4)]'
                    : 'bg-[#111111] border-[#2A2A2A] text-[#706C64]'
                }`}
              >
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-[#4FAF72]" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 animate-spin text-[#D4AF37]" />
                ) : (
                  <Icon className="w-3.5 h-3.5" />
                )}
              </div>

              {/* Title & Stage Details */}
              <div className="min-w-0 flex-1 ml-2">
                <p className={`text-xs font-bold ${isDone ? 'text-[#F5F3ED]' : isCurrent ? 'text-[#D4AF37] font-black' : 'text-[#706C64]'}`}>
                  {item.label}
                </p>
                {item.timestamp && (
                  <span className="text-[10px] text-[#706C64] font-mono block">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                )}
              </div>

              {/* Status & Duration Badge */}
              <div className="flex items-center gap-2 flex-shrink-0">
                {item.duration_ms != null && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#111111] border border-[#2A2A2A] text-[#A7A39A]">
                    {item.duration_ms} ms
                  </span>
                )}
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded capitalize ${
                    isDone
                      ? 'bg-green-500/15 text-[#4FAF72] border border-green-500/30'
                      : isCurrent
                      ? 'bg-[#5C4A20]/25 text-[#D4AF37] border border-[#5C4A20]'
                      : 'bg-slate-500/10 text-[#706C64] border border-slate-500/20'
                  }`}
                >
                  {isDone ? 'Completed' : isCurrent ? 'Running' : 'Pending'}
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
