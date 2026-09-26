'use client';
import { motion } from 'framer-motion';
import {
  Shield, FileText, AlertTriangle, Terminal,
  Cpu, Lock, Zap, CheckCircle2, Wrench, Info, ArrowRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface QuickActionsProps {
  contextType: 'general' | 'scan' | 'finding';
  findingTitle?: string | null;
  technologies?: string[];
  onAction: (message: string) => void;
  disabled?: boolean;
}

interface ActionItem {
  label: string;
  message: string;
  icon: React.ComponentType<{ className?: string }>;
}

const SCAN_ACTIONS: ActionItem[] = [
  { label: 'Summarize this scan', message: 'Summarize this scan and give me the key security takeaways.', icon: FileText },
  { label: 'Explain security score', message: 'Explain my security score and grade in detail. Why is it this value?', icon: Shield },
  { label: 'High severity issues', message: 'List and explain all HIGH severity findings in this scan.', icon: AlertTriangle },
  { label: 'Priority investigations', message: 'Based on this scan, what are the most important issues I should investigate first?', icon: Terminal },
  { label: 'Technology stack', message: 'What technologies were detected? Are any of them outdated or risky?', icon: Cpu },
  { label: 'CVE exposure', message: 'Which detected technologies have known CVEs? Explain the risk.', icon: Lock },
  { label: 'EOL component risks', message: 'Which components have reached end-of-life or are approaching it? What is the risk?', icon: Zap },
  { label: 'Verification boundary', message: 'What can SentinelScan actually confirm from this scan vs what is estimated?', icon: CheckCircle2 },
];

const FINDING_ACTIONS: ActionItem[] = [
  { label: 'Why is this dangerous?', message: 'Why is this finding dangerous? What are the real-world risks?', icon: AlertTriangle },
  { label: 'Inspect evidence', message: 'Show and explain the evidence SentinelScan observed for this finding.', icon: Terminal },
  { label: 'Technical explanation', message: 'Give me a technical explanation of this vulnerability — how it works and why it exists.', icon: Cpu },
  { label: 'Severity breakdown', message: 'Why was this finding classified with its current severity rating?', icon: Shield },
  { label: 'OWASP 2025 mapping', message: 'Explain the OWASP Top 10:2025 mapping for this finding.', icon: Lock },
  { label: 'How to remediate', message: 'Give me step-by-step remediation instructions for this finding.', icon: Wrench },
  { label: 'Passive limitations', message: 'What aspects of this finding can SentinelScan NOT verify from passive external observation?', icon: Info },
];

const GENERAL_ACTIONS: ActionItem[] = [
  { label: 'How does SentinelScan work?', message: 'What is SentinelScan and how does it work?', icon: Shield },
  { label: 'How scoring works', message: 'How does SentinelScan calculate the security score and grade?', icon: FileText },
  { label: 'What is NOT_VERIFIABLE?', message: 'What does NOT_VERIFIABLE mean in SentinelScan findings?', icon: Info },
  { label: 'Assessment limitations', message: 'What are the known limitations of SentinelScan passive assessments?', icon: AlertTriangle },
];

export default function QuickActions({ contextType, onAction, disabled }: QuickActionsProps) {
  const actions =
    contextType === 'finding' ? FINDING_ACTIONS :
    contextType === 'scan'    ? SCAN_ACTIONS :
    GENERAL_ACTIONS;

  return (
    <div className="w-full">
      <div className="flex items-center gap-2 overflow-x-auto pb-1 -mx-1 px-1" style={{ scrollbarWidth: 'none' }}>
        {actions.map((action) => {
          const Icon = action.icon;
          return (
            <motion.button
              key={action.label}
              whileHover={{ y: -1.5 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => onAction(action.message)}
              disabled={disabled}
              className={cn(
                'group flex-shrink-0 flex items-center gap-1.5 rounded-xl',
                'transition-all duration-150 select-none whitespace-nowrap',
                'disabled:opacity-30 disabled:cursor-not-allowed',
              )}
              style={{
                padding: '6px 11px',
                fontSize: '11px',
                fontWeight: 500,
                background: '#0C0C0C',
                border: '1px solid #1C1C1C',
                color: '#6E6A62',
              }}
              onMouseEnter={e => {
                if (!disabled) {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderColor = '#3A3020';
                  el.style.color = '#C8C5BD';
                  el.style.background = '#101008';
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLElement;
                el.style.borderColor = '#1C1C1C';
                el.style.color = '#6E6A62';
                el.style.background = '#0C0C0C';
              }}
            >
              <Icon className="w-3 h-3 flex-shrink-0 opacity-50 group-hover:opacity-80 transition-opacity" />
              <span>{action.label}</span>
              <ArrowRight
                className="w-2.5 h-2.5 flex-shrink-0 transition-all duration-150"
                style={{ opacity: 0, transform: 'translateX(-3px)' }}
              />
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}
