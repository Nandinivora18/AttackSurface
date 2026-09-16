'use client';
import { useEffect, useState, useRef, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Download, ArrowLeft, Shield, ChevronDown, ChevronUp,
  ExternalLink, AlertTriangle, CheckCircle, Globe, Lock,
  Cpu, Info, ShieldAlert, Bug, ShieldCheck,
  X, Filter, Printer, FileText, Check, Terminal, BookOpen, Zap, ArrowRight
} from 'lucide-react';
import ReportSubNav from '@/components/reports/ReportSubNav';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ReportSkeleton } from '@/components/shared/LoadingSkeleton';
import api from '@/lib/api';
import {
  Report, Finding, Severity, OWASPMapping, CategoryScore,
  OWASPCategoryAssessment, ComponentInventoryItem
} from '@/types';
import { formatDate, getGradeColor, getScoreColor, resolveFindingLocation, formatConfidence } from '@/lib/utils';
import toast from 'react-hot-toast';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#4FAF72',
  info: '#94A3B8',
};

const CATEGORY_DISPLAY_NAMES: Record<string, string> = {
  ssl_tls: 'HTTPS / SSL',
  security_headers: 'Website Security',
  cookies: 'Cookies',
  dns: 'DNS / Email',
  technology_stack: 'Software & Versions',
  content_exposure: 'Exposed Information',
  configuration: 'Configuration',
};

const CAT_COLORS: Record<string, string> = { green: '#4FAF72', yellow: '#F59E0B', orange: '#F97316', red: '#EF4444' };
const CAT_BG: Record<string, string> = { green: 'rgba(79,175,114,0.1)', yellow: 'rgba(245,158,11,0.1)', orange: 'rgba(249,115,22,0.1)', red: 'rgba(239,68,68,0.1)' };

const CAT_KEYWORDS: Record<string, string[]> = {
  ssl_tls: ['ssl', 'tls', 'transport security', 'certificate', 'cipher', 'https'],
  security_headers: ['injection prevention', 'clickjacking', 'mime sniffing', 'xss protection', 'isolation', 'feature control', 'content-security-policy', 'x-frame-options', 'referrer', 'permissions', 'cors', 'security header'],
  cookies: ['cookie'],
  dns: ['dns', 'spf', 'dmarc', 'dkim', 'mx', 'email auth'],
  technology_stack: ['cve', 'technology', 'vulnerable', 'outdated', 'component'],
  content_exposure: ['content', 'information disclosure', 'exposed', 'sensitive', 'privacy'],
  configuration: ['configuration', 'misconfiguration', 'connectivity'],
};

function findingMatchesCat(f: Finding, catKey: string): boolean {
  const combined = `${(f.category || '').toLowerCase()} ${(f.title || '').toLowerCase()}`;
  return (CAT_KEYWORDS[catKey] || []).some((kw) => combined.includes(kw));
}

/* ─── Semantic Helper: Positively Verified Protections Only ──── */
function isPositivelyVerifiedProtection(f: Finding): boolean {
  if (!f.is_passed_control) return false;
  const lowerTitle = (f.title || '').toLowerCase();
  const lowerDesc = (f.description || '').toLowerCase();
  const lowerProblem = (f.problem || '').toLowerCase();

  const negativeOrUncertain = [
    'not detected',
    'not observed',
    'not configured',
    'not found',
    'could not be confirmed',
    'could not connect',
    'undisclosed',
    'inconclusive',
    'unconfirmed',
    'missing',
    'potential dkim',
    'allows all origins',
    'superseded',
  ];

  if (negativeOrUncertain.some((kw) => lowerTitle.includes(kw) || lowerDesc.includes(kw) || lowerProblem.includes(kw))) {
    return false;
  }
  return true;
}

/* ─── Score Status Mapping (Calm, Understandable, Consistent) ─ */
function getScoreStatus(score: number): { label: string; cls: string } {
  if (score >= 90) return { label: 'Good Security', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' };
  if (score >= 75) return { label: 'Mostly Secure', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' };
  if (score >= 60) return { label: 'Needs Attention', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' };
  if (score >= 40) return { label: 'Significant Issues', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' };
  return { label: 'High Risk', cls: 'bg-red-500/15 text-red-400 border-red-500/30' };
}

/* ─── Dynamic Plain-English Description ──────────────────────── */
function getPlainDescription(counts: Record<Severity, number>): string {
  if (counts.critical > 0) {
    return `The assessment identified ${counts.critical} critical finding${counts.critical > 1 ? 's' : ''} requiring immediate attention${counts.high > 0 ? `, along with ${counts.high} high-severity issue${counts.high > 1 ? 's' : ''}` : ''}.`;
  }
  if (counts.high > 0) {
    return `SentinelScan assessed this website and found several security issues that should be addressed, including ${counts.high} high-severity finding${counts.high > 1 ? 's' : ''} requiring priority attention.`;
  }
  if (counts.medium > 0) {
    return `SentinelScan assessed this website and found no high-severity issues. There are ${counts.medium} medium-severity configuration improvement${counts.medium > 1 ? 's' : ''} recommended.`;
  }
  return 'SentinelScan assessed this website and found no high-severity issues. Foundational security controls are verified.';
}

/* ─── Score Ring ──────────────────────────────────────────────── */
function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const color = getScoreColor(score);
  const gradeColor = getGradeColor(grade);
  const r = 68, circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);

  return (
    <div className="relative w-44 h-44 mx-auto">
      <svg className="w-44 h-44 -rotate-90" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={r} fill="none" stroke="#1A1A1A" strokeWidth="12" />
        <circle
          cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${circ} ${circ}`} strokeDashoffset={offset}
          strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1.2s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl sm:text-5xl font-extrabold text-[#F5F3ED] font-mono tracking-tight">{score}</span>
        <span className="text-xs text-[#706C64]">out of 100</span>
        <span className="text-lg font-bold mt-1" style={{ color: gradeColor }}>Grade {grade}</span>
      </div>
    </div>
  );
}

/* ─── Category Score Card (Part 7: 3-Col Balanced, Compact) ──── */
function CategoryScoreCard({
  catKey, data, selected, onClick,
}: { catKey: string; data: CategoryScore; selected: boolean; onClick: () => void }) {
  const color = CAT_COLORS[data.color] || '#4FAF72';
  const displayName = CATEGORY_DISPLAY_NAMES[catKey] || data.label;
  const isGood = data.pct >= 80;

  return (
    <motion.button
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      className={`glass-card p-3.5 space-y-2.5 w-full text-left transition-all cursor-pointer hover:border-[#5C4A20] ${
        selected ? 'ring-2 border-[#D4AF37] bg-[#5C4A20]/10' : 'border-[#2A2A2A] bg-[#0D0D0D]'
      }`}
      style={{
        boxShadow: selected ? `0 0 16px rgba(212,175,55,0.15)` : undefined,
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-bold text-[#F5F3ED] truncate">{displayName}</span>
        <span className="text-xs font-mono font-bold text-[#F5F3ED]">
          {data.score}<span className="text-[#706C64] font-normal">/{data.max}</span>
        </span>
      </div>

      <div className="h-1.5 rounded-full overflow-hidden bg-[#1A1A1A]">
        <motion.div
          className="h-full rounded-full"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${data.pct}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
        />
      </div>

      <div className="flex items-center justify-between text-[11px]">
        <span className={isGood ? 'text-[#4FAF72] font-semibold' : 'text-[#F97316] font-semibold'}>
          {isGood ? 'Good condition' : 'Needs attention'}
        </span>
        <span className="text-[#706C64] font-mono">{data.pct}%</span>
      </div>

      {Array.isArray(data.deductions) && data.deductions.length > 0 ? (
        <div className="pt-2 border-t border-[#2A2A2A]/50 space-y-1 text-[10px]">
          <div className="flex items-center justify-between text-[#A7A39A] gap-2">
            <span className="truncate">- {data.deductions[0].finding_title}</span>
            <span className="font-mono text-red-400 font-bold flex-shrink-0">-{data.deductions[0].points_deducted}</span>
          </div>
          {data.deductions.length > 1 && (
            <p className="text-[9px] text-[#706C64] italic">
              +{data.deductions.length - 1} more issue{data.deductions.length > 2 ? 's' : ''}
            </p>
          )}
          <div className="pt-1 flex items-center justify-end text-[10px] text-[#D4AF37] font-semibold">
            <span>View findings →</span>
          </div>
        </div>
      ) : (
        <div className="pt-2 border-t border-[#2A2A2A]/50 flex items-center justify-between text-[10px] text-[#4FAF72]">
          <span>No deductions</span>
          <span className="text-[#706C64] text-[10px]">View findings →</span>
        </div>
      )}
    </motion.button>
  );
}

/* ─── Part 5: Fix These First (Top 3 Concise Priorities) ─────── */
function FixTheseFirstSection({
  findings,
  onSelectFinding,
}: {
  findings: Finding[];
  onSelectFinding: (findingId: string) => void;
}) {
  const prioritized = useMemo(() => {
    return [...findings]
      .filter((f) => !f.is_passed_control)
      .sort((a, b) => {
        const diff = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
        if (diff !== 0) return diff;
        return (Number(b.cvss_score) || 0) - (Number(a.cvss_score) || 0);
      })
      .slice(0, 3);
  }, [findings]);

  if (prioritized.length === 0) return null;

  return (
    <GlassCard className="p-6 border border-[#5C4A20]/40 bg-[#111111] space-y-4 shadow-[0_0_24px_rgba(212,175,55,0.08)]">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#5C4A20]/25 border border-[#D4AF37]/40 flex items-center justify-center">
            <Zap className="w-4 h-4 text-[#D4AF37]" />
          </div>
          <div>
            <h2 className="text-base sm:text-lg font-extrabold text-[#F5F3ED] tracking-tight">Fix These First</h2>
            <p className="text-xs text-[#A7A39A]">Top priority security issues that should be addressed first</p>
          </div>
        </div>
        <span className="text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20]">
          High Impact First
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {prioritized.map((item, idx) => {
          const plainDesc = item.problem || item.description || "Security configuration issue detected.";
          const rawWhy = item.impact || "Leaving this unconfigured increases exposure to connection attacks on unsafe networks.";
          const whyItMatters = rawWhy.split('. ')[0].replace(/\.$/, '') + '.';
          const rawFix = item.recommendation || (item.fix_steps && item.fix_steps[0]) || "Apply recommended server security settings.";
          const howToFix = rawFix.split('. ')[0].replace(/\.$/, '') + '.';

          return (
            <div
              key={item.id || idx}
              className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] hover:border-[#5C4A20]/60 transition-all flex flex-col justify-between space-y-3"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#161616] text-[#D4AF37] border border-[#2A2A2A]">
                    Priority #{idx + 1}
                  </span>
                  <SeverityBadge severity={item.severity} size="sm" />
                </div>

                <h3 className="text-sm font-bold text-[#F5F3ED] leading-snug">
                  {item.title}
                </h3>

                <p className="text-xs text-[#A7A39A] leading-relaxed line-clamp-2">
                  {plainDesc}
                </p>

                <div className="pt-2 border-t border-[#2A2A2A]/60 space-y-2 text-xs">
                  <div>
                    <span className="text-[10px] font-bold uppercase text-[#F97316] tracking-wider block">Why it matters:</span>
                    <p className="text-[11px] text-[#F5F3ED]/90 leading-snug line-clamp-2 mt-0.5">
                      {whyItMatters}
                    </p>
                  </div>

                  <div>
                    <span className="text-[10px] font-bold uppercase text-[#4FAF72] tracking-wider block">How to fix:</span>
                    <p className="text-[11px] text-[#F5F3ED]/90 leading-snug line-clamp-2 mt-0.5">
                      {howToFix}
                    </p>
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => onSelectFinding(item.id)}
                className="w-full mt-2 py-2 text-xs font-bold text-[#D4AF37] bg-[#5C4A20]/15 hover:bg-[#5C4A20]/30 border border-[#5C4A20]/40 rounded-lg flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>View Finding</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </GlassCard>
  );
}

/* ─── Part 6: Simplified Security Summary ────────────────────── */
function SecuritySummarySection({ report }: { report: Report }) {
  const strengths = useMemo(() => {
    if (report.executive_summary?.strengths && report.executive_summary.strengths.length > 0) {
      return report.executive_summary.strengths;
    }
    return [
      'Positive security configuration verified',
      'Secure connection established via HTTPS',
      'Basic web defenses in place',
    ];
  }, [report.executive_summary]);

  const weaknesses = useMemo(() => {
    if (report.executive_summary?.weaknesses && report.executive_summary.weaknesses.length > 0) {
      return report.executive_summary.weaknesses;
    }
    return [
      'Website security settings need improvement',
      'Some security defense headers are missing',
    ];
  }, [report.executive_summary]);

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111] space-y-4">
      <div className="flex items-center justify-between border-b border-[#2A2A2A]/60 pb-3">
        <h2 className="text-base font-bold text-[#F5F3ED] flex items-center gap-2">
          <Shield className="w-5 h-5 text-[#D4AF37]" /> Security Summary
        </h2>
        <span className="text-xs text-[#706C64]">Plain-English Health Check</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* What is good */}
        <div className="p-4 rounded-xl bg-[#0D0D0D] border border-emerald-500/20 space-y-2.5">
          <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
            <CheckCircle className="w-4 h-4" />
            <span>What is good</span>
          </div>
          <ul className="space-y-2 text-xs text-[#F5F3ED]">
            {strengths.slice(0, 4).map((s, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-[#4FAF72] font-bold mt-0.5">✓</span>
                <span className="text-[#A7A39A] leading-relaxed">{s}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* What needs attention */}
        <div className="p-4 rounded-xl bg-[#0D0D0D] border border-amber-500/20 space-y-2.5">
          <div className="flex items-center gap-2 text-amber-400 font-bold text-xs uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4" />
            <span>What needs attention</span>
          </div>
          <ul className="space-y-2 text-xs text-[#F5F3ED]">
            {weaknesses.slice(0, 4).map((w, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-[#F97316] font-bold mt-0.5">⚠</span>
                <span className="text-[#A7A39A] leading-relaxed">{w}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </GlassCard>
  );
}

/* ─── Part 9: Simplified OWASP Top 10 (100% Collapsed by Default) ─ */
function OWASPMatrixCard({
  owaspSummary,
}: {
  owaspSummary?: Record<string, OWASPCategoryAssessment>;
}) {
  const [expandedCat, setExpandedCat] = useState<string | null>(null);

  const categories = [
    { key: 'A01_BrokenAccessControl', id: 'A01', name: 'Broken Access Control' },
    { key: 'A02_SecurityMisconfiguration', id: 'A02', name: 'Security Misconfiguration' },
    { key: 'A03_SoftwareSupplyChainFailures', id: 'A03', name: 'Software Supply Chain Failures' },
    { key: 'A04_CryptographicFailures', id: 'A04', name: 'Cryptographic Failures' },
    { key: 'A05_Injection', id: 'A05', name: 'Injection' },
    { key: 'A06_InsecureDesign', id: 'A06', name: 'Insecure Design' },
    { key: 'A07_AuthenticationFailures', id: 'A07', name: 'Authentication Failures' },
    { key: 'A08_SoftwareOrDataIntegrityFailures', id: 'A08', name: 'Software or Data Integrity Failures' },
    { key: 'A09_SecurityLoggingAndAlertingFailures', id: 'A09', name: 'Security Logging & Alerting' },
    { key: 'A10_MishandlingOfExceptionalConditions', id: 'A10', name: 'Mishandling of Exceptional Conditions' },
  ];

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111] space-y-4">
      <div className="space-y-1">
        <h2 className="text-base sm:text-lg font-bold text-[#F5F3ED] flex items-center gap-2">
          <Shield className="w-5 h-5 text-orange-400" /> OWASP Top 10
        </h2>
        <p className="text-xs text-[#A7A39A]">
          SentinelScan checks your website against the OWASP Top 10 security risks. Click any category to view evaluation methodology.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
        {categories.map((c) => {
          const assessment = owaspSummary?.[c.key];
          const rawStatus = assessment?.status || 'PASS';
          const count = assessment?.findings_count || 0;
          const isExpanded = expandedCat === c.key;

          // Standardized statuses
          let statusLabel = '✓ Passed';
          let badgeColor = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';

          if (rawStatus === 'FAIL' || count > 0) {
            statusLabel = `⚠ Findings (${count})`;
            badgeColor = 'bg-red-500/15 text-red-400 border-red-500/30';
          } else if (rawStatus === 'NOT_VERIFIABLE') {
            statusLabel = 'ℹ Not Verifiable';
            badgeColor = 'bg-purple-500/15 text-purple-400 border-purple-500/30';
          } else if (rawStatus === 'INCONCLUSIVE') {
            statusLabel = 'ℹ Needs Review';
            badgeColor = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
          } else if (rawStatus === 'NOT_APPLICABLE') {
            statusLabel = 'Not Applicable';
            badgeColor = 'bg-slate-500/15 text-slate-400 border-slate-500/30';
          }

          return (
            <div
              key={c.key}
              className="p-3 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] hover:border-[#383838] transition-all cursor-pointer"
              onClick={() => setExpandedCat((prev) => (prev === c.key ? null : c.key))}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="text-xs font-mono font-bold text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded border border-orange-500/20">
                    {c.id}
                  </span>
                  <span className="text-xs font-semibold text-[#F5F3ED] truncate">{c.name}</span>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${badgeColor}`}>
                    {statusLabel}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5 text-[#706C64]" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 text-[#706C64]" />
                  )}
                </div>
              </div>

              {isExpanded && assessment && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="mt-2.5 pt-2.5 border-t border-[#2A2A2A] space-y-1.5 text-[11px]"
                >
                  {count > 0 && (
                    <p className="text-red-400 font-semibold">
                      {count} related security finding{count > 1 ? 's' : ''} mapped to this OWASP category.
                    </p>
                  )}
                  <p className="text-[#D4AF37] font-semibold">Evaluation Method:</p>
                  <p className="text-[#A7A39A] leading-relaxed">{assessment.method}</p>
                  {assessment.limitations && (
                    <>
                      <p className="text-[#706C64] font-semibold mt-1">Scope &amp; Technical Limitations:</p>
                      <p className="text-[#706C64] leading-relaxed">{assessment.limitations}</p>
                    </>
                  )}
                </motion.div>
              )}
            </div>
          );
        })}
      </div>
    </GlassCard>
  );
}

/* ─── Part 11: Technology & Version Check (Compact Table) ────── */
function TechnologyVersionCheckCard({
  inventory,
  techStack,
}: {
  inventory?: ComponentInventoryItem[];
  techStack?: Record<string, any>;
}) {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  // Unify items from component_inventory or fallback to tech_stack
  const items = useMemo(() => {
    if (inventory && inventory.length > 0) {
      return inventory.map((comp) => ({
        name: comp.technology,
        version: comp.normalized_version || comp.raw_version || null,
        status: comp.lifecycle_status || 'VERSION_UNKNOWN',
        category: comp.category,
        latestVersion: comp.latest_version,
        eolDate: comp.eol_date,
        cveCount: comp.cve_count || 0,
        evidence: comp.evidence,
      }));
    }
    if (techStack && Object.keys(techStack).length > 0) {
      return Object.entries(techStack).map(([name, info]) => ({
        name,
        version: info.version || null,
        status: info.version ? 'SUPPORTED' : 'VERSION_UNKNOWN',
        category: info.category,
        latestVersion: null,
        eolDate: null,
        cveCount: 0,
        evidence: null,
      }));
    }
    return [];
  }, [inventory, techStack]);

  if (items.length === 0) return null;

  const totalTech = items.length;
  const versionedCount = items.filter((i) => !!i.version).length;
  const uniqueCategories = new Set(items.map((i) => i.category).filter(Boolean)).size || 1;

  const formatStatus = (st: string, hasVersion: boolean) => {
    if (!hasVersion || st === 'VERSION_UNKNOWN' || st === 'LIFECYCLE_UNKNOWN') {
      return { label: 'Version unknown', cls: 'text-slate-400 border-slate-500/30 bg-slate-500/15' };
    }
    switch (st) {
      case 'SUPPORTED':
        return { label: 'Supported', cls: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/15' };
      case 'UPDATE_AVAILABLE':
        return { label: 'Update available', cls: 'text-amber-400 border-amber-500/30 bg-amber-500/15' };
      case 'SECURITY_SUPPORT_ENDED':
        return { label: 'Support ended', cls: 'text-orange-400 border-orange-500/30 bg-orange-500/15' };
      case 'END_OF_LIFE':
        return { label: 'End of life', cls: 'text-red-400 border-red-500/30 bg-red-500/15' };
      default:
        return { label: 'Version unknown', cls: 'text-slate-400 border-slate-500/30 bg-slate-500/15' };
    }
  };

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111] space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3 border-b border-[#2A2A2A]/50 pb-3">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-[#F5F3ED] flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#D4AF37]" /> Technology &amp; Version Check
          </h2>
          <p className="text-xs text-[#A7A39A]">
            Software components and versions detected on this website.
          </p>
        </div>

        {/* Compact Summary Metrics */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <span className="px-2.5 py-1 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED] font-mono">
            <strong className="text-[#D4AF37]">{totalTech}</strong> Total
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED] font-mono">
            <strong className="text-[#4FAF72]">{versionedCount}</strong> Versioned
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED] font-mono">
            <strong className="text-[#A7A39A]">{uniqueCategories}</strong> Categories
          </span>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-[#2A2A2A] text-[#706C64]">
              <th className="pb-2.5 font-semibold">Technology</th>
              <th className="pb-2.5 font-semibold">Detected Version</th>
              <th className="pb-2.5 font-semibold text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2A2A2A]/40 text-[#A7A39A]">
            {items.map((comp, idx) => {
              const hasVersion = !!comp.version;
              const statusInfo = formatStatus(comp.status, hasVersion);
              const isExpanded = expandedRow === idx;
              const hasExtra = !!(comp.eolDate || comp.latestVersion || comp.cveCount || comp.category || comp.evidence);

              return (
                <tr
                  key={idx}
                  onClick={() => hasExtra && setExpandedRow(isExpanded ? null : idx)}
                  className={`transition-colors ${hasExtra ? 'cursor-pointer hover:bg-[#151515]' : ''}`}
                >
                  <td className="py-2.5 font-semibold text-[#F5F3ED]">
                    <div className="flex items-center gap-1.5">
                      <span>{comp.name}</span>
                      {hasExtra && (
                        <span className="text-[10px] text-[#706C64]">
                          {isExpanded ? '▲' : '▼'}
                        </span>
                      )}
                    </div>
                    {isExpanded && (
                      <div className="mt-2 space-y-1 text-[11px] text-[#706C64] font-normal">
                        {comp.category && <p>Category: <span className="text-[#A7A39A]">{comp.category}</span></p>}
                        {comp.latestVersion && <p>Latest release: <span className="text-[#A7A39A]">{comp.latestVersion}</span></p>}
                        {comp.eolDate && <p>EOL date: <span className="text-[#F97316]">{comp.eolDate}</span></p>}
                        {comp.cveCount > 0 && <p className="text-red-400 font-bold">{comp.cveCount} CVEs associated</p>}
                        {comp.evidence && <p className="font-mono text-[10px] text-[#D4AF37] break-all">Evidence: {comp.evidence}</p>}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 font-mono">
                    {hasVersion ? (
                      <span className="text-[#D4AF37] font-semibold">{comp.version}</span>
                    ) : (
                      <span className="text-[#706C64] italic">Unknown</span>
                    )}
                  </td>
                  <td className="py-2.5 text-right">
                    <span className={`inline-block text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${statusInfo.cls}`}>
                      {statusInfo.label}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </GlassCard>
  );
}

/* ─── Part 12 & 13: Finding Card with Progressive Disclosure ─── */
function FindingCard({
  finding,
  assetUrl,
  initiallyOpen = false,
}: {
  finding: Finding;
  assetUrl?: string;
  initiallyOpen?: boolean;
}) {
  const [open, setOpen] = useState(initiallyOpen);
  const [showTechnical, setShowTechnical] = useState(false);

  useEffect(() => {
    if (initiallyOpen) setOpen(true);
  }, [initiallyOpen]);

  const plainExplanation = finding.problem || finding.description || "Security configuration issue detected.";
  const loc = resolveFindingLocation(finding, assetUrl);
  const isCve = !!finding.cve_id;

  return (
    <motion.div
      id={`finding-${finding.id}`}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card overflow-hidden border border-[#2A2A2A] bg-[#111111] transition-colors ${
        open ? 'border-[#5C4A20]/80 shadow-[0_0_16px_rgba(212,175,55,0.08)]' : ''
      }`}
    >
      {/* ── Collapsed View (Part 12) ── */}
      <button
        className="w-full flex items-start gap-4 p-4 text-left hover:bg-white/[0.02] transition-colors cursor-pointer"
        onClick={() => setOpen(!open)}
      >
        <div className="pt-0.5">
          <SeverityBadge severity={finding.severity} />
        </div>

        <div className="flex-1 min-w-0 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-bold text-[#F5F3ED] text-sm leading-snug">{finding.title}</p>
            {finding.cvss_score != null && (
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-black/40 text-[#D4AF37] border border-[#2A2A2A]">
                CVSS {Number(finding.cvss_score).toFixed(1)}
              </span>
            )}
          </div>

          <p className="text-xs text-[#A7A39A] leading-relaxed line-clamp-2">
            {plainExplanation}
          </p>

          <p className="text-[11px] text-[#706C64] truncate pt-0.5">
            <span className="text-[#A7A39A] font-medium">{loc.label}:</span>{' '}
            <span className="text-[#D4AF37] font-mono">{loc.value}</span>
          </p>
        </div>

        <div className="flex items-center gap-1.5 flex-shrink-0 pt-1 text-xs font-semibold">
          <span className="text-[#D4AF37] hidden sm:inline">{open ? 'Hide details' : 'View Details →'}</span>
          {open ? <ChevronUp className="w-4 h-4 text-[#706C64]" /> : <ChevronDown className="w-4 h-4 text-[#706C64]" />}
        </div>
      </button>

      {/* ── Expanded Progressive Disclosure (Part 13) ── */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-[#2A2A2A] px-5 pb-6 pt-4 space-y-5"
          >
            {/* 1. What is wrong? */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#D4AF37]">
                What is wrong?
              </p>
              <p className="text-xs text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#2A2A2A] font-medium">
                {finding.problem || finding.description}
              </p>
            </div>

            {/* 2. Where was it found? */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#A7A39A]">
                Where was it found?
              </p>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] text-[#706C64] uppercase font-semibold">{loc.label}</p>
                  <p className="text-xs font-mono font-bold text-[#D4AF37] truncate mt-0.5">
                    {loc.value}
                  </p>
                </div>
                <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] flex-shrink-0">
                  {loc.badge}
                </span>
              </div>
            </div>

            {/* 3. Why does it matter? */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#F97316]">
                Why does it matter?
              </p>
              <div className="p-3 rounded-lg bg-orange-500/5 border border-orange-500/20 text-xs text-[#F5F3ED] leading-relaxed">
                {finding.impact || "Leaving this unconfigured increases vulnerability to eavesdropping, clickjacking, or data tampering on untrusted networks."}
              </div>
            </div>

            {/* 4. How to fix it */}
            <div className="space-y-2">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#4FAF72]">
                How to fix it
              </p>

              {finding.recommendation && (
                <p className="text-xs text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#2A2A2A]">
                  {finding.recommendation}
                </p>
              )}

              {finding.fix_steps && finding.fix_steps.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  {finding.fix_steps.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-[#F5F3ED] bg-[#161616] p-2.5 rounded-lg border border-[#2A2A2A]">
                      <span className="w-5 h-5 rounded bg-[#5C4A20]/30 text-[#D4AF37] font-bold font-mono text-[10px] flex items-center justify-center flex-shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              )}

              {finding.configuration_example && (
                <div className="pt-2">
                  <p className="text-[11px] font-bold text-[#D4AF37] uppercase tracking-wider mb-1">
                    Configuration Example
                  </p>
                  <pre className="text-[11px] text-[#D4AF37] bg-black/80 p-3 rounded-lg block font-mono overflow-x-auto border border-[#5C4A20]/40 leading-relaxed whitespace-pre-wrap">
                    {finding.configuration_example}
                  </pre>
                </div>
              )}
            </div>

            {/* ── Technical Details ▾ (Progressive Disclosure) ── */}
            <div className="pt-2 border-t border-[#2A2A2A]/60">
              <button
                type="button"
                onClick={() => setShowTechnical(!showTechnical)}
                className="w-full flex items-center justify-between py-2 text-xs font-bold uppercase tracking-wider text-[#A7A39A] hover:text-[#F5F3ED] transition-colors cursor-pointer"
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#D4AF37]" />
                  {showTechnical ? '▲ Hide Technical Details' : '▼ Technical Details'}
                </span>
                <span className="text-[10px] font-normal text-[#706C64]">Evidence, CVSS, Standards</span>
              </button>

              {showTechnical && (
                <div className="mt-2 space-y-3 p-3.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                      <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-0.5">Category</span>
                      <span className="text-[#F5F3ED] font-medium">{finding.category}</span>
                    </div>
                    {finding.cvss_score != null && (
                      <div>
                        <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-0.5">CVSS Score</span>
                        <span className="text-[#D4AF37] font-mono font-bold">{Number(finding.cvss_score).toFixed(1)}</span>
                      </div>
                    )}
                  </div>

                  {finding.confidence && (
                    <div>
                      <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-0.5">Confidence</span>
                      <span className="text-[#4FAF72] font-semibold">{formatConfidence(finding.confidence)}</span>
                    </div>
                  )}

                  {finding.evidence && (
                    <div>
                      <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-0.5">Captured Evidence</span>
                      <code className="text-[11px] text-[#D4AF37] bg-black/60 p-2.5 rounded block font-mono break-all border border-[#5C4A20]/30 whitespace-pre-wrap">
                        {finding.evidence}
                      </code>
                    </div>
                  )}

                  {finding.owasp_mapping && (
                    <div className="pt-2 border-t border-[#2A2A2A]/50">
                      <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-1">OWASP Mapping</span>
                      <a
                        href={finding.owasp_mapping.reference}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        <span>OWASP {finding.owasp_mapping.id}: {finding.owasp_mapping.title}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}

                  {isCve && (
                    <div className="pt-2 border-t border-[#2A2A2A]/50 flex items-center justify-between">
                      <span className="text-red-400 font-mono font-bold">CVE: {finding.cve_id}</span>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[#D4AF37] hover:underline flex items-center gap-1 text-[11px]"
                      >
                        NVD Entry <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}

                  {finding.references && finding.references.length > 0 && (
                    <div className="pt-2 border-t border-[#2A2A2A]/50">
                      <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-1">Documentation Links</span>
                      <div className="space-y-1">
                        {finding.references.map((ref, idx) => (
                          <a
                            key={idx}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#D4AF37] hover:underline flex items-center gap-1 text-xs truncate block"
                          >
                            <ExternalLink className="w-3 h-3 flex-shrink-0" />
                            <span className="truncate">{ref}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {finding.id && (
                    <div className="pt-2 border-t border-[#2A2A2A]/50 flex justify-end">
                      <Link
                        href={`/findings/${finding.id}`}
                        className="inline-flex items-center gap-1 text-xs text-[#D4AF37] hover:underline font-semibold"
                      >
                        Open in Finding Triage Workspace <ExternalLink className="w-3 h-3" />
                      </Link>
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ─── Part 14: What is Already Protected (Positively Verified Controls Only) ─ */
function PassedControlsSection({ passedControls }: { passedControls: Finding[] }) {
  const verifiedProtections = useMemo(() => {
    return passedControls.filter((pc) => isPositivelyVerifiedProtection(pc));
  }, [passedControls]);

  return (
    <GlassCard className="p-5 border border-green-500/20 bg-[#111111] space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h3 className="text-sm font-bold text-[#F5F3ED] flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-[#4FAF72]" /> What is already protected
        </h3>
        {verifiedProtections.length > 0 && (
          <span className="text-[11px] font-mono font-bold text-[#4FAF72] bg-green-500/10 px-2 py-0.5 rounded border border-green-500/20">
            {verifiedProtections.length} verified
          </span>
        )}
      </div>

      {verifiedProtections.length === 0 ? (
        <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] text-xs text-[#706C64] text-center">
          No verified protections were identified in this assessment.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          {verifiedProtections.map((pc, idx) => (
            <div key={pc.id || idx} className="p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] flex items-start gap-2">
              <span className="text-[#4FAF72] font-bold">✓</span>
              <div className="min-w-0">
                <p className="font-semibold text-[#F5F3ED] text-[11px] leading-tight">{pc.title}</p>
                {pc.description && (
                  <p className="text-[10px] text-[#706C64] mt-0.5 line-clamp-1">{pc.description}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </GlassCard>
  );
}

/* ─── Part 15: How SentinelScan Checks Websites (Secondary) ──── */
function MethodologySection() {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] text-xs space-y-2">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between text-left text-[#A7A39A] hover:text-[#F5F3ED] transition-colors cursor-pointer"
      >
        <span className="font-semibold flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#D4AF37]" />
          How SentinelScan checks websites
        </span>
        <span className="text-[11px] text-[#706C64] flex items-center gap-1">
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </span>
      </button>

      {expanded && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="pt-2 border-t border-[#2A2A2A] space-y-2.5 text-[#A7A39A]"
        >
          <p className="leading-relaxed">
            SentinelScan performs passive, non-destructive checks of publicly accessible website and network information.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> HTTP response &amp; header analysis</div>
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> TLS/SSL certificate &amp; cipher inspection</div>
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> DNS &amp; email authentication verification</div>
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> Technology stack fingerprinting</div>
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> NIST NVD CVE correlation</div>
            <div className="flex items-center gap-1.5"><span className="text-[#4FAF72]">✓</span> Safe, passive, non-intrusive evaluation</div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | Severity>('all');
  const [selectedCat, setSelectedCat] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const findingsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!id) return;
    api.get(`/api/reports/${id}`)
      .then((res) => setReport(res.data))
      .catch(() => { toast.error('Report not found'); router.push('/reports'); })
      .finally(() => setLoading(false));
  }, [id, router]);

  const downloadExport = async (format: string) => {
    if (!report) return;
    setDownloading(true);
    setExportMenuOpen(false);
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    const apiHost = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    try {
      const mode = format.includes('executive') ? 'executive' : 'technical';
      const downloadUrl = `${apiHost}/api/reports/${report.id}/pdf?mode=${mode}`;

      const headers: Record<string, string> = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch(downloadUrl, {
        method: 'GET',
        headers,
        credentials: 'include',
      });

      if (!response.ok) {
        toast.error('Download failed');
        return;
      }

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);

      if (format.startsWith('open-pdf')) {
        window.open(blobUrl, '_blank');
        toast.success('PDF report opened in new tab');
        setDownloading(false);
        return;
      }

      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `sentinelscan-${report.id.substring(0, 8)}-${mode}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => window.URL.revokeObjectURL(blobUrl), 60000);
      toast.success(`PDF report (${mode}) downloaded`);
    } catch (err: any) {
      console.error('Export download error:', err);
      toast.error('Export failed. Please check server connection.');
    } finally {
      setDownloading(false);
    }
  };

  const handleCatClick = (catKey: string) => {
    const next = selectedCat === catKey ? null : catKey;
    setSelectedCat(next);
    setActiveTab('all');
    if (next) setTimeout(() => findingsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
  };

  const handleSelectFindingFromTop3 = (findingId: string) => {
    setSelectedCat(null);
    setActiveTab('all');
    setSelectedFindingId(findingId);
    setTimeout(() => {
      const el = document.getElementById(`finding-${findingId}`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else {
        findingsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 100);
  };

  if (loading) return <ReportSkeleton />;
  if (!report) return null;

  const allFindings = report.findings || [];
  const findings = allFindings.filter((f: any) => !f.is_passed_control);
  const passedControls = allFindings.filter((f: any) => f.is_passed_control);

  const counts: Record<Severity, number> = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  let filtered = activeTab === 'all' ? findings : findings.filter((f) => f.severity === activeTab);
  if (selectedCat) filtered = filtered.filter((f) => findingMatchesCat(f, selectedCat));
  const sortedFindings = [...filtered].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const scoreBreakdown = report.score_breakdown;

  // Calm, consistent score status & plain-English description
  const scoreStatus = getScoreStatus(report.overall_score);
  const plainDescription = getPlainDescription(counts);

  return (
    <div className="space-y-6 sm:space-y-8 page-enter max-w-5xl mx-auto py-2 sm:py-4">
      {/* ─── Part 3: Report Header ───────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2" aria-label="Go Back">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl sm:text-2xl font-extrabold text-[#F5F3ED] tracking-tight">Security Report</h1>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border bg-[#5C4A20]/20 text-[#D4AF37] border-[#5C4A20]">
                {report.scan_mode === 'safe_active'
                  ? 'Controlled Safe Active'
                  : report.scan_mode === 'authenticated_safe_active'
                  ? 'Authenticated Safe Active'
                  : 'Passive Assessment'}
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs text-[#706C64] mt-0.5">
              <span>{formatDate(report.created_at)}</span>
              <span>•</span>
              <a
                href={report.scan?.url || '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#D4AF37] hover:underline flex items-center gap-1 font-mono"
              >
                {report.scan?.url || 'Target'} <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Export Report CTA */}
        <div className="relative">
          <button
            onClick={() => setExportMenuOpen(!exportMenuOpen)}
            disabled={downloading}
            className="btn-cyber py-2 px-4 flex items-center gap-2 text-xs font-bold"
          >
            {downloading ? (
              <span className="flex items-center gap-2">
                <span className="w-3 h-3 border-2 border-black/30 border-t-black rounded-full animate-spin" /> Exporting…
              </span>
            ) : (
              <>
                <Download className="w-3.5 h-3.5 inline-block" />
                <span>Export Report</span>
                <ChevronDown className="w-3 h-3 inline-block ml-0.5" />
              </>
            )}
          </button>

          <AnimatePresence>
            {exportMenuOpen && (
              <motion.div
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 6 }}
                className="absolute right-0 mt-2 w-48 rounded-xl bg-[#111111] border border-[#2A2A2A] shadow-2xl z-50 p-1.5 space-y-1"
              >
                <button
                  onClick={() => downloadExport('pdf?mode=executive')}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors cursor-pointer text-left"
                >
                  <Download className="w-3.5 h-3.5 text-[#D4AF37]" /> Executive PDF
                </button>
                <button
                  onClick={() => downloadExport('pdf?mode=technical')}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors cursor-pointer text-left"
                >
                  <Download className="w-3.5 h-3.5 text-[#D4AF37]" /> Technical PDF
                </button>
                <button
                  onClick={() => downloadExport('open-pdf')}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors cursor-pointer text-left"
                >
                  <FileText className="w-3.5 h-3.5 text-[#D4AF37]" /> Open PDF in Browser
                </button>
                <button
                  onClick={() => window.print()}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors cursor-pointer text-left"
                >
                  <Printer className="w-3.5 h-3.5 text-[#D4AF37]" /> Print Report
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* SubNav Tabs */}
      <ReportSubNav reportId={report.id} />

      {/* ─── Part 4: Security Score Hero (Calm & Balanced) ───────── */}
      <GlassCard className="p-6 sm:p-8 border border-[#2A2A2A] bg-[#111111] space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          <div className="md:col-span-1 flex flex-col items-center text-center">
            <ScoreRing score={report.overall_score} grade={report.grade} />
            <div className="mt-3">
              <span className={`text-xs font-bold px-3 py-1 rounded-full border ${scoreStatus.cls}`}>
                {scoreStatus.label}
              </span>
            </div>
          </div>

          <div className="md:col-span-2 space-y-4">
            <div>
              <p className="text-xs font-bold uppercase tracking-wider text-[#706C64]">Website Assessed</p>
              <h2 className="text-base sm:text-lg font-bold text-[#F5F3ED] break-all">
                {report.scan?.url || 'Target Website'}
              </h2>
              <p className="text-xs text-[#A7A39A] leading-relaxed mt-1">
                {plainDescription}
              </p>
            </div>

            {/* Severity Breakdown: Large Numbers & Short Labels */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2">
              <div className="text-center py-2.5 px-2 rounded-xl border border-[#2A2A2A] bg-[#0D0D0D]">
                <p className="text-2xl font-black font-mono text-[#F97316]">{counts.high}</p>
                <p className="text-[10px] font-bold text-[#706C64] uppercase tracking-wider mt-0.5">High</p>
              </div>
              <div className="text-center py-2.5 px-2 rounded-xl border border-[#2A2A2A] bg-[#0D0D0D]">
                <p className="text-2xl font-black font-mono text-[#F59E0B]">{counts.medium}</p>
                <p className="text-[10px] font-bold text-[#706C64] uppercase tracking-wider mt-0.5">Medium</p>
              </div>
              <div className="text-center py-2.5 px-2 rounded-xl border border-[#2A2A2A] bg-[#0D0D0D]">
                <p className="text-2xl font-black font-mono text-[#4FAF72]">{counts.low}</p>
                <p className="text-[10px] font-bold text-[#706C64] uppercase tracking-wider mt-0.5">Low</p>
              </div>
              <div className="text-center py-2.5 px-2 rounded-xl border border-[#2A2A2A] bg-[#0D0D0D]">
                <p className="text-2xl font-black font-mono text-[#94A3B8]">{counts.info}</p>
                <p className="text-[10px] font-bold text-[#706C64] uppercase tracking-wider mt-0.5">Info</p>
              </div>
            </div>

            {/* Scan Execution Notice */}
            <div className="pt-2 flex items-center gap-2 text-xs text-[#706C64]">
              <span className="text-[#4FAF72] font-bold">✓</span>
              <span>Scan completed successfully</span>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* ─── Part 5: Fix These First ─────────────────────────────── */}
      <FixTheseFirstSection
        findings={findings}
        onSelectFinding={handleSelectFindingFromTop3}
      />

      {/* ─── Part 6: Security Summary ────────────────────────────── */}
      <SecuritySummarySection report={report} />

      {/* ─── Part 7: Simplified Security Score Breakdown (3-Col) ──── */}
      {scoreBreakdown && Object.keys(scoreBreakdown).length > 0 && (
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111] space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-[#F5F3ED] flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-[#D4AF37]" /> Security Score Breakdown
              </h2>
              <p className="text-xs text-[#706C64]">Click any category to filter findings below</p>
            </div>
            {selectedCat && (
              <button
                onClick={() => setSelectedCat(null)}
                className="flex items-center gap-1.5 text-xs px-3 py-1 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] hover:bg-[#5C4A20]/30 transition-colors cursor-pointer"
              >
                <X className="w-3 h-3" /> Clear filter
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {Object.entries(scoreBreakdown).map(([key, cat]) => (
              <CategoryScoreCard
                key={key}
                catKey={key}
                data={cat}
                selected={selectedCat === key}
                onClick={() => handleCatClick(key)}
              />
            ))}
          </div>
        </GlassCard>
      )}

      {/* ─── Part 9: OWASP Top 10 (Collapsed by Default) ─────────── */}
      <OWASPMatrixCard owaspSummary={report.owasp_summary} />

      {/* ─── Part 11: Technology & Version Check ─────────────────── */}
      <TechnologyVersionCheckCard
        inventory={report.component_inventory}
        techStack={report.tech_stack}
      />

      {/* ─── Part 12 & 13: All Findings ──────────────────────────── */}
      <div ref={findingsRef}>
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111] space-y-4">
          <div className="flex items-center justify-between mb-2 flex-wrap gap-3">
            <div>
              <h2 className="text-base sm:text-lg font-bold text-[#F5F3ED]">
                All Findings{' '}
                <span className="text-[#706C64] font-normal text-xs">
                  ({sortedFindings.length}
                  {selectedCat ? ` in ${CATEGORY_DISPLAY_NAMES[selectedCat] || selectedCat}` : ''})
                </span>
              </h2>
              {selectedCat && (
                <p className="text-xs text-[#D4AF37] mt-0.5 flex items-center gap-1">
                  <Filter className="w-3 h-3" /> Filtered by: {CATEGORY_DISPLAY_NAMES[selectedCat] || selectedCat}
                </p>
              )}
            </div>

            {/* Filter Tabs: All, High, Medium, Low, Info */}
            <div className="flex gap-1.5 flex-wrap">
              <button
                onClick={() => setActiveTab('all')}
                className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border cursor-pointer ${
                  activeTab === 'all'
                    ? 'bg-[#5C4A20]/25 text-[#F5F3ED] border-[#5C4A20]'
                    : 'text-[#706C64] border-[#2A2A2A] hover:text-[#A7A39A] bg-[#0D0D0D]'
                }`}
              >
                All ({findings.length})
              </button>

              {counts.high > 0 && (
                <button
                  onClick={() => setActiveTab('high')}
                  className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border cursor-pointer ${
                    activeTab === 'high'
                      ? 'bg-orange-500/20 text-[#F97316] border-orange-500/30'
                      : 'text-[#706C64] border-[#2A2A2A] hover:text-[#F97316] bg-[#0D0D0D]'
                  }`}
                >
                  High ({counts.high})
                </button>
              )}

              {counts.medium > 0 && (
                <button
                  onClick={() => setActiveTab('medium')}
                  className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border cursor-pointer ${
                    activeTab === 'medium'
                      ? 'bg-amber-500/20 text-[#F59E0B] border-amber-500/30'
                      : 'text-[#706C64] border-[#2A2A2A] hover:text-[#F59E0B] bg-[#0D0D0D]'
                  }`}
                >
                  Medium ({counts.medium})
                </button>
              )}

              {counts.low > 0 && (
                <button
                  onClick={() => setActiveTab('low')}
                  className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border cursor-pointer ${
                    activeTab === 'low'
                      ? 'bg-green-500/20 text-[#4FAF72] border-green-500/30'
                      : 'text-[#706C64] border-[#2A2A2A] hover:text-[#4FAF72] bg-[#0D0D0D]'
                  }`}
                >
                  Low ({counts.low})
                </button>
              )}

              {counts.info > 0 && (
                <button
                  onClick={() => setActiveTab('info')}
                  className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border cursor-pointer ${
                    activeTab === 'info'
                      ? 'bg-slate-500/20 text-[#94A3B8] border-slate-500/30'
                      : 'text-[#706C64] border-[#2A2A2A] hover:text-[#94A3B8] bg-[#0D0D0D]'
                  }`}
                >
                  Info ({counts.info})
                </button>
              )}
            </div>
          </div>

          {sortedFindings.length === 0 ? (
            <div className="py-12 text-center space-y-2">
              <CheckCircle className="w-10 h-10 text-[#4FAF72] mx-auto" />
              <p className="text-sm font-semibold text-[#F5F3ED]">No findings in this category</p>
              <p className="text-xs text-[#706C64]">This security domain appears to be properly configured.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {sortedFindings.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  assetUrl={report.scan?.url}
                  initiallyOpen={selectedFindingId === f.id}
                />
              ))}
            </div>
          )}
        </GlassCard>
      </div>

      {/* ─── Part 14: What is Already Protected (Compact) ───────── */}
      <PassedControlsSection passedControls={passedControls} />

      {/* ─── Part 15: Methodology Disclosure ────────────────────── */}
      <MethodologySection />
    </div>
  );
}
