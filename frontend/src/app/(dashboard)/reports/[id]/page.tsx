'use client';
import { useEffect, useState, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Download, ArrowLeft, Shield, ChevronDown, ChevronUp,
  ExternalLink, AlertTriangle, CheckCircle, Globe, Lock,
  Cpu, Info, ShieldAlert, Calendar, Bug, Link2, ShieldCheck,
  Crosshair, X, Filter, Printer, FileText,
  Code, Check, AlertOctagon, Terminal, BookOpen, Layers, Zap,
} from 'lucide-react';
import ScanTimeline from '@/components/shared/ScanTimeline';
import ReportSubNav from '@/components/reports/ReportSubNav';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts';
import GlassCard from '@/components/shared/GlassCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ReportSkeleton } from '@/components/shared/LoadingSkeleton';
import api from '@/lib/api';
import { Report, Finding, Severity, OWASPMapping, MITREMapping, CategoryScore, OWASPCategoryAssessment, ComponentInventoryItem, DiscoveredEndpointItem } from '@/types';
import { formatDate, getGradeColor, getScoreColor, resolveFindingLocation, formatAssessmentStatus, formatConfidence } from '@/lib/utils';
import toast from 'react-hot-toast';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#4FAF72',
  info: '#94A3B8',
};
const CAT_COLORS: Record<string, string> = { green: '#4FAF72', yellow: '#F59E0B', orange: '#F97316', red: '#EF4444' };
const CAT_BG: Record<string, string> = { green: 'rgba(79,175,114,0.1)', yellow: 'rgba(245,158,11,0.1)', orange: 'rgba(249,115,22,0.1)', red: 'rgba(239,68,68,0.1)' };

/* ─── CVSS Gauge ─────────────────────────────────────────────── */
function CvssGauge({ score }: { score: number }) {
  const color = score >= 9 ? '#EF4444' : score >= 7 ? '#F97316' : score >= 4 ? '#F59E0B' : '#4FAF72';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-[#2A2A2A] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${(score / 10) * 100}%`, background: color }} />
      </div>
      <span className="text-xs font-mono font-bold" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  );
}

function CveBadge({ cveId }: { cveId: string }) {
  return (
    <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 transition-colors"
      onClick={(e) => e.stopPropagation()}>
      <Bug className="w-3 h-3" />{cveId}
    </a>
  );
}

function OWASPBadge({ mapping }: { mapping: OWASPMapping }) {
  return (
    <a href={mapping.reference} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-orange-500/15 text-orange-400 border border-orange-500/30 hover:bg-orange-500/25 transition-colors"
      onClick={(e) => e.stopPropagation()} title={mapping.title}>
      <Shield className="w-3 h-3" />OWASP {mapping.id}
    </a>
  );
}

function MITREBadge({ mapping }: { mapping: MITREMapping }) {
  return (
    <a href={mapping.reference} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-purple-500/15 text-purple-400 border border-purple-500/30 hover:bg-purple-500/25 transition-colors"
      onClick={(e) => e.stopPropagation()} title={mapping.technique_name}>
      <Crosshair className="w-3 h-3" />{mapping.technique_id}
    </a>
  );
}

function OWASPPanel({ mapping }: { mapping: OWASPMapping }) {
  return (
    <div className="p-3 rounded-lg bg-orange-500/5 border border-orange-500/20 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-orange-500/15 border border-orange-500/25 flex items-center justify-center flex-shrink-0">
            <Shield className="w-4 h-4 text-orange-400" />
          </div>
          <div>
            <p className="text-[10px] text-orange-400/70 uppercase tracking-wider font-semibold">OWASP Top 10 (2025) · {mapping.id}</p>
            <p className="text-xs font-bold text-orange-300">{mapping.title}</p>
          </div>
        </div>
        <a href={mapping.reference} target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-1 text-[11px] text-orange-400 hover:text-orange-300 transition-colors"
          onClick={(e) => e.stopPropagation()}>
          <ExternalLink className="w-3 h-3" /> Official Reference
        </a>
      </div>
      <p className="text-xs text-[#A7A39A] leading-relaxed">{mapping.description}</p>
    </div>
  );
}

function MITREPanel({ mapping }: { mapping: MITREMapping }) {
  return (
    <div className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/25 flex items-center justify-center flex-shrink-0">
            <Crosshair className="w-4 h-4 text-purple-400" />
          </div>
          <div>
            <p className="text-[10px] text-purple-400/70 uppercase tracking-wider font-semibold">MITRE ATT&CK · {mapping.technique_id}</p>
            <p className="text-xs font-bold text-purple-300">{mapping.technique_name}</p>
          </div>
        </div>
        <a href={mapping.reference} target="_blank" rel="noopener noreferrer"
          className="flex items-center gap-1 text-[11px] text-purple-400 hover:text-purple-300 transition-colors"
          onClick={(e) => e.stopPropagation()}>
          <ExternalLink className="w-3 h-3" /> ATT&CK Reference
        </a>
      </div>
      <p className="text-xs text-[#A7A39A] leading-relaxed">{mapping.description}</p>
    </div>
  );
}

/* ─── Clickable Category Score Card ──────────────────────────── */
function CategoryScoreCard({
  catKey, data, selected, onClick,
}: { catKey: string; data: CategoryScore; selected: boolean; onClick: () => void }) {
  const color = CAT_COLORS[data.color] || '#4FAF72';
  const bg = CAT_BG[data.color] || 'rgba(79,175,114,0.08)';
  return (
    <motion.button
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={onClick}
      className={`glass-card p-4 space-y-3 w-full text-left transition-all cursor-pointer hover:scale-[1.02] ${selected ? 'ring-2' : ''}`}
      style={{
        borderColor: selected ? color : `${color}25`,
        boxShadow: selected ? `0 0 16px ${color}30` : undefined,
      }}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-[#F5F3ED]">{data.label}</span>
        <span className="text-sm font-black font-mono" style={{ color }}>
          {data.score}<span className="text-[#706C64] font-normal">/{data.max}</span>
        </span>
      </div>
      <div className="h-2 rounded-full overflow-hidden bg-[#1A1A1A]">
        <motion.div className="h-full rounded-full" style={{ background: color }}
          initial={{ width: 0 }} animate={{ width: `${data.pct}%` }}
          transition={{ duration: 0.9, ease: 'easeOut', delay: 0.15 }} />
      </div>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-mono font-bold px-1.5 py-0.5 rounded" style={{ color, background: bg }}>{data.pct}%</span>
        <span className="text-[10px] text-[#706C64] capitalize">{data.color} posture</span>
      </div>
      {Array.isArray(data.deductions) && data.deductions.length > 0 && (
        <div className="space-y-1 pt-1.5 border-t border-[#2A2A2A]/60 text-[10px]">
          <span className="font-bold text-red-400 block uppercase tracking-wider text-[9px]">Why points were deducted ({data.deductions.length})</span>
          {data.deductions.slice(0, 2).map((d: any, idx: number) => (
            <div key={idx} className="flex items-center justify-between text-[#A7A39A] gap-2">
              <span className="truncate">- {d.finding_title}</span>
              <span className="font-mono text-red-400 font-bold flex-shrink-0">-{d.points_deducted} pts</span>
            </div>
          ))}
        </div>
      )}
      {!selected && Array.isArray(data.recommendations) && data.recommendations.length > 0 && (!data.deductions || data.deductions.length === 0) && (
        <div className="space-y-1 pt-1 border-t border-[#2A2A2A]">
          {data.recommendations.slice(0, 2).map((rec, i) => (
            <p key={i} className="text-[10px] text-[#A7A39A] leading-snug flex gap-1.5">
              <span className="text-[#D4B978] font-bold flex-shrink-0">•</span>
              <span className="line-clamp-1">{rec}</span>
            </p>
          ))}
        </div>
      )}
    </motion.button>
  );
}

/* ─── Score Ring ──────────────────────────────────────────────── */
function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const color = getScoreColor(score);
  const gradeColor = getGradeColor(grade);
  const r = 70, circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  return (
    <div className="relative w-48 h-48 mx-auto">
      <svg className="w-48 h-48 -rotate-90" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={r} fill="none" stroke="#1A1A1A" strokeWidth="14" />
        <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="14"
          strokeDasharray={`${circ} ${circ}`} strokeDashoffset={offset}
          strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1.2s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-5xl font-black text-[#F5F3ED]">{score}</span>
        <span className="text-sm text-[#A7A39A]">out of 100</span>
        <span className="text-3xl font-black mt-1" style={{ color: gradeColor }}>Grade {grade}</span>
      </div>
    </div>
  );
}

/* ─── Enriched Finding Card (Vertical Plain English Flow) ─────────────────────── */
function FindingCard({
  finding,
  assetUrl,
}: {
  finding: Finding;
  assetUrl?: string;
}) {
  const [open, setOpen] = useState(false);
  const [showTechnical, setShowTechnical] = useState(false);
  const [showReferences, setShowReferences] = useState(false);

  const isCve = !!finding.cve_id;
  const hasOwasp = !!finding.owasp_mapping;
  const hasMitre = !!finding.mitre_mapping;
  const hasStandards = isCve || hasOwasp || hasMitre || (finding.references && finding.references.length > 0);

  const plainExplanation = finding.problem || finding.description || "Security configuration issue detected.";
  const loc = resolveFindingLocation(finding, assetUrl);

  return (
    <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
      className={`glass-card overflow-hidden border border-[#2A2A2A] bg-[#111111] ${isCve ? 'border-red-500/20' : ''}`}>
      
      {/* ── Collapsed Header ── */}
      <button
        className="w-full flex items-start gap-4 p-4 text-left hover:bg-white/[0.02] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <div className="pt-0.5">
          <SeverityBadge severity={finding.severity} />
        </div>

        <div className="flex-1 min-w-0 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-bold text-[#F5F3ED] text-sm leading-snug">{finding.title}</p>
            {finding.cvss_score != null && (
              <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-black/40 text-[#D4B978] border border-[#2A2A2A]">
                CVSS {Number(finding.cvss_score).toFixed(1)}
              </span>
            )}
          </div>

          {/* Plain English 1-Liner Explanation in Collapsed View */}
          <p className="text-xs text-[#F5F3ED]/90 font-medium leading-relaxed line-clamp-2">
            {plainExplanation}
          </p>

          {/* Location Line */}
          <p className="text-[11px] text-[#706C64] flex items-center gap-1.5 truncate pt-0.5">
            <span className="text-[#A7A39A] font-semibold">{loc.label}:</span>
            <span className="text-[#D4B978] font-mono truncate">{loc.value}</span>
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-shrink-0 pt-1 text-xs font-semibold">
          <span className="text-[#D4AF37] hidden sm:inline">{open ? 'Hide details' : 'View details →'}</span>
          {open ? <ChevronUp className="w-4 h-4 text-[#706C64]" /> : <ChevronDown className="w-4 h-4 text-[#706C64]" />}
        </div>
      </button>

      {/* ── Expanded Vertical Flow ── */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-[#2A2A2A] px-5 pb-6 pt-4 space-y-5"
          >

            {/* 1. WHAT'S WRONG? */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#D4AF37]">
                WHAT&apos;S WRONG?
              </p>
              <p className="text-xs text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#2A2A2A] font-medium">
                {finding.problem || finding.description}
              </p>
            </div>

            {/* 2. WHERE WE FOUND IT */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <p className="text-xs font-extrabold uppercase tracking-wider text-[#A7A39A]">
                  WHERE WE FOUND IT
                </p>
                <span className="text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] flex-shrink-0">
                  {loc.badge}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] text-[#706C64] uppercase font-semibold">{loc.label}</p>
                  <p className="text-xs font-mono font-bold text-[#D4AF37] truncate mt-0.5">
                    {loc.value}
                  </p>
                </div>
              </div>
            </div>

            {/* 3. WHY IT MATTERS */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#F97316]">
                WHY IT MATTERS
              </p>
              <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                <p className="text-xs text-[#F5F3ED] leading-relaxed">
                  {finding.impact || "Without this setting, someone on an unsafe network could potentially interfere with a visitor's connection before it is securely established."}
                </p>
              </div>
            </div>

            {/* 4. HOW TO FIX IT */}
            <div className="space-y-2">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#4FAF72]">
                HOW TO FIX IT
              </p>

              {finding.recommendation && (
                <p className="text-xs text-[#F5F3ED] leading-relaxed bg-[#0D0D0D] p-3 rounded-lg border border-[#2A2A2A]">
                  {finding.recommendation}
                </p>
              )}

              {finding.fix_steps && finding.fix_steps.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  {finding.fix_steps.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-xs text-[#F5F3ED] bg-[#161616] p-2 rounded border border-[#2A2A2A]">
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
                    Recommended Server Configuration
                  </p>
                  <pre className="text-[11px] text-[#D4AF37] bg-black/80 p-3 rounded-lg block font-mono overflow-x-auto border border-[#5C4A20]/40 leading-relaxed whitespace-pre-wrap">
                    {finding.configuration_example}
                  </pre>
                </div>
              )}
            </div>

            {/* 5. HOW TO CHECK THE FIX */}
            <div className="space-y-1.5">
              <p className="text-xs font-extrabold uppercase tracking-wider text-[#4FAF72]">
                HOW TO CHECK THE FIX
              </p>
              <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-xs text-[#F5F3ED] leading-relaxed">
                After making the change, run another SentinelScan scan. The finding should disappear once SentinelScan confirms the required setting is present.
              </div>
            </div>

            {/* ── 6. ASSESSMENT EVIDENCE (Expandable / Secondary) ── */}
            <div className="pt-2 border-t border-[#2A2A2A]/60">
              <button
                type="button"
                onClick={() => setShowTechnical(!showTechnical)}
                className="w-full flex items-center justify-between py-2 text-xs font-bold uppercase tracking-wider text-[#A7A39A] hover:text-[#F5F3ED] transition-colors"
              >
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#D4AF37]" />
                  {showTechnical ? '▲ Hide Assessment Evidence' : '▼ Assessment Evidence'}
                </span>
                <span className="text-[10px] font-normal text-[#706C64]">Evidence &amp; Confidence</span>
              </button>

              {showTechnical && (
                <div className="mt-2 space-y-3 p-3.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-xs">
                  <div>
                    <span className="text-[10px] text-[#706C64] uppercase font-bold block mb-0.5">Detection Category</span>
                    <span className="text-[#F5F3ED] font-medium">{finding.category}</span>
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
                </div>
              )}
            </div>

            {/* ── 7. SECURITY REFERENCES (Expandable / Secondary) ── */}
            {hasStandards && (
              <div className="pt-1 border-t border-[#2A2A2A]/60">
                <button
                  type="button"
                  onClick={() => setShowReferences(!showReferences)}
                  className="w-full flex items-center justify-between py-2 text-xs font-bold uppercase tracking-wider text-[#A7A39A] hover:text-[#F5F3ED] transition-colors"
                >
                  <span className="flex items-center gap-1.5">
                    <BookOpen className="w-3.5 h-3.5 text-[#D4AF37]" />
                    {showReferences ? '▲ Hide Security References' : '▼ Security References'}
                  </span>
                  <span className="text-[10px] font-normal text-[#706C64]">OWASP, MITRE, CWE</span>
                </button>

                {showReferences && (
                  <div className="mt-2 space-y-3 p-3.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-xs">
                    {hasOwasp && <OWASPPanel mapping={finding.owasp_mapping!} />}
                    {hasMitre && <MITREPanel mapping={finding.mitre_mapping!} />}

                    {isCve && (
                      <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-red-400" />
                          <span className="font-bold text-red-300">CVE ID: {finding.cve_id}</span>
                        </div>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[#D4AF37] hover:underline flex items-center gap-1 text-[11px]"
                        >
                          View on NVD <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    )}

                    {finding.references && finding.references.length > 0 && (
                      <div>
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
                  </div>
                )}
              </div>
            )}

            {/* ── Link to Finding Details ── */}
            {finding.id && (
              <div className="pt-2 border-t border-[#2A2A2A]/40 flex justify-end">
                <Link
                  href={`/findings/${finding.id}`}
                  className="inline-flex items-center gap-1.5 text-xs text-[#D4AF37] hover:underline font-semibold"
                >
                  Open Finding Details &amp; Triage Workspace <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
            )}

          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ─── OWASP Top 10 Assessment Matrix Component ────────────── */
function OWASPMatrixCard({ owaspSummary }: { owaspSummary?: Record<string, OWASPCategoryAssessment> }) {
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

  const statusStyles: Record<string, { bg: string; text: string; border: string }> = {
    PASS: { bg: 'bg-emerald-500/15', text: 'text-emerald-400', border: 'border-emerald-500/30' },
    FAIL: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30' },
    INCONCLUSIVE: { bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/30' },
    NOT_APPLICABLE: { bg: 'bg-slate-500/15', text: 'text-slate-400', border: 'border-slate-500/30' },
    NOT_VERIFIABLE: { bg: 'bg-purple-500/15', text: 'text-purple-400', border: 'border-purple-500/30' },
  };

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-orange-500/15 border border-orange-500/25 flex items-center justify-center">
            <Shield className="w-5 h-5 text-orange-400" />
          </div>
          <div>
            <h3 className="font-bold text-[#F5F3ED] text-base">OWASP Top 10:2025 Assessment Matrix</h3>
            <p className="text-xs text-[#706C64]">Assessment mechanisms implemented across all 10 categories</p>
          </div>
        </div>
        <span className="text-[10px] font-mono text-[#D4AF37] px-2.5 py-1 rounded-full bg-[#5C4A20]/20 border border-[#5C4A20]">
          Verified Evaluation
        </span>
      </div>

      <div className="p-3 mb-4 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-xs text-[#A7A39A] leading-relaxed">
        <strong className="text-[#D4AF37]">Assessment Boundary:</strong> SentinelScan provides OWASP Top 10:2025 assessment coverage across A01-A10 using passive analysis, controlled non-destructive testing, and evidence-assisted assessment. Detection and verification depth varies by category.
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {categories.map((c) => {
          const assessment = owaspSummary?.[c.key];
          const rawStatus = assessment?.status || 'PASS';
          const { label: statusLabel, bg, text, border } = formatAssessmentStatus(rawStatus);
          const isExpanded = expandedCat === c.key;

          return (
            <div
              key={c.key}
              className="p-3.5 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] hover:border-[#383838] transition-all cursor-pointer"
              onClick={() => setExpandedCat(isExpanded ? null : c.key)}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className="text-xs font-mono font-bold text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded border border-orange-500/20">
                    {c.id}
                  </span>
                  <span className="text-xs font-semibold text-[#F5F3ED] truncate">{c.name}</span>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${bg} ${text} ${border}`}>
                  {statusLabel}
                </span>
              </div>

              {assessment && (
                <div className="mt-2 text-[11px] text-[#A7A39A] flex items-center justify-between">
                  <span>Method: {assessment.method?.split(',')[0]}</span>
                  <span className="font-mono text-[#706C64]">{assessment.findings_count} finding{assessment.findings_count !== 1 ? 's' : ''}</span>
                </div>
              )}

              {isExpanded && assessment && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="mt-3 pt-3 border-t border-[#2A2A2A] space-y-1.5 text-[11px]"
                >
                  <p className="text-[#D4AF37] font-semibold">Evaluation Method:</p>
                  <p className="text-[#A7A39A]">{assessment.method}</p>
                  <p className="text-[#706C64] font-semibold mt-1">Scope &amp; Technical Limitations:</p>
                  <p className="text-[#706C64]">{assessment.limitations}</p>
                </motion.div>
              )}
            </div>
          );
        })}
      </div>
    </GlassCard>
  );
}

/* ─── Component Lifecycle Inventory Component ────────────────── */
function ComponentInventoryCard({ inventory }: { inventory?: ComponentInventoryItem[] }) {
  if (!inventory || inventory.length === 0) return null;

  const statusColors: Record<string, string> = {
    SUPPORTED: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/15',
    UPDATE_AVAILABLE: 'text-blue-400 border-blue-500/30 bg-blue-500/15',
    SECURITY_SUPPORT_ENDED: 'text-amber-400 border-amber-500/30 bg-amber-500/15',
    END_OF_LIFE: 'text-red-400 border-red-500/30 bg-red-500/15',
    LIFECYCLE_UNKNOWN: 'text-slate-400 border-slate-500/30 bg-slate-500/15',
    VERSION_UNKNOWN: 'text-slate-400 border-slate-500/30 bg-slate-500/15',
  };

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-500/15 border border-blue-500/25 flex items-center justify-center">
            <Cpu className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="font-bold text-[#F5F3ED] text-base">Component Intelligence &amp; Lifecycle Inventory</h3>
            <p className="text-xs text-[#706C64]">{inventory.length} components fingerprinted and correlated with vendor lifecycles</p>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-[#2A2A2A] text-[#706C64]">
              <th className="pb-2.5 font-semibold">Technology</th>
              <th className="pb-2.5 font-semibold">Category</th>
              <th className="pb-2.5 font-semibold">Detected Version</th>
              <th className="pb-2.5 font-semibold">Confidence</th>
              <th className="pb-2.5 font-semibold">Latest Release</th>
              <th className="pb-2.5 font-semibold">EOL Date</th>
              <th className="pb-2.5 font-semibold text-right">Lifecycle Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#2A2A2A]/40 text-[#A7A39A]">
            {inventory.map((comp, idx) => {
              const st = comp.lifecycle_status || 'LIFECYCLE_UNKNOWN';
              const badgeClass = statusColors[st] || statusColors.LIFECYCLE_UNKNOWN;
              return (
                <tr key={idx} className="hover:bg-[#151515] transition-colors">
                  <td className="py-3 font-semibold text-[#F5F3ED]">{comp.technology}</td>
                  <td className="py-3 text-[11px]">{comp.category}</td>
                  <td className="py-3 font-mono text-[#D4AF37]">
                    {comp.normalized_version || comp.raw_version || '—'}
                    {comp.vendor_suffix && <span className="text-[10px] text-[#706C64] block">{comp.vendor_suffix}</span>}
                  </td>
                  <td className="py-3 font-mono text-[10px]">{formatConfidence(comp.version_confidence)}</td>
                  <td className="py-3 font-mono text-[11px]">{comp.latest_version || '—'}</td>
                  <td className="py-3 font-mono text-[11px]">{comp.eol_date || '—'}</td>
                  <td className="py-3 text-right">
                    <span className={`inline-block text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${badgeClass}`}>
                      {st.replace(/_/g, ' ')}
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

/* ─── Discovered Endpoints Component ─────────────────────────── */
function DiscoveredEndpointsCard({ endpoints }: { endpoints?: DiscoveredEndpointItem[] }) {
  if (!endpoints || endpoints.length <= 1) return null;

  return (
    <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-9 h-9 rounded-xl bg-purple-500/15 border border-purple-500/25 flex items-center justify-center">
          <Globe className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h3 className="font-bold text-[#F5F3ED] text-base">Same-Origin Crawler Discovered Endpoints</h3>
          <p className="text-xs text-[#706C64]">{endpoints.length} endpoints discovered during bounded crawl</p>
        </div>
      </div>

      <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
        {endpoints.map((ep, idx) => (
          <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-xs font-mono">
            <div className="flex items-center gap-2 truncate">
              <span className="text-[10px] font-bold text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                {ep.method}
              </span>
              <span className="text-[#A7A39A] truncate">{ep.url}</span>
            </div>
            {ep.status && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${ep.status < 400 ? 'text-emerald-400' : 'text-amber-400'}`}>
                {ep.status}
              </span>
            )}
          </div>
        ))}
      </div>
    </GlassCard>
  );
}

type FilterTab = 'all' | 'cve' | 'owasp' | 'mitre' | Severity;

/* ─── Category keyword mapping ────────────────────────────────── */
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

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<FilterTab>('all');
  const [selectedCat, setSelectedCat] = useState<string | null>(null);
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
      // Never pass the access JWT in the query string — browser history and
      // server access logs would retain it. Always authenticate via the
      // Authorization header; the open-in-new-tab flow fetches a Blob and opens
      // an object URL instead of opening a URL that embeds ?token=.
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

  if (loading) return <ReportSkeleton />;
  if (!report) return null;

  const allFindings = report.findings || [];
  const findings = allFindings.filter((f: any) => !f.is_passed_control);
  const passedControls = allFindings.filter((f: any) => f.is_passed_control);

  const counts: any = SEV_ORDER.reduce((a: any, s) => { a[s] = findings.filter((f) => f.severity === s).length; return a; }, {});
  const cveFindings = findings.filter((f) => !!f.cve_id).sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
  const owaspFindings = findings.filter((f) => !!f.owasp_mapping);
  const mitreFindings = findings.filter((f) => !!f.mitre_mapping);

  let filtered = activeTab === 'all' ? findings : activeTab === 'cve' ? cveFindings : activeTab === 'owasp' ? owaspFindings : activeTab === 'mitre' ? mitreFindings : findings.filter((f) => f.severity === activeTab);
  if (selectedCat) filtered = filtered.filter((f) => findingMatchesCat(f, selectedCat));
  const sortedFindings = [...filtered].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const pieData = SEV_ORDER.filter((s) => counts[s] > 0).map((s) => ({ name: s, value: counts[s] }));
  const barData = SEV_ORDER.filter((s) => counts[s] > 0).map((s) => ({ severity: s.charAt(0).toUpperCase() + s.slice(1), count: counts[s], fill: SEV_COLORS[s] }));

  const owaspCategories = owaspFindings.reduce((acc: any, f) => { const k = f.owasp_mapping!.id; if (!acc[k]) acc[k] = { ...f.owasp_mapping!, count: 0 }; acc[k].count++; return acc; }, {});
  const mitreCategories = Array.from(mitreFindings.reduce((map: any, f) => { const t = f.mitre_mapping!; if (!map.has(t.technique_id)) map.set(t.technique_id, { ...t, count: 0 }); map.get(t.technique_id)!.count++; return map; }, new Map()).values());
  const scoreBreakdown = report.score_breakdown;

  return (
    <div className="space-y-8 page-enter max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2"><ArrowLeft className="w-4 h-4" /></button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-[#F5F3ED]">Security Report</h1>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border bg-[#5C4A20]/20 text-[#D4AF37] border-[#5C4A20]">
                {report.scan_mode === 'safe_active'
                  ? 'Controlled Safe Active'
                  : report.scan_mode === 'authenticated_safe_active'
                  ? 'Authenticated Safe Active'
                  : 'Passive Assessment'}
              </span>
            </div>
            <p className="text-xs text-[#706C64]">{formatDate(report.created_at)}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Export Dropdown */}
          <div className="relative">
            <button
              onClick={() => setExportMenuOpen(!exportMenuOpen)}
              disabled={downloading}
              className="btn-cyber py-2 px-5 flex items-center gap-2"
            >
              {downloading ? (
                <span className="flex items-center gap-2">
                  <span className="w-3 h-3 border-2 border-black/30 border-t-black rounded-full animate-spin" /> Exporting…
                </span>
              ) : (
                <>
                  <span><Download className="w-4 h-4 inline-block mr-1.5" /> Export Report <ChevronDown className="w-3.5 h-3.5 inline-block ml-1" /></span>
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
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4 text-[#D4AF37]" /> Executive PDF
                  </button>
                  <button
                    onClick={() => downloadExport('pdf?mode=technical')}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors"
                  >
                    <Download className="w-4 h-4 text-[#D4AF37]" /> Technical PDF
                  </button>
                  <button
                    onClick={() => downloadExport('open-pdf')}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors"
                  >
                    <FileText className="w-4 h-4 text-[#D4AF37]" /> Open PDF in Browser
                  </button>
                  <button
                    onClick={() => window.print()}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#5C4A20]/20 rounded-lg transition-colors"
                  >
                    <Printer className="w-4 h-4 text-[#D4AF37]" /> Print Report
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* SubNav Tabs */}
      <ReportSubNav reportId={report.id} />

      {/* Summary Hero */}
      <GlassCard className="p-8 border border-[#2A2A2A] bg-[#111111]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-center">
          <div className="md:col-span-1 flex flex-col items-center text-center">
            <ScoreRing score={report.overall_score} grade={report.grade} />
            <div className="mt-4"><span className={`severity-badge badge-${report.risk_level}`}>{report.risk_level} risk</span></div>
          </div>
          <div className="md:col-span-2 space-y-4">
            <div><h2 className="text-lg font-bold text-[#F5F3ED] mb-1 break-all">{report.scan?.url || 'Security Assessment'}</h2><p className="text-sm text-[#A7A39A] leading-relaxed">{report.summary}</p></div>
            <div className="grid grid-cols-5 gap-2">
              {SEV_ORDER.map((sev) => (
                <div key={sev} className="text-center py-2 rounded-lg border border-[#2A2A2A] bg-[#0D0D0D]">
                  <p className="text-xl font-black" style={{ color: SEV_COLORS[sev] }}>{counts[sev]}</p>
                  <p className="text-[10px] text-[#706C64] capitalize mt-0.5">{sev}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Executive Summary Grid */}
      {report.executive_summary && typeof report.executive_summary === 'object' && (
        <GlassCard className="p-6 space-y-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between border-b border-[#2A2A2A]/60 pb-3 flex-wrap gap-2">
            <h3 className="font-bold text-[#F5F3ED] text-base flex items-center gap-2">
              <Shield className="w-5 h-5 text-[#D4AF37]" /> Executive Security Assessment Summary
            </h3>
            {report.executive_summary.overall_risk && (
              <span className="text-xs font-mono font-bold px-3 py-1 rounded-full bg-red-500/15 text-[#EF4444] border border-red-500/30">
                {report.executive_summary.overall_risk}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
            {/* Business Impact */}
            {report.executive_summary.business_impact && (
              <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-1.5">
                <span className="font-bold text-[#EF4444] uppercase tracking-wider text-[10px] block">Business & Compliance Impact</span>
                <p className="text-[#A7A39A] leading-relaxed">{report.executive_summary.business_impact}</p>
              </div>
            )}

            {/* Strengths */}
            {Array.isArray(report.executive_summary.strengths) && report.executive_summary.strengths.length > 0 && (
              <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-1.5">
                <span className="font-bold text-[#4FAF72] uppercase tracking-wider text-[10px] block">Security Strengths</span>
                <ul className="space-y-1 text-[#A7A39A]">
                  {report.executive_summary.strengths.map((s: string, i: number) => (
                    <li key={i} className="flex items-center gap-2"><CheckCircle className="w-3.5 h-3.5 text-[#4FAF72] flex-shrink-0" /><span>{s}</span></li>
                  ))}
                </ul>
              </div>
            )}

            {/* Weaknesses */}
            {Array.isArray(report.executive_summary.weaknesses) && report.executive_summary.weaknesses.length > 0 && (
              <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-1.5">
                <span className="font-bold text-[#F97316] uppercase tracking-wider text-[10px] block">Key Weaknesses</span>
                <ul className="space-y-1 text-[#A7A39A]">
                  {report.executive_summary.weaknesses.map((w: string, i: number) => (
                    <li key={i} className="flex items-center gap-2"><AlertTriangle className="w-3.5 h-3.5 text-[#F97316] flex-shrink-0" /><span>{w}</span></li>
                  ))}
                </ul>
              </div>
            )}

            {/* Quick Wins */}
            {Array.isArray(report.executive_summary.quick_wins) && report.executive_summary.quick_wins.length > 0 && (
              <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-1.5">
                <span className="font-bold text-[#D4AF37] uppercase tracking-wider text-[10px] block">Recommended Quick Wins</span>
                <ul className="space-y-1 text-[#A7A39A]">
                  {report.executive_summary.quick_wins.map((qw: string, i: number) => (
                    <li key={i} className="flex items-center gap-2"><Zap className="w-3.5 h-3.5 text-[#D4AF37] flex-shrink-0" /><span>{qw}</span></li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </GlassCard>
      )}

      {/* ─── Advanced Score Breakdown (Clickable) ──────────────── */}
      {scoreBreakdown && Object.keys(scoreBreakdown).length > 0 && (
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between mb-2 flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-[#5C4A20]/20 border border-[#5C4A20] flex items-center justify-center"><ShieldCheck className="w-5 h-5 text-[#D4AF37]" /></div>
              <div><h3 className="font-bold text-[#F5F3ED]">Security Score Breakdown</h3><p className="text-xs text-[#706C64] mt-0.5">Click a category to filter findings below · Total: {report.overall_score}/100</p></div>
            </div>
            {selectedCat && (
              <button onClick={() => setSelectedCat(null)} className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] hover:bg-[#5C4A20]/30 transition-colors">
                <X className="w-3 h-3" /> Clear filter
              </button>
            )}
          </div>

          {/* Summary bar */}
          <div className="grid grid-cols-7 gap-1 mb-5 p-3 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A]">
            {Object.entries(scoreBreakdown).map(([key, cat]) => {
              const color = CAT_COLORS[cat.color] || '#D4AF37';
              return (
                <div key={key} className="flex flex-col items-center gap-0.5 px-0.5">
                  <span className="text-sm font-black font-mono" style={{ color }}>{cat.score}</span>
                  <span className="text-[9px] text-[#A7A39A] text-center leading-tight">{cat.label.split('/')[0].split(' ')[0]}</span>
                  <span className="text-[9px] text-[#706C64]">/{cat.max}</span>
                </div>
              );
            })}
          </div>

          {/* Clickable cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {Object.entries(scoreBreakdown).map(([key, cat]) => (
              <CategoryScoreCard key={key} catKey={key} data={cat}
                selected={selectedCat === key}
                onClick={() => handleCatClick(key)} />
            ))}
          </div>

          {/* Category bar chart */}
          <div className="mt-6 pt-5 border-t border-[#2A2A2A]">
            <p className="text-xs font-semibold text-[#A7A39A] uppercase tracking-wider mb-3">Score comparison</p>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={Object.entries(scoreBreakdown).map(([k, c]) => ({ name: c.label.split('/')[0].split(' ')[0], score: c.score, max: c.max, pct: c.pct, fill: CAT_COLORS[c.color] || '#D4AF37' }))} barSize={18}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2A2A2A" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#706C64', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#706C64', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#111111', border: '1px solid #2A2A2A', borderRadius: '8px', color: '#F5F3ED', fontSize: 11 }}
                  formatter={(val: any, name: any, props: any) => [`${props.payload.score}/${props.payload.max} (${props.payload.pct}%)`, 'Score']} />
                <Bar dataKey="pct" radius={[4, 4, 0, 0]}>
                  {Object.entries(scoreBreakdown).map(([k, c]) => (
                    <Cell key={k} fill={CAT_COLORS[c.color] || '#D4AF37'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </GlassCard>
      )}

      {/* Assessment Methodology */}
      <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-bold text-[#F5F3ED] text-base flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[#D4AF37]" /> Assessment Methodology
          </h3>
          <span className="text-[10px] font-mono uppercase px-2.5 py-0.5 rounded-full bg-[#5C4A20]/20 text-[#D4AF37] border border-[#5C4A20] font-bold">
            Passive &amp; Non-Destructive
          </span>
        </div>
        <p className="text-xs text-[#A7A39A] leading-relaxed mb-4">
          SentinelScan executes exclusively non-destructive, passive assessments against publicly accessible network and application endpoints.
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs text-[#F5F3ED]">
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> HTTP Response Analysis
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> Security Header Inspection
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> TLS Certificate Analysis
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> DNS Record Analysis
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> Technology Fingerprinting
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A]">
            <span className="text-[#D4AF37] font-bold">✓</span> NIST NVD CVE Correlation
          </div>
        </div>
        <div className="mt-4 pt-3 border-t border-[#2A2A2A]/40 flex items-center gap-4 text-[11px] text-[#706C64] font-mono flex-wrap">
          <span>• No Exploitation</span>
          <span>• No Brute Force</span>
          <span>• No Destructive Testing</span>
        </div>
      </GlassCard>

      {/* Scan Timeline */}
      <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
        <ScanTimeline timeline={report.timeline} progress={100} />
      </GlassCard>

      {/* OWASP Top 10 Matrix Card */}
      <OWASPMatrixCard owaspSummary={report.owasp_summary} />

      {/* Component Lifecycle Inventory Card */}
      <ComponentInventoryCard inventory={report.component_inventory} />

      {/* Discovered Endpoints Card */}
      <DiscoveredEndpointsCard endpoints={report.discovered_endpoints} />

      {/* OWASP */}
      {owaspFindings.length > 0 && (
        <GlassCard className="p-6 border border-orange-500/20 bg-[#111111]">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-orange-500/15 border border-orange-500/25 flex items-center justify-center"><Shield className="w-5 h-5 text-orange-400" /></div>
            <div><h3 className="font-bold text-[#F5F3ED]">OWASP Top 10 Mapping</h3><p className="text-xs text-[#706C64] mt-0.5">{owaspFindings.length} findings mapped · OWASP Top 10 (2025)</p></div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {Object.values(owaspCategories).map((cat: any) => (
              <a key={cat.id} href={cat.reference} target="_blank" rel="noopener noreferrer"
                className="flex items-start gap-3 p-3 rounded-xl bg-orange-500/5 border border-orange-500/20 hover:bg-orange-500/10 transition-colors">
                <div className="w-10 h-10 rounded-lg bg-orange-500/20 border border-orange-500/30 flex items-center justify-center flex-shrink-0"><span className="text-xs font-black text-orange-400">{cat.id}</span></div>
                <div className="min-w-0"><p className="text-xs font-bold text-orange-300 leading-tight">{cat.title}</p><p className="text-[11px] text-[#706C64] mt-0.5">{cat.count} finding{cat.count !== 1 ? 's' : ''}</p></div>
              </a>
            ))}
          </div>
        </GlassCard>
      )}

      {/* MITRE */}
      {mitreFindings.length > 0 && (
        <GlassCard className="p-6 border border-purple-500/20 bg-[#111111]">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-purple-500/15 border border-purple-500/25 flex items-center justify-center"><Crosshair className="w-5 h-5 text-purple-400" /></div>
            <div><h3 className="font-bold text-[#F5F3ED]">MITRE ATT&amp;CK Mapping</h3><p className="text-xs text-[#706C64] mt-0.5">{mitreFindings.length} findings mapped to ATT&amp;CK techniques</p></div>
          </div>
          <div className="space-y-2">
            {mitreCategories.map((tech: any) => (
              <a key={tech.technique_id} href={tech.reference} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-4 p-3 rounded-xl bg-purple-500/5 border border-purple-500/20 hover:bg-purple-500/10 transition-colors">
                <div className="w-16 h-9 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center flex-shrink-0"><span className="text-[11px] font-black font-mono text-purple-400">{tech.technique_id}</span></div>
                <div className="flex-1 min-w-0"><p className="text-xs font-bold text-purple-300">{tech.technique_name}</p><p className="text-[11px] text-[#706C64] truncate">{tech.description.slice(0, 90)}…</p></div>
                <span className="flex-shrink-0 text-[11px] px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-400 border border-purple-500/25 font-bold">{tech.count} finding{tech.count !== 1 ? 's' : ''}</span>
              </a>
            ))}
          </div>
        </GlassCard>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <h3 className="font-bold text-[#F5F3ED] mb-4">Security Coverage Radar</h3>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={scoreBreakdown ? Object.values(scoreBreakdown).map((c) => ({ subject: c.label.split('/')[0].split(' ')[0], score: c.pct })) : [{ subject: 'SSL', score: 50 }, { subject: 'Headers', score: 50 }, { subject: 'DNS', score: 50 }, { subject: 'Tech', score: 50 }, { subject: 'Content', score: 50 }]}>
              <PolarGrid stroke="#2A2A2A" /><PolarAngleAxis dataKey="subject" tick={{ fill: '#706C64', fontSize: 11 }} />
              <Radar name="Score" dataKey="score" stroke="#D4AF37" fill="#D4AF37" fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </GlassCard>
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <h3 className="font-bold text-[#F5F3ED] mb-4">Findings by Severity</h3>
          {pieData.length > 0 ? (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={180}>
                <PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3} dataKey="value">
                  {pieData.map((entry) => <Cell key={entry.name} fill={SEV_COLORS[entry.name as Severity]} />)}
                </Pie><Tooltip contentStyle={{ background: '#111111', border: '1px solid #2A2A2A', borderRadius: '8px', color: '#F5F3ED' }} /></PieChart>
              </ResponsiveContainer>
              <div className="flex-1 space-y-2">
                {pieData.map((d) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full" style={{ background: SEV_COLORS[d.name as Severity] }} /><span className="capitalize text-[#A7A39A]">{d.name}</span></div>
                    <span className="font-bold text-[#F5F3ED]">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center"><div className="text-center"><CheckCircle className="w-12 h-12 text-[#4FAF72] mx-auto mb-3" /><p className="text-[#4FAF72] font-semibold">No findings</p></div></div>
          )}
        </GlassCard>
      </div>

      {/* Severity Bar Chart */}
      {barData.length > 0 && (
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <h3 className="font-bold text-[#F5F3ED] mb-4">Findings Count by Severity</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={barData} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A2A2A" vertical={false} />
              <XAxis dataKey="severity" tick={{ fill: '#706C64', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: '#706C64', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#111111', border: '1px solid #2A2A2A', borderRadius: '8px', color: '#F5F3ED' }} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {barData.map((entry) => <Cell key={entry.severity} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </GlassCard>
      )}

      {/* SSL / Tech / DNS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center gap-2 mb-3"><Lock className="w-4 h-4 text-[#D4AF37]" /><h3 className="font-bold text-[#F5F3ED] text-sm">SSL/TLS</h3></div>
          {report.ssl_info ? (
            <div className="space-y-2 text-xs">
              <div className="flex justify-between"><span className="text-[#706C64]">TLS Version</span><span className="text-[#A7A39A] font-mono">{report.ssl_info.tls_version || '—'}</span></div>
              <div className="flex justify-between"><span className="text-[#706C64]">Issuer</span><span className="text-[#A7A39A] truncate max-w-[120px] text-right">{report.ssl_info.certificate?.issuer || '—'}</span></div>
              <div className="flex justify-between"><span className="text-[#706C64]">Expires</span><span className={`font-mono ${(report.ssl_info.certificate?.days_remaining || 0) < 30 ? 'text-red-400' : 'text-[#4FAF72]'}`}>{report.ssl_info.certificate?.days_remaining ?? '?'}d</span></div>
            </div>
          ) : <p className="text-xs text-[#706C64]">No SSL data</p>}
        </GlassCard>
        <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center gap-2 mb-3"><Cpu className="w-4 h-4 text-[#D4AF37]" /><h3 className="font-bold text-[#F5F3ED] text-sm">Tech Stack</h3></div>
          {report.tech_stack && Object.keys(report.tech_stack).length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {Object.entries(report.tech_stack).slice(0, 10).map(([tech, info]) => {
                const conf = (info as any)?.confidence ?? 95;
                const confColor = conf >= 90 ? '#4FAF72' : conf >= 75 ? '#F59E0B' : '#D4AF37';
                return (
                  <span key={tech} className="inline-flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED]">
                    <span className="font-medium">{tech}{(info as any)?.version ? ` v${(info as any).version}` : ''}</span>
                    <span className="text-[10px] font-mono font-bold px-1 rounded bg-black/40" style={{ color: confColor }}>
                      {conf}%
                    </span>
                  </span>
                );
              })}
            </div>
          ) : <p className="text-xs text-[#706C64]">No tech detected</p>}
        </GlassCard>
        <GlassCard className="p-5 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center gap-2 mb-3"><Globe className="w-4 h-4 text-[#D4AF37]" /><h3 className="font-bold text-[#F5F3ED] text-sm">DNS / Email</h3></div>
          {report.dns_info ? (
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center gap-2">{report.dns_info.spf ? <CheckCircle className="w-3 h-3 text-[#4FAF72]" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}<span className="text-[#A7A39A]">SPF Record</span></div>
              <div className="flex items-center gap-2">{report.dns_info.dmarc ? <CheckCircle className="w-3 h-3 text-[#4FAF72]" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}<span className="text-[#A7A39A]">DMARC Policy</span></div>
              <div className="flex items-center gap-2"><Info className="w-3 h-3 text-[#706C64]" /><span className="text-[#A7A39A]">{report.dns_info.a_records?.length || 0} A record(s)</span></div>
            </div>
          ) : <p className="text-xs text-[#706C64]">No DNS data</p>}
        </GlassCard>
      </div>

      {/* CVE Summary */}
      {cveFindings.length > 0 && (
        <GlassCard className="p-6 border border-red-500/20 bg-[#111111]">
          <div className="flex items-center gap-3 mb-5">
            <div className="w-9 h-9 rounded-xl bg-red-500/15 border border-red-500/25 flex items-center justify-center"><Bug className="w-5 h-5 text-red-400" /></div>
            <div><h3 className="font-bold text-[#F5F3ED]">CVE Vulnerabilities Detected</h3><p className="text-xs text-[#706C64] mt-0.5">{cveFindings.length} CVE{cveFindings.length !== 1 ? 's' : ''} — sorted by CVSS score</p></div>
            <span className="ml-auto text-xs px-2.5 py-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/25 font-bold">{cveFindings.length} CVE{cveFindings.length !== 1 ? 's' : ''}</span>
          </div>
          <div className="space-y-2">
            <div className="grid grid-cols-12 gap-3 px-3 text-[10px] uppercase tracking-wider text-[#706C64] font-semibold">
              <div className="col-span-3">CVE ID</div><div className="col-span-3">CVSS</div><div className="col-span-2">Severity</div><div className="col-span-2 hidden md:block">Published</div><div className="col-span-2 text-right">Link</div>
            </div>
            {cveFindings.map((cve) => (
              <motion.div key={cve.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
                className="grid grid-cols-12 gap-3 items-center px-3 py-2.5 rounded-lg bg-[#0D0D0D] border border-[#2A2A2A] hover:border-red-500/25 transition-colors">
                <div className="col-span-3"><span className="text-xs font-mono font-bold text-red-400">{cve.cve_id}</span></div>
                <div className="col-span-3">{cve.cvss_score != null ? <CvssGauge score={Number(cve.cvss_score)} /> : <span className="text-xs text-[#706C64]">N/A</span>}</div>
                <div className="col-span-2"><SeverityBadge severity={cve.severity} size="sm" /></div>
                <div className="col-span-2 hidden md:block"><span className="text-xs text-[#706C64]">{cve.published_date || '—'}</span></div>
                <div className="col-span-2 text-right"><a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-[#D4AF37] hover:text-[#F5F3ED] transition-colors">NVD <ExternalLink className="w-3 h-3" /></a></div>
              </motion.div>
            ))}
          </div>
        </GlassCard>
      )}

      {/* All Findings */}
      <div ref={findingsRef}>
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
        <div className="flex items-center justify-between mb-5 flex-wrap gap-3">
          <div>
            <h3 className="font-bold text-[#F5F3ED]">All Findings <span className="text-[#706C64] font-normal text-sm">({sortedFindings.length}{selectedCat ? ` in ${scoreBreakdown?.[selectedCat]?.label || selectedCat}` : ''})</span></h3>
            {selectedCat && (
              <p className="text-xs text-[#D4AF37] mt-0.5 flex items-center gap-1">
                <Filter className="w-3 h-3" /> Filtered by category: <span className="font-semibold">{scoreBreakdown?.[selectedCat]?.label}</span>
                <button onClick={() => setSelectedCat(null)} className="ml-2 text-[#706C64] hover:text-[#F5F3ED]"><X className="w-3 h-3" /></button>
              </p>
            )}
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {[{ key: 'all', label: `All (${findings.length})`, cls: 'bg-[#5C4A20]/25 text-[#F5F3ED] border-[#5C4A20]' }].map(({ key, label, cls }) => (
              <button key={key} onClick={() => setActiveTab(key as FilterTab)}
                className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border ${activeTab === key ? cls : 'text-[#706C64] border-[#2A2A2A] hover:text-[#A7A39A] bg-[#0D0D0D]'}`}>{label}</button>
            ))}
            {cveFindings.length > 0 && <button onClick={() => setActiveTab('cve')} className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border ${activeTab === 'cve' ? 'bg-red-500/20 text-[#EF4444] border-red-500/30' : 'text-[#706C64] border-[#2A2A2A] hover:text-[#EF4444] bg-[#0D0D0D]'}`}>🐛 CVE ({cveFindings.length})</button>}
            {owaspFindings.length > 0 && <button onClick={() => setActiveTab('owasp')} className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border ${activeTab === 'owasp' ? 'bg-orange-500/20 text-[#F97316] border-orange-500/30' : 'text-[#706C64] border-[#2A2A2A] hover:text-[#F97316] bg-[#0D0D0D]'}`}>🛡 OWASP ({owaspFindings.length})</button>}
            {mitreFindings.length > 0 && <button onClick={() => setActiveTab('mitre')} className={`text-xs px-3 py-1.5 rounded-full font-medium transition-all border ${activeTab === 'mitre' ? 'bg-purple-500/20 text-[#D4AF37] border-[#D4AF37]/30' : 'text-[#706C64] border-[#2A2A2A] hover:text-[#D4AF37] bg-[#0D0D0D]'}`}>🎯 MITRE ({mitreFindings.length})</button>}
            {SEV_ORDER.map((sev) => counts[sev] > 0 && (
              <button key={sev} onClick={() => setActiveTab(sev)} className="text-xs px-3 py-1.5 rounded-full font-medium transition-all capitalize border border-[#2A2A2A] text-[#706C64] hover:text-[#A7A39A] bg-[#0D0D0D]"
                style={activeTab === sev ? { background: `${SEV_COLORS[sev]}20`, color: SEV_COLORS[sev], borderColor: `${SEV_COLORS[sev]}40` } : {}}>{sev} ({counts[sev]})</button>
            ))}
          </div>
        </div>
        {sortedFindings.length === 0 ? (
          <div className="py-12 text-center"><CheckCircle className="w-10 h-10 text-[#4FAF72] mx-auto mb-3" /><p className="text-[#A7A39A]">No findings in this category</p></div>
        ) : (
          <div className="space-y-2">{sortedFindings.map((f) => <FindingCard key={f.id} finding={f} assetUrl={report.scan?.url} />)}</div>
        )}
      </GlassCard>
      </div>

      {/* Passed Controls */}
      {passedControls.length > 0 && (
        <GlassCard className="p-6 border border-green-500/20 bg-[#111111]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-[#F5F3ED] flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-[#22C55E]" /> Passed Security Controls ({passedControls.length})
              </h3>
              <p className="text-xs text-[#706C64] mt-0.5">Verified positive security configurations and defenses</p>
            </div>
            <span className="text-xs px-2.5 py-1 rounded-full bg-green-500/15 text-[#22C55E] border border-green-500/25 font-bold">
              Verified Passed
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {passedControls.map((pc: any) => (
              <div key={pc.id} className="p-3 rounded-xl bg-green-500/5 border border-green-500/20 flex items-start gap-3">
                <CheckCircle className="w-4 h-4 text-[#22C55E] flex-shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <p className="text-xs font-bold text-green-300">{pc.title}</p>
                  <p className="text-[11px] text-[#A7A39A] mt-0.5 line-clamp-2">{pc.description}</p>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>
      )}

    </div>
  );
}
