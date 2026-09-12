'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useInView, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import {
  Shield, Zap, Globe, Lock, Eye, AlertTriangle,
  CheckCircle, ArrowRight, ChevronDown, ChevronUp,
  FileText, Cpu, Mail, Server, Code2, Activity,
  Terminal, ExternalLink, Check, Copy, Layers,
  Database, ShieldAlert, Sparkles, CheckCircle2,
  AlertCircle, Info, HelpCircle
} from 'lucide-react';
import LandingNavbar from '@/components/layout/Navbar';
import SplashCursor from '@/components/shared/SplashCursor';

/* ────────── Typing Effect ────────── */
const TYPING_PHRASES = [
  'Missing Security Headers',
  'Weak SSL/TLS Configuration',
  'Exposed Sensitive Files',
  'DNS Misconfigurations',
  'Outdated Software Versions',
  'Cookie Security Weaknesses',
  'OWASP Top 10:2025 Exposures',
  'Information Disclosure',
];

function TypingEffect() {
  const [index, setIndex] = useState(0);
  const [displayed, setDisplayed] = useState('');
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const phrase = TYPING_PHRASES[index];
    let timeout: NodeJS.Timeout;
    if (!deleting && displayed.length < phrase.length) {
      timeout = setTimeout(() => setDisplayed(phrase.slice(0, displayed.length + 1)), 50);
    } else if (!deleting && displayed.length === phrase.length) {
      timeout = setTimeout(() => setDeleting(true), 2000);
    } else if (deleting && displayed.length > 0) {
      timeout = setTimeout(() => setDisplayed(displayed.slice(0, -1)), 25);
    } else {
      setDeleting(false);
      setIndex((i) => (i + 1) % TYPING_PHRASES.length);
    }
    return () => clearTimeout(timeout);
  }, [displayed, deleting, index]);

  return (
    <span className="text-[#D4AF37] font-semibold">
      {displayed}
      <span className="animate-pulse">|</span>
    </span>
  );
}

/* ────────── Stats Counter ────────── */
function CountUp({ target, suffix = '' }: { target: number; suffix?: string }) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });

  useEffect(() => {
    if (!inView) return;
    const duration = 1200;
    const steps = 30;
    const stepTime = duration / steps;
    const increment = target / steps;
    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(current));
      }
    }, stepTime);
    return () => clearInterval(timer);
  }, [inView, target]);

  return <span ref={ref}>{count.toLocaleString()}{suffix}</span>;
}

/* ────────── Coverage Metrics ────────── */
const STATS = [
  { value: 37, suffix: '', label: 'Security Detectors', desc: 'Active across passive modules' },
  { value: 8, suffix: '', label: 'Assessment Areas', desc: 'Headers, SSL, DNS, Tech, OWASP...' },
  { value: 10, suffix: '', label: 'OWASP:2025 Risks', desc: 'Direct taxonomy mapping' },
  { value: 4, suffix: '', label: 'Report Formats', desc: 'Web, JSON, Exec & Tech PDF' },
];

/* ────────── Security Layers (One URL. Multiple Layers) ────────── */
const SECURITY_LAYERS = [
  {
    title: 'Network & Transport',
    badge: 'TLS & DNS',
    icon: Lock,
    desc: 'Deep inspection of cryptographic protocols, certificate chains, and DNS zone configurations.',
    checks: [
      'TLS 1.2 & 1.3 protocol validation',
      'Certificate expiry & chain of trust',
      'Forward secrecy cipher suite check',
      'SPF, DMARC & MX routing records',
    ],
  },
  {
    title: 'HTTP & Browser Defense',
    badge: 'Headers & Policies',
    icon: Shield,
    desc: 'Audit of defense-in-depth response headers shielding client sessions and mitigating attacks.',
    checks: [
      'Content-Security-Policy (CSP) parsing',
      'Strict-Transport-Security (HSTS) enforcement',
      'X-Frame-Options & Clickjacking defense',
      'Permissions-Policy & Referrer-Policy',
    ],
  },
  {
    title: 'Stack & CVE Intelligence',
    badge: 'Fingerprinting',
    icon: Cpu,
    desc: 'Non-invasive technology detection cross-referenced against authoritative vulnerability feeds.',
    checks: [
      'Signatures across 10 technology categories',
      'Web server & framework identification',
      'NIST NVD API v2 CVE correlation',
      'Known EOL & patch status flags',
    ],
  },
  {
    title: 'Data & Surface Exposure',
    badge: 'Privacy & Content',
    icon: Eye,
    desc: 'Detection of publicly accessible configuration files, debug endpoints, and session cookie flaws.',
    checks: [
      'Cookie flags: Secure, HttpOnly, SameSite',
      'Sensitive file exposure (.git, .env, backups)',
      'Administrative & debug portal detection',
      'Plaintext email & credential exposure',
    ],
  },
];

/* ────────── Pipeline Steps ────────── */
const PIPELINE_STEPS = [
  {
    num: '01',
    title: 'Target Validation',
    sub: 'SSRF & Safety Guard',
    desc: 'Safe URL normalization, private IP / loopback blocking, and DNS reachability verification.',
  },
  {
    num: '02',
    title: 'Passive Discovery',
    sub: 'Network & Metadata',
    desc: 'Asynchronous DNS lookups, TLS handshake analysis, and standard HTTP header collection.',
  },
  {
    num: '03',
    title: 'Security Analysis',
    sub: '37 Detector Checks',
    desc: 'Deterministic evaluation of transport ciphers, HTTP security headers, and cookie attributes.',
  },
  {
    num: '04',
    title: 'CVE Correlation',
    sub: 'NIST NVD API v2',
    desc: 'Signature matching against 23 tech profiles and query of known CVE records.',
  },
  {
    num: '05',
    title: 'OWASP & Scoring',
    sub: 'A01–A10:2025 Taxonomies',
    desc: 'Deductive score modeling (0–100) and mapping to 10 OWASP Top 10:2025 risk categories.',
  },
  {
    num: '06',
    title: 'Actionable Reporting',
    sub: '4 Delivery Formats',
    desc: 'Synthesis into interactive web dashboards, machine JSON, and downloadable Executive & Technical PDFs.',
  },
];

/* ────────── Security Modules (8 verified) ────────── */
const MODULES = [
  {
    icon: Lock,
    title: 'SSL/TLS Analysis',
    desc: 'Inspect certificate validity, TLS protocol versions, cipher configurations, and transport security indicators.',
    badge: '6 Detectors',
  },
  {
    icon: Shield,
    title: 'Security Headers',
    desc: 'Analyze HTTP security headers including CSP, HSTS, X-Frame-Options, Referrer-Policy, and Permissions-Policy.',
    badge: '11 Detectors',
  },
  {
    icon: Globe,
    title: 'DNS Security',
    desc: 'Query and evaluate DNS records including SPF policy, DMARC alignment, and MX routing configuration.',
    badge: '4 Detectors',
  },
  {
    icon: Cpu,
    title: 'Tech Fingerprinting',
    desc: 'Fingerprint web technologies across 10 categories and extract available version information for components.',
    badge: '23 Signatures',
  },
  {
    icon: Eye,
    title: 'Sensitive File Probing',
    desc: 'Probe for exposed paths including .git, .env, administrative interfaces, and backup artifacts safely.',
    badge: 'Passive Probes',
  },
  {
    icon: Code2,
    title: 'Cookie Security',
    desc: 'Evaluate Secure, HttpOnly, and SameSite attributes on all session and tracking cookies returned.',
    badge: '3 Attributes',
  },
  {
    icon: Database,
    title: 'CVE Correlation',
    desc: 'Match detected technology versions against the NIST NVD database for known CVEs and EOL status.',
    badge: 'NIST NVD v2',
  },
  {
    icon: FileText,
    title: 'Multi-Format Reports',
    desc: 'Generate Executive and Technical PDF reports alongside machine-readable JSON exports with remediation guidance.',
    badge: '4 Formats',
  },
];

/* ────────── OWASP Top 10:2025 Data ────────── */
const OWASP_CATEGORIES = [
  { code: 'A01:2025', title: 'Broken Access Control', scope: 'Administrative interfaces, exposed directories & path traversal risks' },
  { code: 'A02:2025', title: 'Security Misconfiguration', scope: 'Missing HTTP headers, default server banners & permissive CORS' },
  { code: 'A03:2025', title: 'Software Supply Chain Failures', scope: 'Outdated web components, unvetted CDN scripts & legacy frameworks' },
  { code: 'A04:2025', title: 'Cryptographic Failures', scope: 'Missing HSTS, deprecated TLS 1.0/1.1 protocols & weak ciphers' },
  { code: 'A05:2025', title: 'Injection', scope: 'Component version matching to known remote injection CVEs' },
  { code: 'A06:2025', title: 'Insecure Design', scope: 'Lack of defensive browser boundary headers like CSP & Permissions-Policy' },
  { code: 'A07:2025', title: 'Authentication Failures', scope: 'Session cookies transmitted without Secure or HttpOnly flags' },
  { code: 'A08:2025', title: 'Software & Data Integrity', scope: 'Unvalidated third-party scripts lacking integrity attributes' },
  { code: 'A09:2025', title: 'Logging & Alerting Failures', scope: 'Missing CSP report-uri/report-to directive & security contact metadata' },
  { code: 'A10:2025', title: 'Mishandling of Exceptional Conditions', scope: 'Verbose error messages, debug endpoints & stack trace disclosure' },
];

/* ────────── Why SentinelScan Cards ────────── */
const WHY_CARDS = [
  {
    icon: ShieldAlert,
    title: '100% Non-Destructive',
    desc: 'SentinelScan conducts purely passive, non-intrusive inspection of public HTTP, TLS, and DNS metadata. Zero risk of service disruption or downtime.',
  },
  {
    icon: Activity,
    title: 'Fast & Deterministic',
    desc: 'Scans execute asynchronously in 20–60 seconds. Our scoring engine uses deterministic deduction formulas rather than subjective estimates.',
  },
  {
    icon: Terminal,
    title: 'Evidence-Backed Findings',
    desc: 'Every identified issue includes raw HTTP response headers, certificate details, or DNS records so your team can verify the issue immediately.',
  },
  {
    icon: Sparkles,
    title: 'Actionable Remediation',
    desc: 'Findings pair directly with concrete configuration snippets for Nginx, Apache, and application runtimes, along with RFC and OWASP references.',
  },
];

/* ────────── Standards & Credibility ────────── */
const STANDARDS = [
  {
    name: 'OWASP Top 10:2025',
    sub: 'Application Security Taxonomy',
    desc: 'Findings classified directly into the latest 2025 risk definitions.',
  },
  {
    name: 'NIST NVD API v2',
    sub: 'CVE & CVSS Vulnerability Feeds',
    desc: 'Technology stack versions matched against authoritative vulnerability feeds.',
  },
  {
    name: 'RFC 8446 & RFC 5280',
    sub: 'TLS 1.3 & PKI Standards',
    desc: 'Rigorous inspection of cipher suites, certificate validation, and key exchanges.',
  },
  {
    name: 'RFC 7208 & RFC 7489',
    sub: 'SPF & DMARC Specifications',
    desc: 'DNS-level verification of email authentication and domain spoofing protections.',
  },
  {
    name: 'IETF & W3C Standards',
    sub: 'HTTP Security Headers',
    desc: 'Audit of CSP Level 3, HSTS (RFC 6797), Referrer Policy, and Permissions Policy.',
  },
];

/* ────────── Technical FAQ ────────── */
const FAQS = [
  {
    q: 'How does SentinelScan assess websites without causing disruption?',
    a: 'SentinelScan performs passive, non-destructive security evaluation. It analyzes the standard HTTP headers, TLS certificate handshakes, DNS records, and publicly reachable resources that any browser receives. It never executes exploit payloads, brute-force requests, or state-changing operations.',
  },
  {
    q: 'How long does an assessment take to complete?',
    a: 'Most assessments complete within 20 to 60 seconds. Because all 8 assessment stages run concurrently via an asynchronous worker pipeline, you receive live progress via real-time SSE streaming.',
  },
  {
    q: 'What authorization is required before scanning?',
    a: 'SentinelScan is engineered for website owners, security engineers, DevOps teams, and authorized auditors. Because our inspection is strictly passive and reads only public data, it does not stress target infrastructure; however, scanning should always comply with organizational policies and applicable laws.',
  },
  {
    q: 'How is the 0–100 security score and letter grade calculated?',
    a: 'Scoring starts at 100 points and applies severity deductions: Critical (-25 pts), High (-10 pts), Medium (-5 pts), and Low (-2 pts). The resulting score is mapped deterministically to letter grades: A+ (95–100), A (85–94), B (70–84), C (55–69), D (40–54), and F (<40).',
  },
  {
    q: 'What is the difference between SentinelScan and an active penetration test?',
    a: 'An active penetration test sends intrusive exploit vectors, SQL injection fuzzing, and credential attacks. SentinelScan is an Attack Surface and Passive Security Scanner: it provides instant, non-destructive baseline intelligence about your external security configuration, transport ciphers, and exposure.',
  },
  {
    q: 'What report export formats are supported?',
    a: 'SentinelScan offers four reporting options: an interactive live Web Dashboard, machine-readable JSON exports for CI/CD integration, an Executive PDF Summary tailored for stakeholders, and an in-depth Technical PDF Report with full evidence and configuration code.',
  },
];

/* ────────── Main Page Component ────────── */
export default function LandingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(0);
  const [evidenceTab, setEvidenceTab] = useState<'evidence' | 'impact' | 'fix'>('evidence');
  const [copiedCode, setCopiedCode] = useState(false);

  const copySnippet = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#070707] text-[#F5F3ED] overflow-x-hidden relative selection:bg-[#D4AF37]/30 selection:text-[#FFF]">
      {/* Background Interactive Canvas */}
      <SplashCursor
        RAINBOW_MODE={false}
        COLOR="#D4AF37"
        SPLAT_RADIUS={0.15}
        SPLAT_FORCE={3600}
        DENSITY_DISSIPATION={3.8}
        VELOCITY_DISSIPATION={2.2}
        CURL={2.0}
      />

      <LandingNavbar />

      {/* ────────────────── 1. HERO SECTION ────────────────── */}
      <section className="relative min-h-[92vh] flex items-center justify-center pt-28 pb-20 hero-grid overflow-hidden">
        {/* Subtle Ambient Radial Glows */}
        <div className="absolute top-1/4 left-1/4 w-[32rem] h-[32rem] bg-[#D4AF37]/5 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute top-1/3 right-1/4 w-[28rem] h-[28rem] bg-[#5C4A20]/10 rounded-full blur-[100px] pointer-events-none" />

        <div className="relative z-10 max-w-6xl mx-auto px-6 text-center">
          {/* Status Badge */}
          <motion.div
            initial={{ opacity: 0, y: -15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#1A1A1A]/80 border border-[#5C4A20]/60 text-xs font-mono text-[#D4AF37] mb-8 shadow-[0_0_15px_rgba(212,175,55,0.08)] backdrop-blur-md"
          >
            <span className="w-2 h-2 rounded-full bg-[#4FAF72] animate-pulse" />
            <span>PASSIVE EXTERNAL SECURITY & ATTACK SURFACE INTELLIGENCE</span>
          </motion.div>

          {/* Primary Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.6 }}
            className="text-4xl sm:text-6xl md:text-7xl font-black tracking-tight leading-[1.1] mb-6"
          >
            Know Your Attack Surface
            <br />
            <span className="gradient-text">Before Attackers Do</span>
          </motion.h1>

          {/* Typing Subheadline */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25, duration: 0.6 }}
            className="text-xl sm:text-2xl text-[#A7A39A] mb-5 min-h-[40px] flex items-center justify-center gap-2"
          >
            <span>Instantly evaluate</span>
            <TypingEffect />
          </motion.div>

          {/* Truthful Technical Description */}
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.35, duration: 0.6 }}
            className="text-[#8E8A80] mb-10 max-w-3xl mx-auto text-base sm:text-lg leading-relaxed font-normal"
          >
            Non-destructive external security assessment for developers, DevOps, and security teams.
            Gain verified visibility into HTTP headers, TLS ciphers, DNS health, technology fingerprints,
            and OWASP Top 10:2025 risk exposure.
          </motion.p>

          {/* Primary Call to Action Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45, duration: 0.5 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link
              href="/signup"
              className="btn-cyber text-base px-8 py-3.5 flex items-center gap-2.5 group shadow-[0_0_25px_rgba(212,175,55,0.2)] hover:shadow-[0_0_35px_rgba(212,175,55,0.35)]"
            >
              <Zap className="w-5 h-5 text-[#070707] group-hover:scale-110 transition-transform" />
              <span>Start Free Assessment</span>
              <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
            </Link>
            <a
              href="#pipeline"
              className="btn-ghost text-base px-6 py-3.5 flex items-center gap-2 hover:border-[#D4AF37]/50"
            >
              <Terminal className="w-4 h-4 text-[#D4AF37]" />
              <span>View Scan Architecture</span>
            </a>
          </motion.div>

          {/* ── Sample Assessment Terminal Preview ── */}
          <motion.div
            initial={{ opacity: 0, y: 35 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.65, duration: 0.7 }}
            className="mt-14 max-w-4xl mx-auto text-left"
          >
            <div className="glass-card rounded-xl p-6 border border-[#2E2E2E] bg-[#0E0E0E]/90 shadow-2xl relative overflow-hidden">
              {/* Header Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 mb-5 border-b border-[#222222]">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-[#EF4444]/90" />
                  <div className="w-3 h-3 rounded-full bg-[#F59E0B]/90" />
                  <div className="w-3 h-3 rounded-full bg-[#4FAF72]/90" />
                  <div className="ml-3 px-3 py-1 rounded bg-[#161616] border border-[#2A2A2A] text-xs font-mono text-[#D4AF37] flex items-center gap-2">
                    <Lock className="w-3 h-3 text-[#4FAF72]" />
                    <span>https://ginandjuice.shop</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold uppercase tracking-wide bg-[#D4AF37]/15 text-[#D4AF37] border border-[#D4AF37]/30">
                    SAMPLE ASSESSMENT · PASSIVE SCAN
                  </span>
                </div>
              </div>

              {/* Assessment Score & Finding Summary */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 p-4 rounded-lg bg-[#141414] border border-[#242424]">
                <div className="flex flex-col justify-center">
                  <span className="text-xs font-mono text-[#706C64] uppercase tracking-wider">Overall Posture Score</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-3xl font-black text-[#D4AF37]">81</span>
                    <span className="text-sm font-mono text-[#706C64]">/ 100</span>
                    <span className="ml-2 px-2 py-0.5 rounded text-xs font-bold bg-[#4FAF72]/20 text-[#4FAF72] border border-[#4FAF72]/40">
                      Grade: A
                    </span>
                  </div>
                </div>

                <div className="md:col-span-2 flex flex-col justify-center">
                  <span className="text-xs font-mono text-[#706C64] uppercase tracking-wider mb-1.5">Detected Findings (15 Total)</span>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="px-2.5 py-1 rounded bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30 font-semibold">
                      2 High
                    </span>
                    <span className="px-2.5 py-1 rounded bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/30 font-semibold">
                      3 Medium
                    </span>
                    <span className="px-2.5 py-1 rounded bg-[#EAB308]/15 text-[#EAB308] border border-[#EAB308]/30 font-semibold">
                      6 Low
                    </span>
                    <span className="px-2.5 py-1 rounded bg-[#6B7280]/15 text-[#9CA3AF] border border-[#6B7280]/30 font-semibold">
                      4 Info
                    </span>
                  </div>
                </div>
              </div>

              {/* 8 Live Pipeline Stages */}
              <div className="space-y-2.5 font-mono text-xs">
                {[
                  { name: 'DNS Security & Routing Records', detail: 'SPF Valid · DMARC Quarantined · 3 MX Records', status: 'done' },
                  { name: 'TLS/SSL Cryptographic Check', detail: 'TLS 1.3 Active · ECDHE-RSA-AES256 · Cert Valid (84d)', status: 'done' },
                  { name: 'HTTP Security Headers Audit', detail: 'CSP Present · HSTS Missing (A04) · X-Frame-Options OK', status: 'done' },
                  { name: 'Cookie Security Attributes', detail: '3 Session Cookies · Secure Flag Present · HttpOnly Verified', status: 'done' },
                  { name: 'Technology Fingerprinting', detail: 'Nginx 1.24 · Express Framework · React Frontend', status: 'done' },
                  { name: 'CVE Vulnerability Correlation', detail: 'Queried NIST NVD API v2 · 0 Known Unpatched CVEs', status: 'done' },
                  { name: 'Content & Sensitive File Probing', detail: '12 Common Paths Checked · .git/ Protected · No Leakage', status: 'done' },
                  { name: 'OWASP Top 10:2025 Categorization', detail: 'Mapped to A02, A04 & A06 Categories · Deterministic Score', status: 'done' },
                ].map((item, idx) => (
                  <motion.div
                    key={item.name}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.8 + idx * 0.08 }}
                    className="flex items-center justify-between p-2 rounded bg-[#111111]/70 hover:bg-[#171717] transition-colors border border-transparent hover:border-[#2A2A2A]"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#4FAF72] flex-shrink-0" />
                      <span className="text-[#E6E4DD] truncate font-medium">{item.name}</span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 text-[#706C64]">
                      <span className="hidden sm:inline text-[11px] text-[#8E8A80]">{item.detail}</span>
                      <span className="text-[#4FAF72] text-[11px] font-semibold">✓ verified</span>
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Terminal Footer */}
              <div className="mt-5 pt-4 border-t border-[#222222] flex flex-wrap items-center justify-between text-[11px] font-mono text-[#706C64]">
                <div className="flex items-center gap-4">
                  <span>Execution Time: <strong className="text-[#D4AF37]">3.4s</strong></span>
                  <span>Scope: <strong className="text-[#E6E4DD]">Passive External</strong></span>
                </div>
                <div className="flex items-center gap-3 text-[#A7A39A]">
                  <span>Export:</span>
                  <span className="text-[#D4AF37]">JSON</span> · 
                  <span className="text-[#D4AF37]">Executive PDF</span> · 
                  <span className="text-[#D4AF37]">Technical PDF</span>
                </div>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Bottom Scroll Indicator */}
        <motion.a
          href="#coverage"
          animate={{ y: [0, 6, 0] }}
          transition={{ repeat: Infinity, duration: 2.2 }}
          className="absolute bottom-6 left-1/2 -translate-x-1/2 text-[#706C64] hover:text-[#D4AF37] transition-colors"
          aria-label="Scroll to technical coverage"
        >
          <ChevronDown className="w-6 h-6" />
        </motion.a>
      </section>

      {/* ────────────────── 2. TECHNICAL COVERAGE STRIP ────────────────── */}
      <section id="coverage" className="py-14 border-y border-[#262626] bg-[#0B0B0B]/80 relative z-20 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {STATS.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="space-y-1.5"
            >
              <div className="text-4xl md:text-5xl font-black gradient-text tracking-tight font-mono">
                <CountUp target={stat.value} suffix={stat.suffix} />
              </div>
              <h4 className="text-sm font-bold text-[#F5F3ED] uppercase tracking-wider">{stat.label}</h4>
              <p className="text-xs text-[#706C64]">{stat.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ────────────────── 3. SECURITY LAYERS SECTION ────────────────── */}
      <section id="security" className="py-24 px-6 relative">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <motion.p
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 font-semibold"
            >
              Multi-Layered Surface Assessment
            </motion.p>
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]"
            >
              One Target URL. Four Deep Security Layers.
            </motion.h2>
            <motion.p
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.15 }}
              className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto"
            >
              Passive inspection uncovers perimeter misconfigurations across network protocols,
              browser security policies, technology components, and exposed data paths.
            </motion.p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {SECURITY_LAYERS.map((layer, idx) => (
              <motion.div
                key={layer.title}
                initial={{ opacity: 0, y: 25 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: idx * 0.1 }}
                className="glass-card p-8 rounded-xl border border-[#262626] bg-[#101010]/80 hover:border-[#5C4A20] transition-all group"
              >
                <div className="flex items-start justify-between mb-5">
                  <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-[#5C4A20]/20 border border-[#5C4A20] group-hover:scale-105 transition-transform">
                    <layer.icon className="w-6 h-6 text-[#D4AF37]" />
                  </div>
                  <span className="px-3 py-1 rounded-full text-xs font-mono text-[#D4AF37] bg-[#161616] border border-[#2A2A2A]">
                    {layer.badge}
                  </span>
                </div>

                <h3 className="text-xl font-bold text-[#F5F3ED] mb-2 group-hover:text-[#D4AF37] transition-colors">
                  {layer.title}
                </h3>
                <p className="text-sm text-[#8E8A80] mb-6 leading-relaxed">
                  {layer.desc}
                </p>

                <div className="space-y-2.5 pt-4 border-t border-[#1F1F1F]">
                  {layer.checks.map((chk) => (
                    <div key={chk} className="flex items-center gap-2.5 text-xs text-[#C5C2BA] font-mono">
                      <Check className="w-3.5 h-3.5 text-[#4FAF72] flex-shrink-0" />
                      <span>{chk}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 4. PIPELINE SECTION ────────────────── */}
      <section id="pipeline" className="py-24 px-6 bg-[#090909]/90 border-y border-[#262626]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 font-semibold">
              Execution Architecture
            </p>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]">
              From URL to Actionable Security Insight
            </h2>
            <p className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto">
              A transparent, non-destructive 6-stage execution pipeline designed for zero downtime and repeatable assessments.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {PIPELINE_STEPS.map((step, idx) => (
              <motion.div
                key={step.num}
                initial={{ opacity: 0, y: 25 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: idx * 0.1 }}
                className="glass-card p-6 rounded-xl border border-[#262626] bg-[#111111] relative hover:border-[#5C4A20]/60 transition-all"
              >
                <div className="flex items-center justify-between mb-4">
                  <span className="text-3xl font-black font-mono text-[#2D2D2D] group-hover:text-[#5C4A20] transition-colors">
                    {step.num}
                  </span>
                  <span className="text-[11px] font-mono uppercase tracking-wider text-[#D4AF37] px-2.5 py-0.5 rounded bg-[#1A1A1A] border border-[#2A2A2A]">
                    {step.sub}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-[#F5F3ED] mb-2">{step.title}</h3>
                <p className="text-sm text-[#8E8A80] leading-relaxed">{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 5. INTERACTIVE SAMPLE FINDING (EVIDENCE REVEAL) ────────────────── */}
      <section className="py-24 px-6 relative">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <span className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 inline-block font-semibold">
              Transparent Audit Evidence
            </span>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]">
              Every Finding Backed by Verified Evidence
            </h2>
            <p className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto">
              No black-box guesses. SentinelScan pairs every vulnerability directly with captured headers,
              impact statements, and ready-to-use configuration fixes.
            </p>
          </div>

          {/* Interactive Card */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="glass-card rounded-2xl border border-[#5C4A20]/60 bg-[#0E0E0E] shadow-[0_0_40px_rgba(0,0,0,0.8)] overflow-hidden"
          >
            {/* Finding Header */}
            <div className="p-6 bg-[#141414] border-b border-[#242424] flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40">
                    HIGH SEVERITY
                  </span>
                  <span className="text-xs font-mono text-[#706C64]">
                    ID: header.hsts.missing
                  </span>
                  <span className="text-xs font-mono text-[#D4AF37]">
                    OWASP A04:2025
                  </span>
                </div>
                <h3 className="text-xl font-bold text-[#F5F3ED]">
                  Missing HTTP Strict-Transport-Security (HSTS)
                </h3>
              </div>

              {/* Tab Selector */}
              <div className="flex items-center gap-1.5 p-1 bg-[#0A0A0A] rounded-lg border border-[#2A2A2A]">
                {(['evidence', 'impact', 'fix'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setEvidenceTab(tab)}
                    className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all capitalize ${
                      evidenceTab === tab
                        ? 'bg-[#5C4A20] text-[#FFF] font-bold shadow'
                        : 'text-[#8E8A80] hover:text-[#F5F3ED]'
                    }`}
                  >
                    {tab === 'evidence' ? 'Captured Evidence' : tab === 'impact' ? 'Risk Impact' : 'Remediation Fix'}
                  </button>
                ))}
              </div>
            </div>

            {/* Tab Body */}
            <div className="p-6">
              <AnimatePresence mode="wait">
                {evidenceTab === 'evidence' && (
                  <motion.div
                    key="evidence"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="space-y-4"
                  >
                    <div className="flex items-center justify-between text-xs text-[#706C64] font-mono">
                      <span>HTTP Response Headers Captured from ginandjuice.shop</span>
                      <span className="text-[#EF4444]">strict-transport-security: NOT PRESENT</span>
                    </div>

                    <div className="p-4 rounded-lg bg-[#070707] border border-[#222222] font-mono text-xs text-[#C5C2BA] leading-relaxed overflow-x-auto">
                      <p className="text-[#8E8A80]">HTTP/2 200 OK</p>
                      <p>date: Sat, 12 Sep 2026 18:00:00 GMT</p>
                      <p>content-type: text/html; charset=utf-8</p>
                      <p>server: nginx/1.24.0</p>
                      <p>x-powered-by: Express</p>
                      <p>x-content-type-options: nosniff</p>
                      <p className="text-[#EF4444] bg-[#EF4444]/10 py-1 px-2 rounded -mx-2 my-1 font-bold">
                        # MISSING: Strict-Transport-Security header was not detected in response
                      </p>
                      <p>cache-control: public, max-age=3600</p>
                    </div>

                    <p className="text-xs text-[#8E8A80] flex items-center gap-2">
                      <Info className="w-4 h-4 text-[#D4AF37] flex-shrink-0" />
                      <span>Detector verified lack of HSTS policy over secure HTTPS endpoint. Tested via passive header analyzer.</span>
                    </p>
                  </motion.div>
                )}

                {evidenceTab === 'impact' && (
                  <motion.div
                    key="impact"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="space-y-4"
                  >
                    <div className="p-4 rounded-lg bg-[#141414] border border-[#2A2A2A] text-sm text-[#C5C2BA] space-y-3">
                      <div className="flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 text-[#F97316] flex-shrink-0 mt-0.5" />
                        <div>
                          <h4 className="font-bold text-[#F5F3ED] mb-1">Man-in-the-Middle (MitM) & SSL Stripping Exposure</h4>
                          <p className="text-xs text-[#8E8A80] leading-relaxed">
                            Without an active HSTS header with a sufficient max-age, browsers may initiate the first connection over plaintext HTTP.
                            An attacker on the same local network can perform SSL stripping to intercept authentication cookies and session tokens.
                          </p>
                        </div>
                      </div>

                      <div className="pt-3 border-t border-[#222222] grid grid-cols-2 gap-4 text-xs font-mono">
                        <div>
                          <span className="text-[#706C64]">Taxonomy:</span>
                          <p className="text-[#D4AF37]">OWASP A04:2025 — Cryptographic Failures</p>
                        </div>
                        <div>
                          <span className="text-[#706C64]">CWE Association:</span>
                          <p className="text-[#D4AF37]">CWE-523: Unprotected Transport of Credentials</p>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}

                {evidenceTab === 'fix' && (
                  <motion.div
                    key="fix"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="space-y-4"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-[#8E8A80]">Nginx Configuration Fix (2 Year Expiry + Subdomains)</span>
                      <button
                        onClick={() => copySnippet('add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;')}
                        className="flex items-center gap-1.5 text-xs font-mono text-[#D4AF37] hover:text-[#FFF] transition-colors"
                      >
                        {copiedCode ? <Check className="w-3.5 h-3.5 text-[#4FAF72]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedCode ? 'Copied' : 'Copy Snippet'}</span>
                      </button>
                    </div>

                    <div className="p-4 rounded-lg bg-[#070707] border border-[#222222] font-mono text-xs text-[#4FAF72]">
                      <code>add_header Strict-Transport-Security &quot;max-age=63072000; includeSubDomains; preload&quot; always;</code>
                    </div>

                    <p className="text-xs text-[#8E8A80]">
                      Reference: IETF RFC 6797. Enable only after ensuring all subdomains are configured with valid SSL/TLS certificates.
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ────────────────── 6. OWASP TOP 10:2025 SECTION ────────────────── */}
      <section id="owasp" className="py-24 px-6 bg-[#0B0B0B] border-y border-[#262626]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 inline-block font-semibold">
              Industry Standard Taxonomy
            </span>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]">
              Direct Mapping to OWASP Top 10:2025
            </h2>
            <p className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto">
              Every passive detector in SentinelScan corresponds to authoritative security frameworks,
              enabling seamless communication between engineering and security compliance teams.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OWASP_CATEGORIES.map((cat, idx) => (
              <motion.div
                key={cat.code}
                initial={{ opacity: 0, y: 15 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: idx * 0.05 }}
                className="glass-card p-5 rounded-xl border border-[#262626] bg-[#121212] hover:border-[#5C4A20] transition-all flex items-start gap-4 group"
              >
                <div className="px-2.5 py-1 rounded bg-[#1A1A1A] border border-[#2E2E2E] text-xs font-mono font-bold text-[#D4AF37] group-hover:border-[#5C4A20] transition-colors flex-shrink-0">
                  {cat.code}
                </div>
                <div className="min-w-0">
                  <h3 className="font-bold text-[#F5F3ED] text-base mb-1 group-hover:text-[#D4AF37] transition-colors">
                    {cat.title}
                  </h3>
                  <p className="text-xs text-[#8E8A80] leading-relaxed">
                    {cat.scope}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 7. DETAILED FEATURES / MODULES ────────────────── */}
      <section id="features" className="py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 font-semibold">
              Passive Detection Modules
            </p>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]">
              37 Precision Security Detectors
            </h2>
            <p className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto">
              Inspect your external attack surface across 8 dedicated assessment engines without writing a line of test code.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {MODULES.map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 25 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.06 }}
                className="glass-card p-6 rounded-xl group border border-[#262626] bg-[#111111] hover:border-[#5C4A20] transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="w-11 h-11 rounded-xl flex items-center justify-center bg-[#5C4A20]/20 border border-[#5C4A20] group-hover:scale-105 transition-transform">
                      <f.icon className="w-5 h-5 text-[#D4AF37]" />
                    </div>
                    <span className="text-[11px] font-mono text-[#D4AF37] px-2 py-0.5 rounded bg-[#161616] border border-[#262626]">
                      {f.badge}
                    </span>
                  </div>
                  <h3 className="font-bold text-[#F5F3ED] text-base mb-2">{f.title}</h3>
                  <p className="text-xs text-[#8E8A80] leading-relaxed mb-4">{f.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 8. WHY SENTINELSCAN (ADVANTAGES) ────────────────── */}
      <section className="py-24 px-6 bg-[#0B0B0B] border-y border-[#262626]">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 inline-block font-semibold">
              Designed for High Integrity
            </span>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED]">
              Why Choose SentinelScan?
            </h2>
            <p className="text-[#8E8A80] text-base sm:text-lg max-w-2xl mx-auto">
              Engineered from the ground up for safe, continuous posture monitoring with zero operational overhead.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {WHY_CARDS.map((card, i) => (
              <motion.div
                key={card.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="glass-card p-6 rounded-xl border border-[#262626] bg-[#121212] hover:border-[#5C4A20]/60 transition-all"
              >
                <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#5C4A20]/20 border border-[#5C4A20] mb-4 text-[#D4AF37]">
                  <card.icon className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-bold text-[#F5F3ED] mb-2">{card.title}</h3>
                <p className="text-xs text-[#8E8A80] leading-relaxed">{card.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 9. TECHNICAL CREDIBILITY & STANDARDS ────────────────── */}
      <section className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <p className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-2 font-semibold">
              Technical Credibility
            </p>
            <h3 className="text-2xl sm:text-3xl font-bold text-[#F5F3ED]">
              Built Around Recognized Security Standards
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {STANDARDS.map((std, i) => (
              <motion.div
                key={std.name}
                initial={{ opacity: 0, y: 15 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className="glass-card p-5 rounded-xl border border-[#222222] bg-[#0E0E0E] text-center flex flex-col justify-between"
              >
                <div>
                  <h4 className="font-mono font-bold text-sm text-[#D4AF37] mb-1">{std.name}</h4>
                  <p className="text-[11px] font-mono text-[#8E8A80] mb-2">{std.sub}</p>
                  <p className="text-xs text-[#706C64] leading-relaxed">{std.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 10. FAQ SECTION ────────────────── */}
      <section id="faq" className="py-24 px-6 bg-[#090909] border-t border-[#262626]">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-xs font-mono uppercase tracking-widest mb-3 font-semibold">
              Frequently Asked Questions
            </p>
            <h2 className="text-3xl sm:text-4xl font-black text-[#F5F3ED]">
              Frequently Asked Questions
            </h2>
            <p className="text-[#8E8A80] text-sm mt-3">
              Key technical details regarding assessment safety, duration, and reporting.
            </p>
          </div>

          <div className="space-y-3">
            {FAQS.map((faq, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                className="glass-card rounded-xl overflow-hidden border border-[#262626] bg-[#111111]"
              >
                <button
                  className="w-full flex items-center justify-between p-5 text-left group"
                  onClick={() => setOpenFaq(openFaq === i ? null : i)}
                  aria-expanded={openFaq === i}
                >
                  <span className="font-semibold text-[#F5F3ED] text-sm sm:text-base pr-4 group-hover:text-[#D4AF37] transition-colors">
                    {faq.q}
                  </span>
                  {openFaq === i ? (
                    <ChevronUp className="w-5 h-5 text-[#D4AF37] flex-shrink-0" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-[#706C64] flex-shrink-0 group-hover:text-[#D4AF37] transition-colors" />
                  )}
                </button>
                {openFaq === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    className="px-5 pb-5 text-[#A7A39A] text-sm leading-relaxed border-t border-[#202020] pt-4"
                  >
                    {faq.a}
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────── 11. FINAL CTA BANNER ────────────────── */}
      <section className="py-24 px-6 relative overflow-hidden">
        <div className="max-w-4xl mx-auto text-center relative z-10">
          <div className="glass-card p-12 sm:p-16 rounded-2xl border border-[#5C4A20] relative bg-[#111111] shadow-[0_0_60px_rgba(212,175,55,0.1)]">
            <div className="absolute inset-0 bg-[#D4AF37]/5 rounded-2xl pointer-events-none" />
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center bg-[#5C4A20]/20 border border-[#5C4A20] mx-auto mb-6 text-[#D4AF37]">
              <Shield className="w-8 h-8" />
            </div>
            <h2 className="text-3xl sm:text-5xl font-black mb-4 text-[#F5F3ED] tracking-tight">
              Ready to See Your Attack Surface?
            </h2>
            <p className="text-[#8E8A80] mb-8 text-base sm:text-lg max-w-xl mx-auto">
              Run an instant, non-destructive assessment and get your posture score,
              verified evidence, and actionable remediation steps in under a minute.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/signup"
                className="btn-cyber text-base px-10 py-4 flex items-center gap-2.5 shadow-[0_0_25px_rgba(212,175,55,0.25)]"
              >
                <Zap className="w-5 h-5 text-[#070707]" />
                <span>Launch Security Scan</span>
                <ArrowRight className="w-4 h-4 ml-1" />
              </Link>
              <a
                href="#pipeline"
                className="btn-ghost text-base px-8 py-4 flex items-center gap-2"
              >
                <span>Review Pipeline Specs</span>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ────────────────── 12. FOOTER ────────────────── */}
      <footer className="border-t border-[#222222] py-14 px-6 bg-[#060606]">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-[#141414] border border-[#5C4A20] flex items-center justify-center">
                <Shield className="w-4 h-4 text-[#D4AF37]" />
              </div>
              <span className="font-bold text-[#F5F3ED] tracking-wider text-base">
                SENTINEL<span className="text-[#D4AF37]">SCAN</span>
              </span>
            </div>

            <p className="text-[#706C64] text-xs text-center max-w-md leading-relaxed font-mono">
              For defensive security assessment and authorized research purposes only.
              Always obtain explicit authorization before evaluating third-party infrastructure.
            </p>

            <div className="flex gap-6 text-xs text-[#706C64] font-mono">
              <a href="#features" className="hover:text-[#F5F3ED] transition-colors">Modules</a>
              <a href="#pipeline" className="hover:text-[#F5F3ED] transition-colors">Pipeline</a>
              <a href="#owasp" className="hover:text-[#F5F3ED] transition-colors">OWASP 2025</a>
              <a href="#faq" className="hover:text-[#F5F3ED] transition-colors">FAQ</a>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-[#1C1C1C] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#524E48] font-mono">
            <div>
              © {new Date().getFullYear()} SentinelScan. Built for cybersecurity excellence.
            </div>
            <div>
              Passive Surface Intelligence & Threat Modeling Engine
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
