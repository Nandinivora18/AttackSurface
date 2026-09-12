'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useInView } from 'framer-motion';
import Link from 'next/link';
import {
  Shield, Zap, Globe, Lock, Eye, AlertTriangle,
  CheckCircle, ArrowRight, Star, ChevronDown, ChevronUp,
  FileText, Cpu, Mail, Server, Code2, Activity,
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
  'CORS Policy Violations',
  'Cookie Security Issues',
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
      timeout = setTimeout(() => setDisplayed(phrase.slice(0, displayed.length + 1)), 55);
    } else if (!deleting && displayed.length === phrase.length) {
      timeout = setTimeout(() => setDeleting(true), 1800);
    } else if (deleting && displayed.length > 0) {
      timeout = setTimeout(() => setDisplayed(displayed.slice(0, -1)), 28);
    } else {
      setDeleting(false);
      setIndex((i) => (i + 1) % TYPING_PHRASES.length);
    }
    return () => clearTimeout(timeout);
  }, [displayed, deleting, index]);

  return (
    <span className="text-[#D4AF37]">
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
    const step = target / 60;
    let current = 0;
    const timer = setInterval(() => {
      current += step;
      if (current >= target) { setCount(target); clearInterval(timer); }
      else setCount(Math.floor(current));
    }, 16);
    return () => clearInterval(timer);
  }, [inView, target]);

  return <div ref={ref}>{count.toLocaleString()}{suffix}</div>;
}

/* ────────── Features Data ────────── */
const FEATURES = [
  { icon: Lock, title: 'SSL/TLS Analysis', desc: 'Deep inspection of certificate validity, TLS version, cipher strength, and expiry warnings.', color: '#D4AF37' },
  { icon: Shield, title: 'Security Headers', desc: 'Check all 10 OWASP-recommended headers including CSP, HSTS, X-Frame-Options, and more.', color: '#D4AF37' },
  { icon: Globe, title: 'DNS Security', desc: 'Analyze SPF, DMARC, and MX records to detect email spoofing vulnerabilities.', color: '#D4AF37' },
  { icon: Cpu, title: 'Tech Fingerprinting', desc: 'Identify 25+ technologies and match detected versions against known CVE databases.', color: '#F97316' },
  { icon: Eye, title: 'Sensitive File Detection', desc: 'Probe for exposed .git, .env, swagger, admin panels, and backup files.', color: '#EF4444' },
  { icon: Mail, title: 'Email Exposure', desc: 'Extract email addresses from HTML source that could be harvested by spammers.', color: '#A7A39A' },
  { icon: Code2, title: 'Cookie Analysis', desc: 'Verify Secure, HttpOnly, and SameSite flags on all session and auth cookies.', color: '#D4AF37' },
  { icon: FileText, title: 'PDF Reports', desc: 'Download branded professional reports with score charts, findings table, and recommendations.', color: '#D4AF37' },
];

const SCAN_STAGES = [
  'DNS Lookup', 'SSL Certificate', 'HTTP Headers', 'Security Headers',
  'Tech Detection', 'CVE Matching', 'File Probing', 'Report Generation',
];

/* ────────── Pricing ────────── */
const PLANS = [
  {
    name: 'Free', price: '$0', period: 'forever',
    features: ['5 scans per month', 'Basic security report', 'Security headers check', 'SSL analysis', 'Email support'],
    cta: 'Get Started', highlight: false,
  },
  {
    name: 'Pro', price: '$29', period: 'per month',
    features: ['Unlimited scans', 'Full PDF reports', 'CVE matching', 'API access', 'Priority support', 'Scan history', 'Email alerts'],
    cta: 'Start Pro Trial', highlight: true,
  },
  {
    name: 'Enterprise', price: 'Custom', period: 'contact us',
    features: ['Everything in Pro', 'Bulk scanning', 'White-label reports', 'SSO / SAML', 'Dedicated support', 'SLA guarantee'],
    cta: 'Contact Sales', highlight: false,
  },
];

/* ────────── FAQ ────────── */
const FAQS = [
  { q: 'Is this tool safe to use on any website?', a: 'SentinelScan only reads publicly accessible HTTP responses, DNS records, and TLS certificates — the same information any browser receives. We never attempt unauthorized access, injection, or modification of target systems.' },
  { q: 'How long does a scan take?', a: 'Most scans complete in 20–60 seconds depending on the target server response time. You\'ll see live progress updates as each module runs.' },
  { q: 'What security checks are included?', a: 'We check SSL/TLS configuration, all OWASP-recommended HTTP security headers, CORS policies, DNS/email security (SPF, DMARC), technology fingerprinting, cookie security, exposed sensitive files, and more.' },
  { q: 'Can I scan any website?', a: 'You should only scan websites you own or have explicit permission to test. The tool is designed for website owners, developers, and security teams to assess their own infrastructure.' },
  { q: 'How is the security score calculated?', a: 'The score starts at 100 and deducts points based on severity: Critical (-25), High (-10), Medium (-5), Low (-2). The final score maps to a letter grade from A+ to F.' },
];

/* ────────── Testimonials ────────── */
const TESTIMONIALS = [
  { name: 'Sarah Chen', role: 'Security Engineer @ Stripe', text: 'SentinelScan found 3 critical misconfigurations in our staging environment that our internal tools missed. The report quality is exceptional.', rating: 5 },
  { name: 'Marcus Okonkwo', role: 'CTO @ FinTech Startup', text: 'We run SentinelScan on every deployment. The real-time progress and professional PDF reports make it easy to share findings with stakeholders.', rating: 5 },
  { name: 'Priya Sharma', role: 'DevOps Lead @ TechCorp', text: 'The HSTS and CSP analysis alone saved us from a potential compliance issue. Beautiful UI and incredibly fast scans.', rating: 5 },
];

/* ────────── Main Page ────────── */
export default function LandingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const featuresRef = useRef<HTMLElement>(null);
  const featuresInView = useInView(featuresRef, { once: true, margin: '-100px' });

  return (
    <div className="min-h-screen bg-[#070707] text-[#F5F3ED] overflow-x-hidden relative">
      <SplashCursor
        RAINBOW_MODE={false}
        COLOR="#D4AF37"
        SPLAT_RADIUS={0.22}
        SPLAT_FORCE={4500}
        DENSITY_DISSIPATION={3.5}
        VELOCITY_DISSIPATION={2.0}
        CURL={2.2}
      />
      <LandingNavbar />

      {/* ── HERO ── */}
      <section className="relative min-h-screen flex items-center justify-center pt-20 hero-grid overflow-hidden">
        {/* Ambient glows */}
        <div className="absolute top-1/3 left-1/4 w-96 h-96 bg-[#D4AF37]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-[#5C4A20]/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="text-5xl md:text-7xl font-black leading-tight mb-6"
          >
            Know Every{' '}
            <span className="gradient-text">Vulnerability</span>
            <br />Before Attackers Do
          </motion.h1>

          {/* Typing Effect */}
          <motion.p
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}
            className="text-xl md:text-2xl text-[#A7A39A] mb-4 min-h-[36px]"
          >
            Instantly detect <TypingEffect />
          </motion.p>

          <motion.p
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }}
            className="text-[#706C64] mb-10 max-w-2xl mx-auto text-lg"
          >
            Professional security assessment for website owners, developers, and security teams.
            Get a comprehensive report in under 60 seconds.
          </motion.p>

          {/* CTA */}
          <motion.div
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link href="/signup" className="btn-cyber text-base px-8 py-3.5 flex items-center gap-2">
              <Zap className="w-5 h-5" />
              <span>Start Free Scan</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </Link>
            <Link href="#features" className="btn-ghost text-base px-6 py-3.5">
              See How It Works
            </Link>
          </motion.div>

          {/* Scan Stage Preview */}
          <motion.div
            initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.8 }}
            className="mt-16 max-w-3xl mx-auto"
          >
            <div className="glass-card p-6 text-left border border-[#2A2A2A] bg-[#111111]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-3 h-3 rounded-full bg-[#EF4444]" />
                <div className="w-3 h-3 rounded-full bg-[#F59E0B]" />
                <div className="w-3 h-3 rounded-full bg-[#4FAF72]" />
                <span className="ml-2 text-xs text-[#706C64] font-mono">SentinelScan — Live Assessment</span>
              </div>
              <div className="space-y-2">
                {SCAN_STAGES.map((stage, i) => (
                  <motion.div
                    key={stage}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 1 + i * 0.15 }}
                    className="flex items-center gap-3"
                  >
                    <CheckCircle className="w-4 h-4 text-[#4FAF72] flex-shrink-0" />
                    <span className="text-sm font-mono text-[#F5F3ED]">{stage}</span>
                    <div className="flex-1 h-px bg-[#2A2A2A]" />
                    <span className="text-xs text-[#4FAF72] font-mono">✓ done</span>
                  </motion.div>
                ))}
              </div>
              <div className="mt-4 pt-4 border-t border-[#2A2A2A] flex items-center justify-between">
                <span className="text-sm text-[#A7A39A]">Overall Score</span>
                <span className="text-2xl font-black text-[#D4AF37]">87 / 100 — Grade: A</span>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Scroll indicator */}
        <motion.a
          href="#features"
          animate={{ y: [0, 8, 0] }} transition={{ repeat: Infinity, duration: 2 }}
          className="absolute bottom-10 left-1/2 -translate-x-1/2 text-[#706C64] hover:text-[#A7A39A]"
          aria-label="Scroll to features"
        >
          <ChevronDown className="w-6 h-6" />
        </motion.a>
      </section>

      {/* ── STATS ── */}
      <section className="py-20 border-y border-[#2A2A2A] bg-[#0D0D0D]/60">
        <div className="max-w-5xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {[
            { value: 10000, suffix: '+', label: 'Scans Run' },
            { value: 50, suffix: '+', label: 'Check Modules' },
            { value: 99, suffix: '%', label: 'Uptime' },
            { value: 25, suffix: '+', label: 'Technologies Detected' },
          ].map((stat) => (
            <div key={stat.label} className="space-y-1">
              <div className="text-4xl font-black gradient-text">
                <CountUp target={stat.value} suffix={stat.suffix} />
              </div>
              <p className="text-sm text-[#706C64]">{stat.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── FEATURES ── */}
      <section id="features" ref={featuresRef as any} className="py-24 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <motion.p
              initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}
              className="text-[#D4AF37] text-sm font-semibold uppercase tracking-widest mb-3"
            >
              Security Modules
            </motion.p>
            <motion.h2
              initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
              className="text-4xl md:text-5xl font-black mb-4 text-[#F5F3ED]"
            >
              Everything You Need to Know
            </motion.h2>
            <motion.p
              initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay: 0.2 }}
              className="text-[#A7A39A] text-lg max-w-2xl mx-auto"
            >
              Comprehensive security assessment modules that analyze every aspect of your website&apos;s security posture.
            </motion.p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            {FEATURES.map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.07 }}
                className="glass-card glass-card-hover p-6 group border border-[#2A2A2A] bg-[#111111] hover:border-[#5C4A20]/60"
              >
                <div
                  className="w-11 h-11 rounded-xl flex items-center justify-center mb-4 transition-all group-hover:scale-110 bg-[#5C4A20]/20 border border-[#5C4A20]"
                >
                  <f.icon className="w-5 h-5 text-[#D4AF37]" />
                </div>
                <h3 className="font-bold text-[#F5F3ED] mb-2">{f.title}</h3>
                <p className="text-sm text-[#A7A39A] leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how-it-works" className="py-24 px-6 bg-[#0D0D0D]/60">
        <div className="max-w-4xl mx-auto text-center">
          <p className="text-[#D4AF37] text-sm font-semibold uppercase tracking-widest mb-3">Simple Process</p>
          <h2 className="text-4xl font-black mb-16 text-[#F5F3ED]">Security in 3 Steps</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { step: '01', icon: Globe, title: 'Enter URL', desc: 'Paste any website URL and click Start Scan. No login required for basic scans.' },
              { step: '02', icon: Activity, title: 'Watch Live Scan', desc: 'Monitor real-time progress across 8 security modules with live stage updates.' },
              { step: '03', icon: FileText, title: 'Get Full Report', desc: 'Receive a comprehensive report with score, grade, findings, and actionable recommendations.' },
            ].map((step, i) => (
              <motion.div
                key={step.step}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.15 }}
                className="relative"
              >
                <div className="glass-card p-8 text-center h-full border border-[#2A2A2A] bg-[#111111]">
                  <div className="text-5xl font-black text-[#2A2A2A] mb-4">{step.step}</div>
                  <step.icon className="w-10 h-10 text-[#D4AF37] mx-auto mb-4" />
                  <h3 className="text-xl font-bold mb-3 text-[#F5F3ED]">{step.title}</h3>
                  <p className="text-[#A7A39A] text-sm leading-relaxed">{step.desc}</p>
                </div>
                {i < 2 && (
                  <div className="hidden md:block absolute top-1/2 -right-4 -translate-y-1/2 z-10">
                    <ArrowRight className="w-6 h-6 text-[#2A2A2A]" />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PRICING ── */}
      <section id="pricing" className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-sm font-semibold uppercase tracking-widest mb-3">Pricing</p>
            <h2 className="text-4xl font-black mb-4 text-[#F5F3ED]">Simple, Transparent Pricing</h2>
            <p className="text-[#A7A39A]">Start free. Scale as you grow.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {PLANS.map((plan, i) => (
              <motion.div
                key={plan.name}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className={`glass-card p-8 relative border bg-[#111111] ${plan.highlight ? 'border-[#5C4A20] shadow-[0_0_20px_rgba(212,175,55,0.15)]' : 'border-[#2A2A2A]'}`}
              >
                {plan.highlight && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 py-1 bg-gradient-to-r from-[#D4AF37] to-[#C6A15B] rounded-full text-xs font-bold text-[#070707] shadow-cyber">
                    Most Popular
                  </div>
                )}
                <h3 className="text-xl font-bold mb-2 text-[#F5F3ED]">{plan.name}</h3>
                <div className="flex items-baseline gap-1 mb-1">
                  <span className="text-4xl font-black gradient-text">{plan.price}</span>
                </div>
                <p className="text-[#706C64] text-sm mb-6">{plan.period}</p>
                <ul className="space-y-3 mb-8">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-center gap-2.5 text-sm text-[#A7A39A]">
                      <CheckCircle className="w-4 h-4 text-[#4FAF72] flex-shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
                <Link href="/signup" className={plan.highlight ? 'btn-cyber w-full justify-center' : 'btn-ghost w-full justify-center'}>
                  <span>{plan.cta}</span>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── TESTIMONIALS ── */}
      <section className="py-24 px-6 bg-[#0D0D0D]/60">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-sm font-semibold uppercase tracking-widest mb-3">Testimonials</p>
            <h2 className="text-4xl font-black text-[#F5F3ED]">Trusted by Security Teams</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {TESTIMONIALS.map((t, i) => (
              <motion.div
                key={t.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="glass-card p-6 border border-[#2A2A2A] bg-[#111111]"
              >
                <div className="flex gap-1 mb-4">
                  {Array.from({ length: t.rating }).map((_, j) => (
                    <Star key={j} className="w-4 h-4 fill-[#D4AF37] text-[#D4AF37]" />
                  ))}
                </div>
                <p className="text-[#A7A39A] text-sm leading-relaxed mb-5">&ldquo;{t.text}&rdquo;</p>
                <div>
                  <p className="font-semibold text-[#F5F3ED]">{t.name}</p>
                  <p className="text-xs text-[#706C64]">{t.role}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FAQ ── */}
      <section id="faq" className="py-24 px-6">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-16">
            <p className="text-[#D4AF37] text-sm font-semibold uppercase tracking-widest mb-3">FAQ</p>
            <h2 className="text-4xl font-black text-[#F5F3ED]">Common Questions</h2>
          </div>
          <div className="space-y-3">
            {FAQS.map((faq, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                className="glass-card overflow-hidden border border-[#2A2A2A] bg-[#111111]"
              >
                <button
                  className="w-full flex items-center justify-between p-5 text-left"
                  onClick={() => setOpenFaq(openFaq === i ? null : i)}
                >
                  <span className="font-semibold text-[#F5F3ED] pr-4">{faq.q}</span>
                  {openFaq === i
                    ? <ChevronUp className="w-5 h-5 text-[#D4AF37] flex-shrink-0" />
                    : <ChevronDown className="w-5 h-5 text-[#706C64] flex-shrink-0" />
                  }
                </button>
                {openFaq === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    className="px-5 pb-5 text-[#A7A39A] text-sm leading-relaxed border-t border-[#2A2A2A] pt-4"
                  >
                    {faq.a}
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA BANNER ── */}
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <div className="glass-card p-12 border border-[#5C4A20] relative bg-[#111111]">
            <div className="absolute inset-0 bg-[#D4AF37]/5 rounded-2xl pointer-events-none" />
            <Shield className="w-14 h-14 text-[#D4AF37] mx-auto mb-5" />
            <h2 className="text-4xl font-black mb-4 text-[#F5F3ED]">
              Start Your Free Security Assessment
            </h2>
            <p className="text-[#A7A39A] mb-8 text-lg">
              Join thousands of developers who trust SentinelScan to keep their websites secure.
            </p>
            <Link href="/signup" className="btn-cyber text-base px-10 py-4 inline-flex items-center gap-2">
              <Zap className="w-5 h-5" />
              <span>Create Free Account</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer className="border-t border-[#2A2A2A] py-12 px-6 bg-[#070707]">
        <div className="max-w-6xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-[#D4AF37]" />
              <span className="font-bold text-[#F5F3ED]">Sentinel<span className="text-[#D4AF37]">Scan</span></span>
            </div>
            <p className="text-[#706C64] text-sm text-center">
              For defensive security and educational purposes only. Always obtain proper authorization before scanning.
            </p>
            <div className="flex gap-6 text-sm text-[#706C64]">
              <a href="#" className="hover:text-[#F5F3ED] transition-colors">Privacy</a>
              <a href="#" className="hover:text-[#F5F3ED] transition-colors">Terms</a>
              <a href="#" className="hover:text-[#F5F3ED] transition-colors">Contact</a>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-[#2A2A2A]/50 text-center text-xs text-[#706C64]">
            © {new Date().getFullYear()} SentinelScan. Built for cybersecurity excellence.
          </div>
        </div>
      </footer>
    </div>
  );
}
