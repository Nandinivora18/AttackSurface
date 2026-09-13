'use client';
import { CheckCircle2 } from 'lucide-react';
import { Report } from '@/types';

interface CoverageItem {
  key: string;
  label: string;
  description: string;
  check: (report: Report) => boolean;
}

const COVERAGE_ITEMS: CoverageItem[] = [
  {
    key: 'dns',
    label: 'DNS Security',
    description: 'SPF, DMARC, NS records',
    check: (r) => !!(r.dns_info && (r.dns_info.a_records?.length > 0 || r.dns_info.ns_records?.length > 0)),
  },
  {
    key: 'ssl',
    label: 'SSL / TLS',
    description: 'Certificate, cipher, protocol',
    check: (r) => !!(r.ssl_info && r.ssl_info.supported !== undefined),
  },
  {
    key: 'headers',
    label: 'Security Headers',
    description: 'HSTS, CSP, X-Frame, etc.',
    check: (r) => !!(r.raw_headers && Object.keys(r.raw_headers).length > 0),
  },
  {
    key: 'cookies',
    label: 'Cookie Security',
    description: 'Secure, HttpOnly, SameSite',
    check: (r) => !!(r.findings?.some((f) => f.category?.toLowerCase().includes('cookie'))),
  },
  {
    key: 'tech',
    label: 'Technology Detection',
    description: 'Frameworks, servers, libraries',
    check: (r) => !!(r.tech_stack && Object.keys(r.tech_stack).length > 0),
  },
  {
    key: 'cve',
    label: 'CVE Correlation',
    description: 'Known vulnerability matching',
    check: (r) => !!(r.component_inventory && r.component_inventory.length > 0),
  },
  {
    key: 'owasp',
    label: 'OWASP A01–A10',
    description: 'OWASP Top 10:2025 assessment',
    check: (r) => !!(r.owasp_summary && Object.keys(r.owasp_summary).length > 0),
  },
  {
    key: 'content',
    label: 'Content Exposure',
    description: 'Email, info leakage, endpoints',
    check: (r) => !!(r.findings?.some((f) => f.category?.toLowerCase().includes('content') || f.category?.toLowerCase().includes('exposure'))),
  },
];

interface AssessmentCoverageProps {
  report: Report | null;
}

export default function AssessmentCoverage({ report }: AssessmentCoverageProps) {
  if (!report) return null;

  const items = COVERAGE_ITEMS.map((item) => ({
    ...item,
    covered: item.check(report),
  }));

  const coveredCount = items.filter((i) => i.covered).length;

  return (
    <div className="rounded-[14px] border border-[rgba(255,255,255,0.08)] bg-[#0C0C0C] p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-[#D4AF37]">
          Assessment Coverage
        </p>
        <span className="text-[11px] font-semibold text-[#6F6F6F]">
          {coveredCount}/{items.length} modules active
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2" role="list" aria-label="Assessment coverage modules">
        {items.map((item) => (
          <div
            key={item.key}
            role="listitem"
            className={`flex items-start gap-2.5 p-3 rounded-[10px] border transition-colors ${
              item.covered
                ? 'border-emerald-500/20 bg-emerald-500/5'
                : 'border-[rgba(255,255,255,0.05)] bg-[#080808] opacity-50'
            }`}
            aria-label={`${item.label}: ${item.covered ? 'active' : 'not detected'}`}
          >
            <CheckCircle2
              className={`w-3.5 h-3.5 flex-shrink-0 mt-0.5 ${item.covered ? 'text-emerald-400' : 'text-[#3A3A3A]'}`}
              aria-hidden="true"
            />
            <div className="min-w-0">
              <p className={`text-[11px] font-semibold leading-tight ${item.covered ? 'text-[#F5F5F5]' : 'text-[#4A4A4A]'}`}>
                {item.label}
              </p>
              <p className="text-[10px] text-[#5A5A5A] mt-0.5 leading-snug line-clamp-1">
                {item.description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
