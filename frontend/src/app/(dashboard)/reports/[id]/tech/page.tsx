'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  Cpu, ArrowLeft, CheckCircle2, AlertTriangle, ShieldAlert,
  ExternalLink, Layers, Code, Server, Globe, Box, Terminal,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import ReportSubNav from '@/components/reports/ReportSubNav';
import api from '@/lib/api';
import { Report } from '@/types';
import { formatConfidence } from '@/lib/utils';
import toast from 'react-hot-toast';

const CATEGORY_GROUPS = [
  { name: 'JavaScript & Frontend Frameworks', key: 'JavaScript Framework', icon: Code },
  { name: 'Content Management Systems (CMS)', key: 'CMS', icon: Box },
  { name: 'E-Commerce Platforms', key: 'E-Commerce', icon: Globe },
  { name: 'Web Server & Infrastructure', key: 'Web Server', icon: Server },
  { name: 'Programming Languages & Backend', key: 'Programming Language', icon: Terminal },
  { name: 'CDN, WAF & Cloud Infrastructure', key: 'CDN / WAF', icon: Cpu },
  { name: 'Analytics & Third-Party Services', key: 'Analytics', icon: Layers },
];

export default function TechnologyPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/api/reports/${id}`)
      .then((res) => setReport(res.data))
      .catch(() => { toast.error('Report not found'); router.push('/reports'); })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-6 max-w-5xl mx-auto page-enter">
        <div className="h-8 w-48 bg-[#161616] rounded animate-pulse" />
        <div className="h-44 bg-[#111111] rounded-xl border border-[#2A2A2A] animate-pulse" />
      </div>
    );
  }

  if (!report) return null;

  const techStack = report.tech_stack || {};
  const findings = report.findings || [];

  // Group technologies by category
  const groupedTech: Record<string, Array<{ name: string; info: any }>> = {};

  Object.entries(techStack).forEach(([name, info]) => {
    const cat = info.category || 'Other Components';
    if (!groupedTech[cat]) groupedTech[cat] = [];
    groupedTech[cat].push({ name, info });
  });

  const totalTechCount = Object.keys(techStack).length;
  const versionedCount = Object.values(techStack).filter((i) => !!i.version).length;

  return (
    <div className="space-y-6 max-w-5xl mx-auto page-enter">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2"><ArrowLeft className="w-4 h-4" /></button>
          <div>
            <h1 className="text-xl font-bold text-[#F5F3ED] flex items-center gap-2">
              <Cpu className="w-5 h-5 text-[#D4AF37]" /> Technology Stack Fingerprinting
            </h1>
            <p className="text-xs text-[#706C64]">{report.scan?.url || 'Target Site'}</p>
          </div>
        </div>
      </div>

      {/* SubNav */}
      <ReportSubNav reportId={report.id} />

      {/* Hero Summary */}
      <GlassCard className="p-8 border border-[#2A2A2A] bg-[#111111]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          <div>
            <h2 className="text-lg font-bold text-[#F5F3ED] mb-1">Detected Software Stack</h2>
            <p className="text-xs text-[#A7A39A] leading-relaxed">
              Automated fingerprinting of web frameworks, CMS platforms, servers, CDN services, and client-side JavaScript libraries.
            </p>
          </div>

          <div className="md:col-span-2 grid grid-cols-3 gap-3">
            <div className="p-3.5 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] text-center">
              <span className="text-2xl font-black text-[#D4AF37] block">{totalTechCount}</span>
              <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Total Technologies</span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] text-center">
              <span className="text-2xl font-black text-[#4FAF72] block">{versionedCount}</span>
              <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Version Identified</span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] text-center">
              <span className="text-2xl font-black text-[#D4AF37] block">{Object.keys(groupedTech).length}</span>
              <span className="text-[10px] uppercase font-bold text-[#A7A39A]">Categories</span>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Technology Categories */}
      {Object.keys(groupedTech).length === 0 ? (
        <GlassCard className="p-12 text-center text-[#706C64] border border-[#2A2A2A] bg-[#111111]">
          <Cpu className="w-12 h-12 text-[#706C64] mx-auto mb-3" />
          <p className="font-semibold text-[#A7A39A]">No technology stack signatures detected</p>
        </GlassCard>
      ) : (
        <div className="space-y-6">
          {Object.entries(groupedTech).map(([catName, items], catIdx) => (
            <GlassCard key={catName} className="p-6 border border-[#2A2A2A] bg-[#111111]">
              <div className="flex items-center gap-2.5 mb-4 pb-2 border-b border-[#2A2A2A]/60">
                <Layers className="w-4 h-4 text-[#D4AF37]" />
                <h3 className="font-bold text-[#F5F3ED] text-sm">{catName}</h3>
                <span className="text-xs text-[#706C64] font-mono ml-auto">{items.length} item{items.length !== 1 ? 's' : ''}</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {items.map(({ name, info }, idx) => {
                  const conf = info.confidence ?? 95;
                  const confColor = conf >= 90 ? '#4FAF72' : conf >= 75 ? '#F59E0B' : '#D4AF37';
                  const cveMatch = findings.find((f) => f.title.toLowerCase().includes(name.toLowerCase()) && !!f.cve_id);

                  return (
                    <motion.div
                      key={name}
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.04 }}
                      className={`p-4 rounded-xl border transition-all ${
                        cveMatch ? 'bg-red-500/5 border-red-500/25' : 'bg-[#0D0D0D] border-[#2A2A2A]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <div>
                          <h4 className="font-bold text-[#F5F3ED] text-sm">{name}</h4>
                          <span className="text-xs text-[#A7A39A] font-mono mt-0.5 block">
                            Version: <strong className="text-[#F5F3ED]">{info.version || 'Not Disclosed'}</strong>
                          </span>
                        </div>

                        {/* Confidence Badge */}
                        <div className="flex flex-col items-end">
                          <span
                            className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border"
                            style={{ borderColor: `${confColor}40`, background: `${confColor}15`, color: confColor }}
                          >
                            {formatConfidence(conf)} Confidence
                          </span>
                        </div>
                      </div>

                      {/* CVE Alert */}
                      {cveMatch && (
                        <div className="mt-3 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2 text-red-300">
                            <ShieldAlert className="w-4 h-4 text-[#EF4444] flex-shrink-0" />
                            <span className="font-bold font-mono">{cveMatch.cve_id}</span>
                          </div>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cveMatch.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[11px] text-[#D4AF37] hover:underline flex items-center gap-1 font-semibold"
                          >
                            View CVE <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </GlassCard>
          ))}
        </div>
      )}
    </div>
  );
}
