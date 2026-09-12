'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import {
  Globe, ArrowLeft, CheckCircle2, AlertTriangle, Info,
  Mail, Shield, Server, FileText, Lock, HelpCircle,
} from 'lucide-react';
import GlassCard from '@/components/shared/GlassCard';
import ReportSubNav from '@/components/reports/ReportSubNav';
import api from '@/lib/api';
import { Report } from '@/types';
import toast from 'react-hot-toast';

const RECORD_EXPLANATIONS = {
  a: 'A (Address) records map hostnames directly to IPv4 web server IP addresses.',
  aaaa: 'AAAA records map hostnames to IPv6 web server IP addresses for next-generation networks.',
  mx: 'MX (Mail Exchanger) records specify which mail servers accept incoming emails for the domain.',
  txt: 'TXT records hold text data used by external services for domain verification and security policies.',
  ns: 'NS (Name Server) records specify the authoritative DNS servers responsible for resolving the domain.',
  cname: 'CNAME (Canonical Name) records alias one domain name to another domain name.',
  spf: 'SPF (Sender Policy Framework) TXT record specifies authorized IP addresses permitted to send mail on behalf of the domain.',
  dkim: 'DKIM (DomainKeys Identified Mail) attaches a cryptographic signature to outgoing emails to verify authenticity.',
  dmarc: 'DMARC leverages SPF and DKIM to instruct receiving servers how to handle unauthenticated emails (none, quarantine, reject).',
  dnssec: 'DNSSEC adds cryptographic signatures to DNS records to prevent DNS spoofing and cache poisoning attacks.',
};

export default function DNSPage() {
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

  const dns = report.dns_info || {
    a_records: [],
    mx_records: [],
    txt_records: [],
    ns_records: [],
    spf: null,
    dmarc: null,
    dnssec: false,
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto page-enter">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="btn-ghost p-2"><ArrowLeft className="w-4 h-4" /></button>
          <div>
            <h1 className="text-xl font-bold text-[#F5F3ED] flex items-center gap-2">
              <Globe className="w-5 h-5 text-[#D4AF37]" /> DNS Records & Email Security Audit
            </h1>
            <p className="text-xs text-[#706C64]">{report.scan?.url || 'Target Site'}</p>
          </div>
        </div>
      </div>

      {/* SubNav */}
      <ReportSubNav reportId={report.id} />

      {/* Email Security Hero Card */}
      <GlassCard className="p-8 border border-[#2A2A2A] bg-[#111111]">
        <h2 className="text-lg font-bold text-[#F5F3ED] mb-2 flex items-center gap-2">
          <Mail className="w-5 h-5 text-[#D4AF37]" /> Domain Email Authentication (SPF, DMARC, DKIM)
        </h2>
        <p className="text-xs text-[#A7A39A] mb-6 leading-relaxed">
          Proper email authentication prevents domain spoofing and phishing attacks. Below is the active policy status for this domain:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* SPF */}
          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] text-xs">SPF Record</span>
              {dns.spf ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/20 text-[#4FAF72] border border-green-500/30">Configured</span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-[#F59E0B] border border-amber-500/30">Missing</span>
              )}
            </div>
            <p className="text-[11px] text-[#A7A39A]">{RECORD_EXPLANATIONS.spf}</p>
            <code className="text-[11px] text-[#D4AF37] bg-black/60 p-2 rounded block font-mono break-all border border-[#2A2A2A]">
              {dns.spf || 'No SPF record found'}
            </code>
          </div>

          {/* DMARC */}
          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] text-xs">DMARC Policy</span>
              {dns.dmarc ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/20 text-[#4FAF72] border border-green-500/30">Enforced</span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-[#EF4444] border border-red-500/30">Missing</span>
              )}
            </div>
            <p className="text-[11px] text-[#A7A39A]">{RECORD_EXPLANATIONS.dmarc}</p>
            <code className="text-[11px] text-[#D4AF37] bg-black/60 p-2 rounded block font-mono break-all border border-[#2A2A2A]">
              {dns.dmarc || 'No DMARC policy found'}
            </code>
          </div>

          {/* DNSSEC */}
          <div className="p-4 rounded-xl bg-[#0D0D0D] border border-[#2A2A2A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-[#F5F3ED] text-xs">DNSSEC Status</span>
              {dns.dnssec ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/20 text-[#4FAF72] border border-green-500/30">Active</span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-500/20 text-[#706C64] border border-slate-500/30">Inactive</span>
              )}
            </div>
            <p className="text-[11px] text-[#A7A39A]">{RECORD_EXPLANATIONS.dnssec}</p>
            <code className="text-[11px] text-[#F5F3ED] bg-black/60 p-2 rounded block font-mono border border-[#2A2A2A]">
              {dns.dnssec ? 'DNSSEC Cryptographic Signatures Verified' : 'DNSSEC signatures not published'}
            </code>
          </div>
        </div>
      </GlassCard>

      {/* DNS Record Tables */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* A & AAAA Records */}
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-[#F5F3ED] text-sm flex items-center gap-2">
              <Server className="w-4 h-4 text-[#D4AF37]" /> A (IPv4) Records ({dns.a_records?.length || 0})
            </h3>
          </div>
          <p className="text-xs text-[#A7A39A] mb-3">{RECORD_EXPLANATIONS.a}</p>
          {dns.a_records && dns.a_records.length > 0 ? (
            <div className="space-y-1 font-mono text-xs">
              {dns.a_records.map((ip) => (
                <div key={ip} className="p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A] text-[#4FAF72] font-bold">
                  {ip}
                </div>
              ))}
            </div>
          ) : <p className="text-xs text-[#706C64]">No IPv4 A records found.</p>}
        </GlassCard>

        {/* MX Records */}
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-[#F5F3ED] text-sm flex items-center gap-2">
              <Mail className="w-4 h-4 text-[#D4AF37]" /> MX (Mail Exchange) Records ({dns.mx_records?.length || 0})
            </h3>
          </div>
          <p className="text-xs text-[#A7A39A] mb-3">{RECORD_EXPLANATIONS.mx}</p>
          {dns.mx_records && dns.mx_records.length > 0 ? (
            <div className="space-y-1 font-mono text-xs">
              {dns.mx_records.map((mx, i) => (
                <div key={i} className="p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A] flex justify-between">
                  <span className="text-[#F5F3ED]">{mx.exchange}</span>
                  <span className="text-[#D4AF37] font-bold">Prio: {mx.preference}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-xs text-[#706C64]">No MX mail records found.</p>}
        </GlassCard>

        {/* NS Records */}
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-[#F5F3ED] text-sm flex items-center gap-2">
              <Globe className="w-4 h-4 text-[#D4AF37]" /> NS (Authoritative Name Servers) ({dns.ns_records?.length || 0})
            </h3>
          </div>
          <p className="text-xs text-[#A7A39A] mb-3">{RECORD_EXPLANATIONS.ns}</p>
          {dns.ns_records && dns.ns_records.length > 0 ? (
            <div className="space-y-1 font-mono text-xs">
              {dns.ns_records.map((ns) => (
                <div key={ns} className="p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED]">
                  {ns}
                </div>
              ))}
            </div>
          ) : <p className="text-xs text-[#706C64]">No NS records found.</p>}
        </GlassCard>

        {/* TXT Records */}
        <GlassCard className="p-6 border border-[#2A2A2A] bg-[#111111]">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-[#F5F3ED] text-sm flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#D4AF37]" /> All TXT Records ({dns.txt_records?.length || 0})
            </h3>
          </div>
          <p className="text-xs text-[#A7A39A] mb-3">{RECORD_EXPLANATIONS.txt}</p>
          {dns.txt_records && dns.txt_records.length > 0 ? (
            <div className="space-y-1.5 font-mono text-[11px]">
              {dns.txt_records.map((txt, i) => (
                <div key={i} className="p-2 rounded bg-[#0D0D0D] border border-[#2A2A2A] text-[#F5F3ED] break-all">
                  {txt}
                </div>
              ))}
            </div>
          ) : <p className="text-xs text-[#706C64]">No TXT records found.</p>}
        </GlassCard>
      </div>
    </div>
  );
}
