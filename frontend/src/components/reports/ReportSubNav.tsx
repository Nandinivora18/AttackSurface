'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, ShieldCheck, Lock, Globe, Cpu } from 'lucide-react';

interface ReportSubNavProps {
  reportId: string;
}

export default function ReportSubNav({ reportId }: ReportSubNavProps) {
  const pathname = usePathname();

  const TABS = [
    { href: `/reports/${reportId}`, label: 'Overview & Findings', icon: LayoutDashboard, exact: true },
    { href: `/reports/${reportId}/headers`, label: 'Security Headers', icon: ShieldCheck },
    { href: `/reports/${reportId}/ssl`, label: 'SSL / TLS Certificate', icon: Lock },
    { href: `/reports/${reportId}/dns`, label: 'DNS Records', icon: Globe },
    { href: `/reports/${reportId}/tech`, label: 'Technology Stack', icon: Cpu },
  ];

  return (
    <div className="flex items-center gap-1 border-b border-[#2A2A2A]/80 pb-3 mb-6 overflow-x-auto">
      {TABS.map((tab) => {
        const isActive = tab.exact ? pathname === tab.href : pathname.startsWith(tab.href);
        const Icon = tab.icon;

        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
              isActive
                ? 'bg-[#161616] text-[#F5F3ED] border border-[#5C4A20] shadow-[0_0_12px_rgba(212,175,55,0.15)]'
                : 'text-[#A7A39A] hover:text-[#F5F3ED] hover:bg-[#111111] border border-transparent'
            }`}
          >
            <Icon className={`w-4 h-4 ${isActive ? 'text-[#D4AF37]' : 'text-[#706C64]'}`} />
            <span>{tab.label}</span>
          </Link>
        );
      })}
    </div>
  );
}
