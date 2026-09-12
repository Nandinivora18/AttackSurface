import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Severity, Grade, RiskLevel } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(dateString));
}

export function formatDateShort(dateString: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  }).format(new Date(dateString));
}

export function timeAgo(dateString: string): string {
  const now = Date.now();
  const then = new Date(dateString).getTime();
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function getSeverityColor(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: '#E05252',
    high: '#E88A32',
    medium: '#D7B34B',
    low: '#4FAF72',
    info: '#81908A',
  };
  return map[severity] ?? '#81908A';
}

export function getSeverityBgClass(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };
  return map[severity] ?? 'badge-info';
}

export function getGradeColor(grade: Grade | string): string {
  const map: Record<string, string> = {
    'A+': '#D4B978',
    'A': '#D4B978',
    'B': '#E4CCA0',
    'C': '#D7B34B',
    'D': '#E88A32',
    'F': '#E05252',
  };
  return map[grade] ?? '#81908A';
}

export function getScoreColor(score: number): string {
  if (score >= 80) return '#D4B978';
  if (score >= 60) return '#D7B34B';
  if (score >= 40) return '#E88A32';
  return '#E05252';
}

export function getRiskBadgeClass(risk: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: 'badge-critical', high: 'badge-high',
    medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
  };
  return map[risk] ?? 'badge-info';
}

export function truncateUrl(url: string, max = 40): string {
  try {
    const parsed = new URL(url);
    const display = parsed.hostname + parsed.pathname;
    return display.length > max ? display.slice(0, max) + '…' : display;
  } catch {
    return url.length > max ? url.slice(0, max) + '…' : url;
  }
}

export function getDomainFromUrl(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

export function countSeverities(findings: { severity: Severity }[]) {
  return findings.reduce(
    (acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>
  );
}

export function saveTokens(accessToken: string, _refreshToken?: string) {
  // Refresh token is managed as an HttpOnly cookie by the backend.
  // It is intentionally never written to localStorage.
  localStorage.setItem('access_token', accessToken);
}

export function clearTokens() {
  // Only clear the access token from localStorage.
  // The refresh_token HttpOnly cookie is cleared by the backend on /api/auth/logout.
  localStorage.removeItem('access_token');
  localStorage.removeItem('sentinel-auth');
}

export function isAuthenticated(): boolean {
  if (typeof window === 'undefined') return false;
  return !!localStorage.getItem('access_token');
}

export function formatAssessmentStatus(status?: string): { label: string; bg: string; text: string; border: string } {
  switch (status?.toUpperCase()) {
    case 'PASS':
      return { label: 'PASS', bg: 'bg-emerald-500/15', text: 'text-emerald-400', border: 'border-emerald-500/30' };
    case 'FAIL':
      return { label: 'FINDING', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30' };
    case 'INCONCLUSIVE':
      return { label: 'NEEDS REVIEW', bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/30' };
    case 'NOT_VERIFIABLE':
      return { label: 'NOT VERIFIABLE', bg: 'bg-purple-500/15', text: 'text-purple-400', border: 'border-purple-500/30' };
    case 'NOT_APPLICABLE':
    default:
      return { label: 'NOT APPLICABLE', bg: 'bg-slate-500/15', text: 'text-slate-400', border: 'border-slate-500/30' };
  }
}

export function formatConfidence(confidence?: string | number): string {
  if (confidence == null) return 'Medium';
  if (typeof confidence === 'number') {
    if (confidence >= 80) return 'High';
    if (confidence >= 50) return 'Medium';
    return 'Low';
  }
  const c = String(confidence).toUpperCase();
  if (c === 'CONFIRMED' || c === 'HIGH') return 'High';
  if (c === 'MEDIUM') return 'Medium';
  if (c === 'LOW') return 'Low';
  return 'Medium';
}

export { resolveFindingLocation, type ResolvedFindingLocation } from './location';
