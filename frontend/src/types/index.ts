// Shared TypeScript types for the entire frontend

export interface User {
  id: string;
  email: string;
  name: string;
  avatar_url?: string;
  google_id?: string;
  role: 'user' | 'admin';
  is_verified: boolean;
  created_at: string;
  last_login?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface StageTimelineItem {
  stage: string;
  label: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  duration_ms?: number;
  started_at?: string;
  completed_at?: string;
  timestamp?: string;
}

export interface Scan {
  id: string;
  url: string;
  status: ScanStatus;
  progress: number;
  current_stage?: string;
  error_message?: string;
  scan_mode?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  overall_score?: number;
  grade?: Grade;
  report_id?: string;
  timeline?: StageTimelineItem[];
  report?: {
    id?: string;
    overall_score?: number;
    grade?: Grade;
    risk_level?: RiskLevel;
    findings_count?: number;
    findings?: Finding[];
  };
}

export interface OWASPMapping {
  id: string;          // e.g. "A05"
  title: string;       // e.g. "Security Misconfiguration"
  description: string;
  reference: string;   // official OWASP URL
}

export interface MITREMapping {
  technique_id: string;   // e.g. "T1557"
  technique_name: string; // e.g. "Adversary-in-the-Middle"
  description: string;
  reference: string;      // official MITRE ATT&CK URL
}

export interface CategoryScore {
  label: string;
  score: number;
  max: number;
  pct: number;
  color: 'green' | 'yellow' | 'orange' | 'red';
  recommendations: string[];
  deductions?: Array<{ finding_title: string; severity: string; points_deducted: number }>;
  icon?: string;
}

export interface Finding {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  status?: 'open' | 'accepted_risk' | 'resolved' | 'false_positive';
  confidence?: 'high' | 'medium' | 'low';
  cvss_score?: number;
  cve_id?: string;
  cwe_id?: string;
  endpoint?: string;
  published_date?: string;
  recommendation?: string;
  problem?: string;
  impact?: string;
  risk_analysis?: string;
  technical_details?: string;
  fix_steps?: string[];
  configuration_example?: string;
  best_practices?: string;
  official_documentation?: string;
  references?: string[];
  evidence?: string;
  owasp_mapping?: OWASPMapping;
  mitre_mapping?: MITREMapping;
  is_passed_control?: boolean;
  created_at?: string;
}

export interface TechInfo {
  category: string;
  confidence: number;
  version?: string;
  icon?: string;
}

export interface SslInfo {
  supported: boolean;
  grade?: string;          // A+, A, B, C, F, N/A
  tls_version?: string;
  cipher?: { name: string; protocol: string; bits: number };
  certificate?: {
    subject: string;
    issuer: string;
    not_before: string;
    not_after: string;
    days_remaining: number;
    san: string[];
    serial_number?: string;
    version?: number;
  };
  issues?: Array<{ severity: string; message: string }>;
}

export interface DnsInfo {
  a_records: string[];
  mx_records: { preference: number; exchange: string }[];
  txt_records: string[];
  ns_records: string[];
  spf?: string;
  dmarc?: string;
  dnssec?: boolean;
}

export interface ScanBasicInfo {
  id: string;
  url: string;
  status: string;
  created_at: string;
}

export interface ExecutiveSummary {
  overall_risk: string;
  business_impact: string;
  strengths: string[];
  weaknesses: string[];
  critical_issues: string[];
  quick_wins: string[];
  priority_fixes: string[];
  security_posture: string;
}

export interface OWASPCategoryAssessment {
  name: string;
  status: 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NOT_APPLICABLE' | 'NOT_VERIFIABLE';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  method: string;
  findings_count: number;
  limitations: string;
}

export interface ComponentInventoryItem {
  technology: string;
  category: string;
  raw_version: string | null;
  normalized_version: string | null;
  vendor_suffix: string | null;
  version_confidence: string;
  source: string;
  evidence: string;
  lifecycle_status: 'SUPPORTED' | 'UPDATE_AVAILABLE' | 'SECURITY_SUPPORT_ENDED' | 'END_OF_LIFE' | 'LIFECYCLE_UNKNOWN' | 'VERSION_UNKNOWN';
  eol_date: string | null;
  latest_version: string | null;
  cves?: Array<Record<string, any>>;
  cve_count?: number;
  notes?: string;
}

export interface DiscoveredEndpointItem {
  url: string;
  method: string;
  status?: number;
  depth?: number;
  content_type?: string;
}

export interface Report {
  id: string;
  scan_id: string;
  overall_score: number;
  grade: Grade;
  risk_level: RiskLevel;
  summary?: string;
  scan_mode?: string;
  executive_summary?: ExecutiveSummary;
  tech_stack?: Record<string, TechInfo>;
  raw_headers?: Record<string, string>;
  ssl_info?: SslInfo;
  dns_info?: DnsInfo;
  score_breakdown?: Record<string, CategoryScore>;
  timeline?: StageTimelineItem[];
  findings: Finding[];
  owasp_summary?: Record<string, OWASPCategoryAssessment>;
  component_inventory?: ComponentInventoryItem[];
  discovered_endpoints?: DiscoveredEndpointItem[];
  scan?: ScanBasicInfo;
  created_at: string;
}

export interface ScanProgressEvent {
  type?: string;
  scan_id: string;
  progress: number;
  stage: string;
  message: string;
  status?: string;
  findings_count?: number;
  report_id?: string;
  error?: string;
  timeline?: StageTimelineItem[];
}

export interface AdminStats {
  total_users: number;
  total_scans: number;
  total_reports: number;
  average_security_score: number;
  today_scans?: number;
  weekly_scans?: number;
  most_common_findings?: { title: string; count: number }[];
  most_vulnerable_tech?: { name: string; count: number }[];
  most_common_missing_headers?: { header: string; count: number }[];
  system_status?: {
    database: string;
    worker_status: string;
    queue_status: string;
    redis: string;
    api_usage: string;
  };
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Notification {
  id: string;
  type: string;
  title: string;
  message?: string;
  is_read: boolean;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface UserScanStats {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  average_score: number | null;
}

export interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  average_score: number | null;
  latest_grade?: string;
  total_assets?: number;
  findings_by_severity?: Record<string, number>;
}


