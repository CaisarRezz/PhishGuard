export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message: string;
}

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Unknown';

export interface Finding {
  label: string;
  detail: string;
  points: number;
  status: string;
  category?: string;
}

export interface WatchlistMatch {
  id: number;
  target: string;
  threat_category: string;
  description: string;
  source?: string;
  date_added?: string;
}

export interface UrlScanResult {
  id?: number;
  url: string;
  normalized_url: string;
  hostname: string;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation: string;
  findings: Finding[];
  watchlist_match?: WatchlistMatch | null;
  created_at?: string;
  disclaimer?: string;
}

export interface QrScanResult {
  id?: number;
  filename: string;
  file_size: number;
  decoded: boolean;
  content: string;
  is_url: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation: string;
  findings: Finding[];
  url_analysis?: UrlScanResult | null;
  created_at?: string;
}

export interface EmailScanResult {
  id?: number;
  subject: string;
  sender?: string;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation: string;
  suspicious_keywords: string[];
  findings: Finding[];
  extracted_urls: string[];
  url_analyses?: {
    url: string;
    hostname: string;
    risk_score: number;
    risk_level: RiskLevel;
  }[];
  created_at?: string;
  disclaimer?: string;
}

export interface FileThreatDetails {
  threat_name: string;
  description: string;
  source: string;
  date_added: string;
}

export interface FileScanResult {
  id?: number;
  filename: string;
  file_size: number;
  sha256: string;
  reputation: 'Malicious' | 'Unknown / Clean in local DB';
  risk_score: number;
  risk_level: RiskLevel;
  threat_details?: FileThreatDetails | null;
  recommendation: string;
  findings: Finding[];
  scanned_at: string;
  disclaimer?: string;
}

export interface WatchlistEntry {
  id: number;
  target: string;
  threat_category: string;
  description?: string;
  source?: string;
  date_added: string;
}

export interface DashboardSummary {
  total_scans: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  suspicious_url_count: number;
  watchlist_matches: number;
}

export interface RiskDistributionItem {
  level: RiskLevel;
  count: number;
  percentage: number;
}

export interface RecentAlert {
  id: number;
  scan_type: string;
  target: string;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
}

export interface DashboardStats {
  summary: DashboardSummary;
  scans_by_type: {
    url: number;
    qr: number;
    email: number;
    file: number;
  };
  risk_distribution: RiskDistributionItem[];
  recent_alerts: RecentAlert[];
  recent_activities: RecentAlert[];
}

export interface ActivityDay {
  date: string;
  total: number;
  high: number;
  medium: number;
  low: number;
}

export interface ActivityTimeline {
  period: string;
  timeline: ActivityDay[];
}

export interface Pagination {
  page: number;
  per_page: number;
  total_items: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface ScanHistoryItem {
  id: number;
  scan_type: 'url' | 'qr' | 'email' | 'file' | string;
  target: string;
  url?: string;
  hostname?: string;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation: string;
  findings?: Finding[];
  details?: any;
  created_at: string;
}

export interface ServiceStatus {
  status: string;
  [key: string]: any;
}

export interface SystemStatusData {
  status: 'operational' | 'degraded' | 'offline';
  version: string;
  timestamp: string;
  services: {
    backend: ServiceStatus;
    database: ServiceStatus;
    url_analyzer: ServiceStatus;
    qr_analyzer: ServiceStatus;
    email_analyzer: ServiceStatus;
    file_analyzer: ServiceStatus;
  };
}
