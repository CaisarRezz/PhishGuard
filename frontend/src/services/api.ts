import axios, { AxiosError } from 'axios';
import {
  ApiResponse,
  SystemStatusData,
  UrlScanResult,
  QrScanResult,
  EmailScanResult,
  FileScanResult,
  WatchlistEntry,
  DashboardStats,
  ActivityTimeline,
  ScanHistoryItem,
  Pagination,
} from '../types/api';

// Base API URL: Supports direct backend access or Vite proxy
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

// Centralized error message extractor
export const getErrorMessage = (error: unknown): string => {
  if (axios.isAxiosError(error)) {
    const serverMessage = error.response?.data?.message;
    if (serverMessage) return serverMessage;
    if (error.code === 'ECONNABORTED') return 'Request timeout: Server took too long to respond.';
    if (error.response?.status === 413) return 'Upload size exceeds maximum allowed limit.';
    if (error.response?.status === 404) return 'The requested resource was not found.';
    if (error.response?.status === 500) return 'Internal server error in backend processing.';
    if (!error.response) return 'Cannot connect to PhishGuard backend server at ' + API_BASE_URL;
  }
  return error instanceof Error ? error.message : 'An unexpected error occurred.';
};

// 1. System Health
export const getSystemStatus = async (): Promise<SystemStatusData> => {
  const resp = await apiClient.get<ApiResponse<SystemStatusData>>('/system/status');
  return resp.data.data;
};

// 2. URL Scanner
export const scanUrl = async (url: string): Promise<UrlScanResult> => {
  const resp = await apiClient.post<ApiResponse<UrlScanResult>>('/url/scan', { url });
  return resp.data.data;
};

// 3. QR Shield
export const scanQrCode = async (file: File): Promise<QrScanResult> => {
  const formData = new FormData();
  formData.append('file', file);
  const resp = await apiClient.post<ApiResponse<QrScanResult>>('/qr/scan', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return resp.data.data;
};

// 4. MailGuard
export const analyzeEmail = async (payload: {
  subject: string;
  body: string;
  sender?: string;
}): Promise<EmailScanResult> => {
  const resp = await apiClient.post<ApiResponse<EmailScanResult>>('/email/analyze', payload);
  return resp.data.data;
};

// 5. FileGuard
export const scanFile = async (file: File): Promise<FileScanResult> => {
  const formData = new FormData();
  formData.append('file', file);
  const resp = await apiClient.post<ApiResponse<FileScanResult>>('/file/scan', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return resp.data.data;
};

// 6. Threat Watchlist
export const getWatchlist = async (search?: string): Promise<{ total: number; items: WatchlistEntry[] }> => {
  const resp = await apiClient.get<ApiResponse<{ total: number; items: WatchlistEntry[] }>>('/watchlist', {
    params: { search },
  });
  return resp.data.data;
};

export const addWatchlistEntry = async (payload: {
  target: string;
  threat_category: string;
  description?: string;
  source?: string;
}): Promise<WatchlistEntry> => {
  const resp = await apiClient.post<ApiResponse<WatchlistEntry>>('/watchlist', payload);
  return resp.data.data;
};

export const deleteWatchlistEntry = async (id: number): Promise<{ deleted_id: number }> => {
  const resp = await apiClient.delete<ApiResponse<{ deleted_id: number }>>(`/watchlist/${id}`);
  return resp.data.data;
};

// 7. Dashboard Analytics
export const getDashboardStats = async (): Promise<DashboardStats> => {
  const resp = await apiClient.get<ApiResponse<DashboardStats>>('/dashboard/stats');
  return resp.data.data;
};

export const getDashboardActivity = async (period: '7d' | '30d' = '7d'): Promise<ActivityTimeline> => {
  const resp = await apiClient.get<ApiResponse<ActivityTimeline>>('/dashboard/activity', {
    params: { period },
  });
  return resp.data.data;
};

// 8. Unified Scan History
export const getScanHistory = async (params: {
  type?: string;
  risk?: string;
  search?: string;
  page?: number;
  per_page?: number;
}): Promise<{ items: ScanHistoryItem[]; pagination: Pagination }> => {
  const resp = await apiClient.get<ApiResponse<{ items: ScanHistoryItem[]; pagination: Pagination }>>('/history', {
    params,
  });
  return resp.data.data;
};

export const getScanHistoryDetail = async (id: number): Promise<ScanHistoryItem> => {
  const resp = await apiClient.get<ApiResponse<ScanHistoryItem>>(`/history/${id}`);
  return resp.data.data;
};

export default apiClient;
