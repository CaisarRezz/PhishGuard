import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Globe,
  QrCode,
  Mail,
  FileCode,
  Activity,
  AlertTriangle,
  Database,
  Cpu,
  RefreshCw,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { getDashboardStats, getDashboardActivity, getSystemStatus, getErrorMessage } from '../services/api';
import { DashboardStats, ActivityTimeline, SystemStatusData, RecentAlert } from '../types/api';
import { StatCard } from '../components/common/StatCard';
import { RiskBadge } from '../components/common/RiskBadge';
import { LoadingState } from '../components/common/LoadingState';
import { ActivityChart } from '../components/charts/ActivityChart';
import { RiskDonutChart } from '../components/charts/RiskDonutChart';
import { useToast } from '../components/common/Toast';

export const Overview: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activity, setActivity] = useState<ActivityTimeline | null>(null);
  const [system, setSystem] = useState<SystemStatusData | null>(null);
  const [period, setPeriod] = useState<'7d' | '30d'>('7d');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const { error } = useToast();
  const navigate = useNavigate();

  const loadData = async (showLoadingSpinner = true) => {
    if (showLoadingSpinner) setLoading(true);
    setRefreshing(true);
    try {
      const [statsData, activityData, systemData] = await Promise.all([
        getDashboardStats(),
        getDashboardActivity(period),
        getSystemStatus(),
      ]);
      setStats(statsData);
      setActivity(activityData);
      setSystem(systemData);
    } catch (err) {
      error('Failed to load dashboard metrics', getErrorMessage(err));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [period]);

  if (loading && !stats) {
    return <LoadingState message="Connecting to SOC Telemetry..." submessage="Fetching real-time database statistics" />;
  }

  const summary = stats?.summary || {
    total_scans: 0,
    high_risk_count: 0,
    medium_risk_count: 0,
    low_risk_count: 0,
    suspicious_url_count: 0,
    watchlist_matches: 0,
  };

  const services = system?.services;

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-black text-white tracking-tight">SOC OVERVIEW</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-sky-500/10 text-sky-400 border border-sky-500/20">
              Live Telemetry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise threat detection engine & security intelligence monitoring
          </p>
        </div>

        <button
          onClick={() => loadData(false)}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-xl border border-soc-border bg-slate-900 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-sky-400' : ''}`} />
          <span>Refresh Data</span>
        </button>
      </div>

      {/* Top Statistic Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={summary.total_scans}
          subtitle="Analyzed across all modules"
          icon={Activity}
          variant="primary"
        />
        <StatCard
          title="High Risk Threats"
          value={summary.high_risk_count}
          subtitle="Critical malicious detections"
          icon={ShieldAlert}
          variant="danger"
        />
        <StatCard
          title="Suspicious URLs"
          value={summary.suspicious_url_count}
          subtitle="URLs with risk score >= 30"
          icon={Globe}
          variant="warning"
        />
        <StatCard
          title="Watchlist Matches"
          value={summary.watchlist_matches}
          subtitle="Known threat domain hits"
          icon={AlertTriangle}
          variant="danger"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ActivityChart
            data={activity?.timeline || []}
            period={period}
            onPeriodChange={setPeriod}
          />
        </div>

        <div className="lg:col-span-1">
          <RiskDonutChart
            data={stats?.risk_distribution || []}
            totalScans={summary.total_scans}
          />
        </div>
      </div>

      {/* Engine Status Grid */}
      <div className="rounded-2xl border border-soc-border bg-soc-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white tracking-tight">Security Engines & Service Health</h3>
            <p className="text-xs text-slate-400">Live operational status confirmed by backend diagnostics</p>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Engine Version: <span className="text-sky-400 font-bold">{system?.version || '2.0.0'}</span>
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {[
            {
              name: 'URL Analyzer',
              icon: Globe,
              status: services?.url_analyzer?.status || 'unknown',
              meta: `${services?.url_analyzer?.active_rules || 10} Rules Active`,
            },
            {
              name: 'QR Shield',
              icon: QrCode,
              status: services?.qr_analyzer?.status || 'unknown',
              meta: services?.qr_analyzer?.engine || 'OpenCV Engine',
            },
            {
              name: 'MailGuard',
              icon: Mail,
              status: services?.email_analyzer?.status || 'unknown',
              meta: `${services?.email_analyzer?.heuristic_rules || 6} Heuristics`,
            },
            {
              name: 'FileGuard',
              icon: FileCode,
              status: services?.file_analyzer?.status || 'unknown',
              meta: `${services?.file_analyzer?.known_threat_hashes || 0} Signatures`,
            },
            {
              name: 'Database API',
              icon: Database,
              status: services?.database?.status || 'unknown',
              meta: `${services?.database?.total_records || 0} Records`,
            },
          ].map((engine) => {
            const Icon = engine.icon;
            const isOperational = engine.status.toLowerCase().includes('operational') || engine.status.toLowerCase() === 'online';

            return (
              <div
                key={engine.name}
                className="p-3.5 rounded-xl border border-soc-border/80 bg-slate-950/50 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-sky-400">
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="relative flex h-2 w-2">
                    <span
                      className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
                        isOperational ? 'bg-emerald-400 animate-ping' : 'bg-red-400'
                      }`}
                    />
                    <span
                      className={`relative inline-flex rounded-full h-2 w-2 ${
                        isOperational ? 'bg-emerald-500' : 'bg-red-500'
                      }`}
                    />
                  </span>
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200">{engine.name}</h4>
                  <p className="text-[10px] font-mono text-slate-400 truncate mt-0.5">{engine.meta}</p>
                  <span
                    className={`inline-block mt-2 text-[10px] font-bold font-mono uppercase ${
                      isOperational ? 'text-emerald-400' : 'text-red-400'
                    }`}
                  >
                    {isOperational ? 'Operational' : engine.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Two-Column Tables: Recent Security Alerts & Latest Activities */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Security Alerts */}
        <div className="rounded-2xl border border-soc-border bg-soc-panel p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">Recent Security Alerts</h3>
              <p className="text-xs text-slate-400">High severity detections requiring attention</p>
            </div>
            <button
              onClick={() => navigate('/alerts')}
              className="text-xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
            >
              <span>View All</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto flex-1">
            {(!stats?.recent_alerts || stats.recent_alerts.length === 0) ? (
              <div className="h-44 flex flex-col items-center justify-center text-xs text-slate-500 font-mono">
                No high-risk security alerts recorded
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-soc-border text-slate-500 font-mono">
                    <th className="pb-2.5">Type</th>
                    <th className="pb-2.5">Target</th>
                    <th className="pb-2.5">Risk</th>
                    <th className="pb-2.5 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/50">
                  {stats.recent_alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => navigate(`/history?search=${encodeURIComponent(alert.target)}`)}
                      className="hover:bg-slate-900/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 font-mono text-sky-400 uppercase font-bold text-[11px]">
                        {alert.scan_type}
                      </td>
                      <td className="py-2.5 text-slate-200 font-mono truncate max-w-[180px]" title={alert.target}>
                        {alert.target}
                      </td>
                      <td className="py-2.5">
                        <RiskBadge level={alert.risk_level} size="sm" />
                      </td>
                      <td className="py-2.5 text-right text-slate-400 font-mono text-[10px]">
                        {alert.created_at ? alert.created_at.replace('T', ' ').substring(0, 19) : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Recent Scan Activities */}
        <div className="rounded-2xl border border-soc-border bg-soc-panel p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">Recent Scan Activity</h3>
              <p className="text-xs text-slate-400">Live feed of all threat inspection tasks</p>
            </div>
            <button
              onClick={() => navigate('/history')}
              className="text-xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
            >
              <span>Full History</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto flex-1">
            {(!stats?.recent_activities || stats.recent_activities.length === 0) ? (
              <div className="h-44 flex flex-col items-center justify-center text-xs text-slate-500 font-mono">
                No scan activity records found
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-soc-border text-slate-500 font-mono">
                    <th className="pb-2.5">Module</th>
                    <th className="pb-2.5">Target</th>
                    <th className="pb-2.5">Score</th>
                    <th className="pb-2.5 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/50">
                  {stats.recent_activities.slice(0, 5).map((act) => (
                    <tr
                      key={act.id}
                      onClick={() => navigate(`/history?search=${encodeURIComponent(act.target)}`)}
                      className="hover:bg-slate-900/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 font-mono text-slate-400 uppercase font-semibold text-[11px]">
                        {act.scan_type}
                      </td>
                      <td className="py-2.5 text-slate-200 font-mono truncate max-w-[180px]" title={act.target}>
                        {act.target}
                      </td>
                      <td className="py-2.5 font-mono font-bold">
                        <span className={act.risk_score >= 60 ? 'text-red-400' : act.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                          {act.risk_score}
                        </span>
                      </td>
                      <td className="py-2.5 text-right text-slate-400 font-mono text-[10px]">
                        {act.created_at ? act.created_at.replace('T', ' ').substring(0, 19) : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
