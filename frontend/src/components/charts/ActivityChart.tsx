import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { ActivityDay } from '../../types/api';

interface ActivityChartProps {
  data: ActivityDay[];
  period: '7d' | '30d';
  onPeriodChange: (p: '7d' | '30d') => void;
}

export const ActivityChart: React.FC<ActivityChartProps> = ({
  data,
  period,
  onPeriodChange,
}) => {
  // Format dates for chart axis (MM/DD)
  const formattedData = data.map((d) => ({
    ...d,
    displayDate: d.date.length >= 10 ? d.date.substring(5) : d.date,
  }));

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="rounded-xl border border-soc-border bg-slate-900/95 p-3 shadow-xl backdrop-blur-md text-xs">
          <p className="font-mono font-bold text-slate-200 mb-1.5 border-b border-slate-800 pb-1">{label}</p>
          <div className="space-y-1">
            <p className="text-red-400 flex items-center justify-between gap-4">
              <span>High Risk:</span>
              <span className="font-mono font-bold">{payload.find((p: any) => p.dataKey === 'high')?.value || 0}</span>
            </p>
            <p className="text-amber-400 flex items-center justify-between gap-4">
              <span>Medium Risk:</span>
              <span className="font-mono font-bold">{payload.find((p: any) => p.dataKey === 'medium')?.value || 0}</span>
            </p>
            <p className="text-emerald-400 flex items-center justify-between gap-4">
              <span>Low Risk:</span>
              <span className="font-mono font-bold">{payload.find((p: any) => p.dataKey === 'low')?.value || 0}</span>
            </p>
            <div className="border-t border-slate-800 pt-1 mt-1 font-semibold text-slate-100 flex items-center justify-between">
              <span>Total Scans:</span>
              <span className="font-mono">{payload.find((p: any) => p.dataKey === 'total')?.value || 0}</span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="rounded-2xl border border-soc-border bg-soc-panel p-5">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight">Security Activity Trends</h3>
          <p className="text-xs text-slate-400">Scan throughput and risk progression timeline</p>
        </div>

        <div className="inline-flex rounded-xl p-1 bg-slate-950/70 border border-soc-border text-xs">
          <button
            onClick={() => onPeriodChange('7d')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              period === '7d'
                ? 'bg-sky-500 text-white font-semibold shadow-soc-glow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            7 Days
          </button>
          <button
            onClick={() => onPeriodChange('30d')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              period === '30d'
                ? 'bg-sky-500 text-white font-semibold shadow-soc-glow'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            30 Days
          </button>
        </div>
      </div>

      <div className="h-72 w-full">
        {formattedData.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
            No activity records in this time frame
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={formattedData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2d4d" vertical={false} />
              <XAxis dataKey="displayDate" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="top"
                align="right"
                iconType="circle"
                wrapperStyle={{ paddingBottom: 15, fontSize: 11 }}
              />
              <Area
                type="monotone"
                dataKey="total"
                name="Total Scans"
                stroke="#0ea5e9"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorTotal)"
              />
              <Area
                type="monotone"
                dataKey="high"
                name="High Risk"
                stroke="#ef4444"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorHigh)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};
