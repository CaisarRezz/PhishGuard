import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { RiskDistributionItem } from '../../types/api';

interface RiskDonutChartProps {
  data: RiskDistributionItem[];
  totalScans: number;
}

const RISK_COLORS: Record<string, string> = {
  High: '#ef4444',
  Medium: '#f59e0b',
  Low: '#10b981',
  Unknown: '#64748b',
};

export const RiskDonutChart: React.FC<RiskDonutChartProps> = ({ data, totalScans }) => {
  const chartData = (data || []).filter((item) => item.count > 0);

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className="rounded-xl border border-soc-border bg-slate-900/95 p-3 shadow-xl backdrop-blur-md text-xs">
          <p className="font-semibold text-slate-100 flex items-center gap-2">
            <span
              className="w-2.5 h-2.5 rounded-full inline-block"
              style={{ backgroundColor: RISK_COLORS[item.level] || '#64748b' }}
            />
            {item.level} Risk
          </p>
          <div className="mt-1 font-mono text-slate-300">
            <span className="font-bold text-white text-sm">{item.count}</span> scans ({item.percentage}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="rounded-2xl border border-soc-border bg-soc-panel p-5 flex flex-col justify-between">
      <div>
        <h3 className="text-base font-bold text-white tracking-tight">Risk Distribution</h3>
        <p className="text-xs text-slate-400">Severity breakdown across all scans</p>
      </div>

      <div className="relative h-56 my-2 flex items-center justify-center">
        {totalScans === 0 ? (
          <div className="text-center text-xs text-slate-500 font-mono">
            No scans recorded yet
          </div>
        ) : (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {chartData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={RISK_COLORS[entry.level] || '#64748b'}
                      stroke="#0e1526"
                      strokeWidth={3}
                    />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>

            {/* Donut Center Statistic */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-black font-mono text-white">{totalScans}</span>
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Total Scans</span>
            </div>
          </>
        )}
      </div>

      {/* Legend with counts and percentages */}
      <div className="grid grid-cols-3 gap-2 pt-3 border-t border-soc-border">
        {['High', 'Medium', 'Low'].map((level) => {
          const item = (data || []).find((d) => d.level === level);
          const count = item ? item.count : 0;
          const percentage = item ? item.percentage : 0;
          const color = RISK_COLORS[level];

          return (
            <div key={level} className="text-center p-2 rounded-xl bg-slate-900/60 border border-soc-border/60">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-[11px] font-semibold text-slate-300">{level}</span>
              </div>
              <div className="text-sm font-bold font-mono text-white">{count}</div>
              <div className="text-[10px] text-slate-500 font-mono">{percentage}%</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
