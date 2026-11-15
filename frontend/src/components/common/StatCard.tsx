import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'primary' | 'danger' | 'warning' | 'success' | 'default';
  trend?: {
    value: string;
    isPositive?: boolean;
  };
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'default',
  trend,
}) => {
  const variantStyles = {
    primary: {
      border: 'border-sky-500/30 hover:border-sky-500/50',
      glow: 'from-sky-500/10 via-transparent to-transparent',
      iconBg: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
      text: 'text-sky-400',
    },
    danger: {
      border: 'border-red-500/30 hover:border-red-500/50',
      glow: 'from-red-500/10 via-transparent to-transparent',
      iconBg: 'bg-red-500/15 text-red-400 border-red-500/30',
      text: 'text-red-400',
    },
    warning: {
      border: 'border-amber-500/30 hover:border-amber-500/50',
      glow: 'from-amber-500/10 via-transparent to-transparent',
      iconBg: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
      text: 'text-amber-400',
    },
    success: {
      border: 'border-emerald-500/30 hover:border-emerald-500/50',
      glow: 'from-emerald-500/10 via-transparent to-transparent',
      iconBg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      text: 'text-emerald-400',
    },
    default: {
      border: 'border-soc-border hover:border-soc-borderLight',
      glow: 'from-slate-800/20 via-transparent to-transparent',
      iconBg: 'bg-slate-800/60 text-slate-300 border-slate-700/50',
      text: 'text-slate-100',
    },
  }[variant];

  return (
    <div
      className={`relative overflow-hidden rounded-2xl bg-soc-panel border ${variantStyles.border} p-5 transition-all duration-300 hover:shadow-soc-card group`}
    >
      <div className={`absolute -top-12 -right-12 w-32 h-32 rounded-full bg-gradient-to-br ${variantStyles.glow} blur-2xl group-hover:scale-125 transition-transform duration-500`} />
      
      <div className="relative flex items-start justify-between">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold tracking-tight text-white font-mono">{value}</span>
            {trend && (
              <span
                className={`text-xs font-semibold px-1.5 py-0.5 rounded ${
                  trend.isPositive ? 'text-emerald-400 bg-emerald-500/10' : 'text-slate-400 bg-slate-800'
                }`}
              >
                {trend.value}
              </span>
            )}
          </div>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>

        <div className={`p-3 rounded-xl border ${variantStyles.iconBg} shadow-inner`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
