import React from 'react';
import { RiskLevel } from '../../types/api';

interface RiskBadgeProps {
  level: RiskLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showPulse?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md', showPulse = true }) => {
  const normalized = (level || 'Low').toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let pulseColor = 'bg-slate-400';

  if (normalized === 'HIGH' || normalized === 'MALICIOUS') {
    colorClasses = 'bg-red-500/15 text-red-400 border-red-500/30';
    pulseColor = 'bg-red-500';
  } else if (normalized === 'MEDIUM' || normalized === 'SUSPICIOUS') {
    colorClasses = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    pulseColor = 'bg-amber-500';
  } else if (normalized === 'LOW' || normalized === 'CLEAN' || normalized === 'SAFE') {
    colorClasses = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    pulseColor = 'bg-emerald-500';
  }

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-2 font-medium',
    lg: 'text-sm px-3.5 py-1.5 gap-2.5 font-semibold',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-full border ${colorClasses} ${sizeClasses} tracking-wide uppercase transition-colors`}
    >
      {showPulse && (
        <span className="relative flex h-2 w-2">
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${pulseColor} opacity-75`} />
          <span className={`relative inline-flex rounded-full h-2 w-2 ${pulseColor}`} />
        </span>
      )}
      {level}
    </span>
  );
};
