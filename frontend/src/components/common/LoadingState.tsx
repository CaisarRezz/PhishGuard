import React from 'react';
import { Shield } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  submessage?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Analyzing security heuristics...',
  submessage = 'Connecting to local threat intelligence database',
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center">
      <div className="relative flex items-center justify-center w-24 h-24 mb-6">
        {/* Radar concentric rings */}
        <div className="absolute inset-0 rounded-full border border-sky-500/20 animate-ping opacity-30" />
        <div className="absolute inset-2 rounded-full border border-sky-500/30 animate-pulse" />
        <div className="absolute inset-4 rounded-full border border-dashed border-sky-500/40 radar-spinner" />
        
        {/* Center icon */}
        <div className="relative p-3.5 rounded-2xl bg-sky-950/80 border border-sky-500/40 shadow-soc-glow">
          <Shield className="w-7 h-7 text-sky-400 animate-pulse" />
        </div>
      </div>
      <h4 className="text-base font-semibold text-slate-100">{message}</h4>
      <p className="mt-1 text-xs text-slate-400 font-mono">{submessage}</p>
    </div>
  );
};
