import React, { useState } from 'react';
import {
  Globe,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ExternalLink,
} from 'lucide-react';
import { scanUrl, getErrorMessage } from '../services/api';
import { UrlScanResult } from '../types/api';
import { RiskBadge } from '../components/common/RiskBadge';
import { LoadingState } from '../components/common/LoadingState';
import { useToast } from '../components/common/Toast';

export const UrlScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [copied, setCopied] = useState(false);
  const { error, success } = useToast();

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetUrl = url.trim();

    if (!targetUrl) {
      error('Input Validation Error', 'Please enter a valid URL or domain name.');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const data = await scanUrl(targetUrl);
      setResult(data);
      success('Scan Complete', `Risk evaluation completed: ${data.risk_level} Risk (${data.risk_score}/100)`);
    } catch (err) {
      error('Scan Failed', getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleQuickSample = (sampleUrl: string) => {
    setUrl(sampleUrl);
  };

  const copyNormalized = () => {
    if (result?.normalized_url) {
      navigator.clipboard.writeText(result.normalized_url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <Globe className="w-6 h-6 text-sky-400" />
          <h1 className="text-2xl font-black text-white tracking-tight">URL THREAT SCANNER</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Local heuristic URL analysis & threat intelligence verification. Never automatically fetches remote URLs.
        </p>
      </div>

      {/* Input Card */}
      <div className="rounded-2xl border border-soc-border bg-soc-panel p-6 shadow-soc-card">
        <form onSubmit={handleScan} className="space-y-4">
          <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
            Target URL or Hostname
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="e.g. secure-login.bank-update.com/verify or http://192.168.1.1/login"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-950/80 border border-soc-border text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 font-mono transition-all"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-white font-bold text-xs uppercase tracking-wider shadow-soc-glow transition-all shrink-0"
            >
              <Search className="w-4 h-4" />
              <span>{loading ? 'Analyzing...' : 'Analyze Threat'}</span>
            </button>
          </div>

          {/* Quick preset chips */}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-[11px] text-slate-400 font-mono">Quick test presets:</span>
            <button
              type="button"
              onClick={() => handleQuickSample('https://phishing-bank-login.com')}
              className="text-[11px] px-2.5 py-1 rounded-lg bg-red-950/40 text-red-300 border border-red-800/40 hover:bg-red-900/40 font-mono transition-colors"
            >
              Watchlist Hit (High)
            </button>
            <button
              type="button"
              onClick={() => handleQuickSample('http://192.168.1.50/login/account-verification')}
              className="text-[11px] px-2.5 py-1 rounded-lg bg-amber-950/40 text-amber-300 border border-amber-800/40 hover:bg-amber-900/40 font-mono transition-colors"
            >
              IP & Keywords (Suspicious)
            </button>
            <button
              type="button"
              onClick={() => handleQuickSample('https://github.com')}
              className="text-[11px] px-2.5 py-1 rounded-lg bg-emerald-950/40 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/40 font-mono transition-colors"
            >
              Legitimate Domain (Low)
            </button>
          </div>
        </form>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="rounded-2xl border border-soc-border bg-soc-panel">
          <LoadingState message="Extracting URL Structural Heuristics..." submessage="Inspecting domain tokens, punycode patterns, and watchlist DB" />
        </div>
      )}

      {/* Results View */}
      {result && !loading && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Watchlist Match Warning Banner */}
          {result.watchlist_match && (
            <div className="p-4 rounded-2xl bg-red-950/80 border border-red-500/60 shadow-soc-glow-danger flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-bold text-red-200 uppercase tracking-wide">
                  CRITICAL: Exact Threat Watchlist Match Detected
                </h4>
                <p className="text-xs text-red-300 mt-0.5">
                  Target is explicitly blacklisted in the local SOC intelligence database under category{' '}
                  <span className="font-bold underline">{result.watchlist_match.threat_category}</span>.
                  {result.watchlist_match.description && ` — "${result.watchlist_match.description}"`}
                </p>
              </div>
            </div>
          )}

          {/* Score & Core Metrics Header */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Risk Gauge Card */}
            <div className="p-6 rounded-2xl border border-soc-border bg-soc-panel flex flex-col items-center justify-center text-center">
              <span className="text-xs font-mono uppercase text-slate-400 font-bold mb-3">Overall Threat Score</span>
              <div className="relative flex items-center justify-center w-28 h-28 mb-3">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-800"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={
                      result.risk_score >= 60
                        ? 'text-red-500'
                        : result.risk_score >= 30
                        ? 'text-amber-500'
                        : 'text-emerald-500'
                    }
                    strokeDasharray={`${result.risk_score}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="text-3xl font-black font-mono text-white">{result.risk_score}</span>
                  <span className="text-[10px] font-mono text-slate-400">/ 100</span>
                </div>
              </div>
              <RiskBadge level={result.risk_level} size="lg" />
            </div>

            {/* Target Breakdown Card */}
            <div className="p-6 rounded-2xl border border-soc-border bg-soc-panel md:col-span-2 flex flex-col justify-between">
              <div>
                <span className="text-xs font-mono uppercase text-slate-400 font-bold">Target Identity</span>
                <div className="mt-2 space-y-2">
                  <div className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-950 border border-soc-border font-mono">
                    <span className="text-slate-400">Hostname:</span>
                    <span className="font-bold text-sky-400">{result.hostname}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs p-2 rounded-lg bg-slate-950 border border-soc-border font-mono">
                    <span className="text-slate-400">Normalized URL:</span>
                    <div className="flex items-center gap-2 max-w-[70%]">
                      <span className="truncate text-slate-200" title={result.normalized_url}>
                        {result.normalized_url}
                      </span>
                      <button
                        onClick={copyNormalized}
                        className="p-1 text-slate-400 hover:text-white transition-colors shrink-0"
                        title="Copy normalized URL"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommendation Box */}
              <div className="mt-4 p-3.5 rounded-xl bg-slate-900/80 border border-slate-700/60">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5 mb-1">
                  <Info className="w-3.5 h-3.5 text-sky-400" />
                  Security Recommendation
                </span>
                <p className="text-xs text-slate-200 leading-relaxed">{result.recommendation}</p>
              </div>
            </div>
          </div>

          {/* Detailed Findings Table */}
          <div className="rounded-2xl border border-soc-border bg-soc-panel p-5">
            <h3 className="text-base font-bold text-white tracking-tight mb-1">Heuristic Indicator Analysis</h3>
            <p className="text-xs text-slate-400 mb-4">Granular feature breakdown evaluated against local detection rules</p>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-soc-border text-slate-400 font-mono">
                    <th className="pb-3 w-12 text-center">Status</th>
                    <th className="pb-3">Detection Indicator</th>
                    <th className="pb-3">Heuristic Detail</th>
                    <th className="pb-3 text-right">Points</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/50">
                  {result.findings.map((f, i) => {
                    const detected = f.points > 0 || f.status === 'Indikator ditemukan';
                    return (
                      <tr key={i} className={`hover:bg-slate-900/40 transition-colors ${detected ? 'bg-red-500/5' : ''}`}>
                        <td className="py-3 text-center">
                          {detected ? (
                            <XCircle className="w-4 h-4 text-red-400 mx-auto" />
                          ) : (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                          )}
                        </td>
                        <td className="py-3 font-semibold text-slate-200">
                          {f.label}
                        </td>
                        <td className="py-3 text-slate-400 text-[11px] max-w-md">
                          {f.detail}
                        </td>
                        <td className="py-3 text-right font-mono font-bold">
                          <span className={detected ? 'text-red-400' : 'text-slate-500'}>
                            {f.points > 0 ? `+${f.points}` : '0'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Disclaimer */}
            <div className="mt-4 pt-3 border-t border-soc-border/60 text-[11px] text-slate-500 font-mono">
              Notice: {result.disclaimer}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
