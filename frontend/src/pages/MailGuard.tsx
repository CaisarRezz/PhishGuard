import React, { useState } from 'react';
import { Mail, AlertTriangle, Link2, ChevronDown, ChevronUp } from 'lucide-react';
import { analyzeEmail, getErrorMessage } from '../services/api';
import type { EmailScanResult } from '../types/api';
import { RiskBadge } from '../components/common/RiskBadge';
import { LoadingState } from '../components/common/LoadingState';
import { useToast } from '../components/common/Toast';

function getRiskColor(level: string): string {
  switch (level?.toLowerCase()) {
    case 'high': return 'text-soc-danger';
    case 'medium': return 'text-soc-warning';
    case 'low': return 'text-soc-success';
    default: return 'text-soc-muted';
  }
}

function getRiskScoreColor(score: number): string {
  if (score >= 70) return 'text-soc-danger';
  if (score >= 40) return 'text-soc-warning';
  return 'text-soc-success';
}

export const MailGuard: React.FC = () => {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [body, setBody] = useState('');
  const [result, setResult] = useState<EmailScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  const { addToast } = useToast();

  const handleAnalyze = async () => {
    if (!body.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const data = await analyzeEmail({ subject, body, sender });
      setResult(data as EmailScanResult);
    } catch (err) {
      addToast(getErrorMessage(err), 'error');
    } finally {
      setLoading(false);
    }
  };

  const toggleFinding = (idx: number) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-soc-text flex items-center gap-3">
          <span className="p-2 bg-soc-primary/20 rounded-lg">
            <Mail className="w-6 h-6 text-soc-primary" />
          </span>
          MailGuard
        </h1>
        <p className="text-soc-muted mt-1">Heuristic Email Phishing Analyzer</p>
      </div>

      {/* Disclaimer Banner */}
      <div className="flex items-start gap-3 bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
        <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <p className="text-amber-300 text-sm">
          This is local heuristic analysis only. SPF/DKIM/DMARC not verified.
        </p>
      </div>

      {/* Input Card */}
      <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium text-soc-text mb-1.5">Email Subject</label>
          <input
            type="text"
            value={subject}
            onChange={e => setSubject(e.target.value)}
            placeholder="Enter email subject..."
            className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-soc-text mb-1.5">
            Sender Address <span className="text-soc-muted font-normal">(optional)</span>
          </label>
          <input
            type="text"
            value={sender}
            onChange={e => setSender(e.target.value)}
            placeholder="sender@example.com"
            className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-soc-text mb-1.5">Email Body</label>
          <textarea
            value={body}
            onChange={e => setBody(e.target.value)}
            placeholder="Paste the email body here..."
            className="w-full min-h-[200px] bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200 resize-y font-mono text-sm"
          />
        </div>
        <button
          onClick={handleAnalyze}
          disabled={!body.trim() || loading}
          className="w-full bg-soc-primary hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2.5 rounded-lg font-medium transition-all duration-200"
        >
          {loading ? 'Analyzing...' : 'Analyze Email'}
        </button>
      </div>

      {/* Loading */}
      {loading && <LoadingState message="Analyzing email for phishing indicators..." />}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-5">
          {/* Risk Score Card */}
          <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6 flex flex-col sm:flex-row items-center gap-6">
            <div className="text-center">
              <div className={`text-6xl font-black ${getRiskScoreColor(result.risk_score)}`}>
                {result.risk_score}
              </div>
              <div className="text-soc-muted text-sm mt-1">Risk Score</div>
            </div>
            <div className="flex flex-col gap-2">
              <RiskBadge level={result.risk_level} />
              {result.disclaimer && (
                <p className="text-soc-muted text-xs max-w-sm">{result.disclaimer}</p>
              )}
            </div>
          </div>

          {/* Suspicious Keywords */}
          {result.suspicious_keywords.length > 0 && (
            <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6">
              <h2 className="text-sm font-semibold text-soc-text mb-3 uppercase tracking-wider">
                Suspicious Keywords
              </h2>
              <div className="flex flex-wrap gap-2">
                {result.suspicious_keywords.map((kw, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 bg-amber-500/20 border border-amber-500/30 text-amber-300 rounded-md text-sm font-mono"
                  >
                    {kw}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Extracted URLs */}
          {result.extracted_urls.length > 0 && (
            <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6">
              <h2 className="text-sm font-semibold text-soc-text mb-3 uppercase tracking-wider flex items-center gap-2">
                <Link2 className="w-4 h-4 text-soc-muted" />
                Extracted URLs ({result.extracted_urls.length})
              </h2>
              <div className="space-y-2">
                {result.extracted_urls.map((u, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 bg-soc-card border border-soc-border rounded-lg px-3 py-2.5"
                  >
                    <span className="font-mono text-sm text-soc-text truncate flex-1 max-w-[60%]">
                      {u.url}
                    </span>
                    <span className={`text-sm font-bold ml-auto mr-2 ${getRiskScoreColor(u.risk_score)}`}>
                      {u.risk_score}
                    </span>
                    <RiskBadge level={u.risk_level} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {result.findings.length > 0 && (
            <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6">
              <h2 className="text-sm font-semibold text-soc-text mb-3 uppercase tracking-wider">
                Findings ({result.findings.length})
              </h2>
              <div className="space-y-2">
                {result.findings.map((f, i) => (
                  <div
                    key={i}
                    className="bg-soc-card border border-soc-border rounded-lg overflow-hidden"
                  >
                    <button
                      onClick={() => toggleFinding(i)}
                      className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-soc-border/20 transition-all duration-200"
                    >
                      <span className="text-sm font-medium text-soc-text">{f.indicator}</span>
                      {expandedFindings.has(i) ? (
                        <ChevronUp className="w-4 h-4 text-soc-muted flex-shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-soc-muted flex-shrink-0" />
                      )}
                    </button>
                    {expandedFindings.has(i) && (
                      <div className="px-4 pb-3 text-sm text-soc-muted border-t border-soc-border pt-2">
                        {f.explanation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6">
              <h2 className="text-sm font-semibold text-soc-text mb-3 uppercase tracking-wider">
                Recommendations
              </h2>
              <ul className="space-y-2">
                {result.recommendations.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-soc-text">
                    <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-soc-primary flex-shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
