import React, { useState, useRef, useCallback } from 'react';
import {
  QrCode,
  Upload,
  ImageIcon,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Link,
  FileImage,
  ScanLine,
  Shield,
} from 'lucide-react';
import { scanQrCode, getErrorMessage } from '../services/api';
import { QrScanResult } from '../types/api';
import { RiskBadge } from '../components/common/RiskBadge';
import { LoadingState } from '../components/common/LoadingState';
import { useToast } from '../components/common/Toast';

export const QrShield: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QrScanResult | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { error, success, warning } = useToast();

  const handleFile = (f: File) => {
    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/bmp'];
    if (!allowedTypes.includes(f.type)) {
      error('Invalid File Type', 'Only PNG, JPG, JPEG, WEBP, and BMP images are supported.');
      return;
    }
    if (f.size > 5 * 1024 * 1024) {
      error('File Too Large', 'QR code image must be smaller than 5 MB.');
      return;
    }
    setFile(f);
    setResult(null);
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target?.result as string);
    reader.readAsDataURL(f);
  };

  const onDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) handleFile(dropped);
  }, []);

  const handleScan = async () => {
    if (!file) return;
    setLoading(true);
    try {
      const data = await scanQrCode(file);
      setResult(data);
      if (data.risk_level === 'High') {
        warning('High Risk QR Content Detected', `Risk score: ${data.risk_score}/100 — do not open this link.`);
      } else {
        success('QR Code Decoded Successfully', data.decoded ? `Content: ${data.content.substring(0, 50)}` : 'No QR pattern found.');
      }
    } catch (err) {
      error('QR Scan Failed', getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <QrCode className="w-6 h-6 text-sky-400" />
          <h1 className="text-2xl font-black text-white tracking-tight">QR SHIELD</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Upload a QR code image to decode its payload and analyze embedded URLs for threats. QR content is never automatically opened.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Panel */}
        <div className="rounded-2xl border border-soc-border bg-soc-panel p-6 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white">Upload QR Code Image</h3>
            <span className="text-[11px] text-slate-400 font-mono">Max 5 MB · PNG, JPG, WEBP, BMP</span>
          </div>

          {/* Drop Zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={onDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`relative flex flex-col items-center justify-center gap-3 p-8 rounded-xl border-2 border-dashed cursor-pointer transition-all duration-200 min-h-[200px] ${
              isDragging
                ? 'border-sky-400 bg-sky-500/10 shadow-soc-glow'
                : file
                ? 'border-emerald-500/50 bg-emerald-500/5'
                : 'border-soc-border hover:border-sky-500/50 hover:bg-sky-500/5'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/bmp"
              className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
            />

            {preview ? (
              <img
                src={preview}
                alt="QR Preview"
                className="max-h-40 max-w-full rounded-lg border border-soc-border object-contain shadow-lg"
              />
            ) : (
              <>
                <div className="p-4 rounded-2xl bg-slate-900/80 border border-soc-border text-sky-400">
                  <Upload className="w-8 h-8" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-semibold text-slate-200">Drop QR code image here</p>
                  <p className="text-xs text-slate-400 mt-0.5">or click to select file from disk</p>
                </div>
              </>
            )}
          </div>

          {/* File Info */}
          {file && (
            <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-950/70 border border-soc-border">
              <FileImage className="w-5 h-5 text-sky-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-slate-200 truncate font-mono">{file.name}</p>
                <p className="text-[11px] text-slate-400 font-mono">{(file.size / 1024).toFixed(1)} KB · {file.type}</p>
              </div>
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={handleScan}
              disabled={!file || loading}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-40 text-white font-bold text-xs uppercase tracking-wider shadow-soc-glow transition-all"
            >
              <ScanLine className="w-4 h-4" />
              {loading ? 'Scanning...' : 'Scan QR Code'}
            </button>
            <button
              onClick={reset}
              className="px-4 py-3 rounded-xl border border-soc-border bg-slate-900 text-slate-400 hover:text-white hover:bg-slate-800 text-xs font-semibold transition-colors"
            >
              Reset
            </button>
          </div>
        </div>

        {/* Result Panel */}
        <div className="rounded-2xl border border-soc-border bg-soc-panel p-6 flex flex-col">
          <h3 className="text-sm font-bold text-white mb-4">Scan Analysis Report</h3>

          {loading ? (
            <LoadingState message="Decoding QR Payload..." submessage="Running OpenCV QRCodeDetector and URL heuristics" />
          ) : !result ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center gap-3 py-10">
              <div className="p-4 rounded-2xl bg-slate-900/80 border border-soc-border">
                <QrCode className="w-9 h-9 text-slate-500" />
              </div>
              <p className="text-xs text-slate-500 font-mono">Upload a QR code image to begin analysis</p>
            </div>
          ) : (
            <div className="space-y-4 animate-in fade-in duration-300">
              {/* Decode Status + Risk */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950/80 border border-soc-border">
                <div className="flex items-center gap-2">
                  {result.decoded ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <div>
                    <span className="text-xs font-bold text-slate-200">
                      {result.decoded ? 'QR Code Decoded Successfully' : 'QR Pattern Not Detected'}
                    </span>
                    <p className="text-[11px] text-slate-400 font-mono">{result.filename} · {(result.file_size / 1024).toFixed(1)} KB</p>
                  </div>
                </div>
                <RiskBadge level={result.risk_level} size="md" />
              </div>

              {/* Decoded Content */}
              {result.decoded && (
                <div className="space-y-2">
                  <label className="text-[11px] font-bold uppercase text-slate-400 font-mono">Decoded Payload</label>
                  <div className="p-3 rounded-xl bg-slate-950 border border-soc-border font-mono text-xs text-slate-200 break-all">
                    {result.content}
                  </div>
                  <div className="flex items-center gap-2 text-[11px]">
                    <span className="text-slate-400 font-mono">Content Type:</span>
                    <span className={`font-bold ${result.is_url ? 'text-sky-400' : 'text-slate-300'}`}>
                      {result.is_url ? '🔗 URL / Hyperlink' : '📝 Plain Text / Non-URL'}
                    </span>
                  </div>
                </div>
              )}

              {/* Risk Score */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950/80 border border-soc-border">
                <span className="text-xs font-mono text-slate-400">Threat Score:</span>
                <span className={`text-sm font-black font-mono ${
                  result.risk_score >= 60 ? 'text-red-400' : result.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {result.risk_score} / 100
                </span>
              </div>

              {/* WARNING — Do not open */}
              {result.is_url && result.risk_score >= 30 && (
                <div className="flex items-start gap-2.5 p-3.5 rounded-xl bg-amber-950/60 border border-amber-500/40">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="text-xs">
                    <p className="font-bold text-amber-200">Do Not Open This Link</p>
                    <p className="text-amber-300 mt-0.5">This QR code encodes a URL with risk indicators. Visiting it could expose you to phishing or malware.</p>
                  </div>
                </div>
              )}

              {/* Recommendation */}
              <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60">
                <p className="text-[11px] font-bold text-slate-400 uppercase font-mono flex items-center gap-1 mb-1">
                  <Shield className="w-3 h-3 text-sky-400" />
                  Security Recommendation
                </p>
                <p className="text-xs text-slate-200 leading-relaxed">{result.recommendation}</p>
              </div>

              {/* Detection Indicators */}
              {result.findings && result.findings.length > 0 && (
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-400 font-mono block mb-2">Detection Indicators</label>
                  <div className="space-y-1.5">
                    {result.findings.filter(f => f.points > 0).map((f, i) => (
                      <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-red-950/40 border border-red-800/30">
                        <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                        <div className="text-xs">
                          <span className="font-semibold text-red-200">{f.label}</span>
                          <span className="text-red-300/80 ml-2 text-[11px]">{f.detail}</span>
                        </div>
                      </div>
                    ))}
                    {result.findings.filter(f => f.points === 0 && f.status !== 'Indikator ditemukan').slice(0, 2).map((f, i) => (
                      <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/20">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                        <span className="text-xs text-emerald-400/80">{f.label} — Not Detected</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
