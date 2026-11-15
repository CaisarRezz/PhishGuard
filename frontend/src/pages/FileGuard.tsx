import React, { useState, useRef, useCallback } from 'react';
import { FileCode, Upload, Copy, Check, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';
import { scanFile, getErrorMessage } from '../services/api';
import type { FileScanResult } from '../types/api';
import { LoadingState } from '../components/common/LoadingState';
import { useToast } from '../components/common/Toast';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const FileGuard: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<FileScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addToast } = useToast();

  const MAX_SIZE = 10 * 1024 * 1024; // 10 MB

  const handleFile = (f: File) => {
    if (f.size > MAX_SIZE) {
      addToast('File exceeds 10 MB limit', 'error');
      return;
    }
    setFile(f);
    setResult(null);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, []);

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const onDragLeave = () => setDragOver(false);

  const handleScan = async () => {
    if (!file) return;
    setLoading(true);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await scanFile(formData);
      setResult(data as FileScanResult);
    } catch (err) {
      addToast(getErrorMessage(err), 'error');
    } finally {
      setLoading(false);
    }
  };

  const copyHash = async (hash: string) => {
    await navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-soc-text flex items-center gap-3">
          <span className="p-2 bg-soc-primary/20 rounded-lg">
            <FileCode className="w-6 h-6 text-soc-primary" />
          </span>
          FileGuard
        </h1>
        <p className="text-soc-muted mt-1">SHA-256 File Reputation Scanner</p>
      </div>

      {/* Security Notice */}
      <div className="flex items-start gap-3 bg-soc-danger/10 border border-soc-danger/30 rounded-xl p-4">
        <ShieldAlert className="w-5 h-5 text-soc-danger flex-shrink-0 mt-0.5" />
        <p className="text-red-300 text-sm font-medium">
          Files are never executed. Only the SHA-256 hash is checked.
        </p>
      </div>

      {/* Upload Area */}
      <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6 space-y-4">
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
        />
        <div
          onClick={() => fileInputRef.current?.click()}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center cursor-pointer transition-all duration-200 ${
            dragOver
              ? 'border-soc-primary bg-soc-primary/10'
              : 'border-soc-border hover:border-soc-primary/50 hover:bg-soc-card'
          }`}
        >
          <Upload className={`w-10 h-10 mb-3 ${dragOver ? 'text-soc-primary' : 'text-soc-muted'}`} />
          <p className="text-soc-text font-medium">Drop any file here or click to browse</p>
          <p className="text-soc-muted text-sm mt-1">Maximum file size: 10 MB</p>
        </div>

        {/* Selected File */}
        {file && (
          <div className="flex items-center gap-3 bg-soc-card border border-soc-border rounded-lg px-4 py-3">
            <FileCode className="w-5 h-5 text-soc-primary flex-shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="text-soc-text text-sm font-medium truncate">{file.name}</p>
              <p className="text-soc-muted text-xs">{formatBytes(file.size)}</p>
            </div>
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={!file || loading}
          className="w-full bg-soc-primary hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2.5 rounded-lg font-medium transition-all duration-200"
        >
          {loading ? 'Scanning...' : 'Scan File'}
        </button>
      </div>

      {/* Loading */}
      {loading && <LoadingState message="Computing SHA-256 hash and checking reputation..." />}

      {/* Results */}
      {result && !loading && (
        <div className="bg-soc-panel/80 border border-soc-border rounded-xl p-6 space-y-5">
          <h2 className="text-sm font-semibold text-soc-text uppercase tracking-wider">Scan Results</h2>

          {/* File Info */}
          <div className="space-y-3">
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted text-sm">File Name</span>
              <span className="font-mono text-soc-text text-sm">{result.filename}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted text-sm">File Size</span>
              <span className="font-mono text-soc-text text-sm">{formatBytes(result.file_size)}</span>
            </div>
            <div className="flex justify-between items-start py-2 border-b border-soc-border gap-4">
              <span className="text-soc-muted text-sm flex-shrink-0">SHA-256</span>
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-mono text-soc-text text-xs truncate max-w-[260px]" title={result.sha256}>
                  {result.sha256}
                </span>
                <button
                  onClick={() => copyHash(result.sha256)}
                  className="flex-shrink-0 p-1 hover:text-soc-primary text-soc-muted transition-all duration-200"
                  title="Copy hash"
                >
                  {copied ? <Check className="w-4 h-4 text-soc-success" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-soc-border">
              <span className="text-soc-muted text-sm">Scan Time</span>
              <span className="text-soc-text text-sm">{new Date(result.scan_timestamp).toLocaleString()}</span>
            </div>
          </div>

          {/* Reputation */}
          {result.threat_found ? (
            <div className="bg-soc-danger/10 border border-soc-danger/30 rounded-xl p-5 space-y-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-soc-danger" />
                <span className="font-bold text-soc-danger tracking-wide">MALICIOUS DETECTED</span>
              </div>
              {result.threat_details && (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-soc-muted">Threat Name</span>
                    <span className="text-soc-text font-medium">{result.threat_details.threat_name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-muted">Description</span>
                    <span className="text-soc-text max-w-[60%] text-right">{result.threat_details.description}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-muted">Source</span>
                    <span className="text-soc-text">{result.threat_details.source}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-muted">Date Added</span>
                    <span className="text-soc-text">{result.threat_details.date_added}</span>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-soc-success/10 border border-soc-success/30 rounded-xl p-5 space-y-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-soc-success" />
                <span className="font-bold text-soc-success tracking-wide">NOT IN LOCAL DATABASE</span>
              </div>
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                <p className="text-soc-muted text-sm">
                  Hash not found in local signature database. This does not guarantee the file is safe.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
