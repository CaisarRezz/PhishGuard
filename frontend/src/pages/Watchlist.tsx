import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldOff, Plus, Search, Trash2 } from 'lucide-react';
import { getWatchlist, addWatchlistEntry, deleteWatchlistEntry, getErrorMessage } from '../services/api';
import type { WatchlistEntry } from '../types/api';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { useToast } from '../components/common/Toast';

const CATEGORIES = ['Phishing', 'Malware', 'Scam', 'Spam', 'C2', 'Other'] as const;

function categoryBadge(cat: string): string {
  switch (cat?.toLowerCase()) {
    case 'malware': return 'bg-red-500/20 text-red-400 border border-red-500/30';
    case 'phishing': return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
    case 'scam': return 'bg-orange-500/20 text-orange-400 border border-orange-500/30';
    case 'spam': return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
    case 'c2': return 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
    default: return 'bg-soc-card text-soc-muted border border-soc-border';
  }
}

export const Watchlist: React.FC = () => {
  const [entries, setEntries] = useState<WatchlistEntry[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<WatchlistEntry | null>(null);
  const [addLoading, setAddLoading] = useState(false);

  // Add form state
  const [target, setTarget] = useState('');
  const [category, setCategory] = useState<string>('Phishing');
  const [description, setDescription] = useState('');
  const [source, setSource] = useState('');

  const { addToast } = useToast();
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchEntries = useCallback(async (q?: string) => {
    setLoading(true);
    try {
      const data = await getWatchlist(q);
      setEntries(data as WatchlistEntry[]);
    } catch (err) {
      addToast(getErrorMessage(err), 'error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchEntries();
  }, [fetchEntries]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchEntries(search || undefined), 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [search, fetchEntries]);

  const handleAdd = async () => {
    if (!target.trim()) return;
    setAddLoading(true);
    try {
      await addWatchlistEntry({ target, threat_category: category, description, source });
      addToast('Entry added to watchlist', 'success');
      setShowAddModal(false);
      setTarget(''); setCategory('Phishing'); setDescription(''); setSource('');
      fetchEntries(search || undefined);
    } catch (err: unknown) {
      const msg = getErrorMessage(err);
      if (msg.includes('409') || msg.toLowerCase().includes('already exists') || msg.includes('conflict')) {
        addToast('Entry already exists in watchlist', 'error');
      } else {
        addToast(msg, 'error');
      }
    } finally {
      setAddLoading(false);
    }
  };

  const handleDelete = async (entry: WatchlistEntry) => {
    try {
      await deleteWatchlistEntry(entry.id);
      addToast('Entry removed from watchlist', 'success');
      fetchEntries(search || undefined);
    } catch (err) {
      addToast(getErrorMessage(err), 'error');
    } finally {
      setConfirmDelete(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-soc-text flex items-center gap-3">
            <span className="p-2 bg-soc-primary/20 rounded-lg">
              <ShieldOff className="w-6 h-6 text-soc-primary" />
            </span>
            Threat Watchlist
            <span className="ml-1 px-2 py-0.5 bg-soc-card border border-soc-border rounded-full text-sm text-soc-muted font-normal">
              {entries.length}
            </span>
          </h1>
          <p className="text-soc-muted mt-1 ml-11">Monitored threat indicators</p>
        </div>
      </div>

      {/* Action Bar */}
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-soc-muted" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search targets, categories..."
            className="w-full bg-soc-panel/80 border border-soc-border rounded-lg pl-9 pr-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200"
          />
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 bg-soc-primary hover:bg-sky-400 text-white px-4 py-2 rounded-lg font-medium transition-all duration-200"
        >
          <Plus className="w-4 h-4" />
          Add Entry
        </button>
      </div>

      {/* Table */}
      <div className="bg-soc-panel/80 border border-soc-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-soc-muted">Loading...</div>
        ) : entries.length === 0 ? (
          <EmptyState
            title="No watchlist entries"
            description="Add domains, URLs, or hashes to monitor for threats."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-soc-muted text-xs uppercase tracking-wider">
                  <th className="text-left px-4 py-3">Target</th>
                  <th className="text-left px-4 py-3">Category</th>
                  <th className="text-left px-4 py-3 hidden md:table-cell">Description</th>
                  <th className="text-left px-4 py-3 hidden lg:table-cell">Source</th>
                  <th className="text-left px-4 py-3 hidden sm:table-cell">Date Added</th>
                  <th className="text-left px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map(entry => (
                  <tr key={entry.id} className="border-b border-soc-border/50 hover:bg-soc-card/50 transition-all duration-200">
                    <td className="px-4 py-3 font-mono text-soc-text max-w-[180px] truncate">{entry.target}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${categoryBadge(entry.threat_category)}`}>
                        {entry.threat_category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-soc-muted max-w-[200px] truncate hidden md:table-cell">
                      {entry.description || '—'}
                    </td>
                    <td className="px-4 py-3 text-soc-muted hidden lg:table-cell">{entry.source || '—'}</td>
                    <td className="px-4 py-3 text-soc-muted text-xs hidden sm:table-cell">
                      {new Date(entry.date_added).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setConfirmDelete(entry)}
                        className="p-1.5 text-soc-muted hover:text-soc-danger transition-all duration-200 rounded"
                        title="Delete entry"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Modal */}
      <Modal isOpen={showAddModal} onClose={() => setShowAddModal(false)} title="Add Watchlist Entry">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">
              Target URL / Domain <span className="text-soc-danger">*</span>
            </label>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="example.com or https://..."
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">Threat Category</label>
            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text focus:outline-none focus:border-soc-primary transition-all duration-200"
            >
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">
              Description <span className="text-soc-muted font-normal">(optional)</span>
            </label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Brief description of the threat..."
              rows={3}
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200 resize-none"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-soc-text mb-1.5">
              Source <span className="text-soc-muted font-normal">(optional)</span>
            </label>
            <input
              type="text"
              value={source}
              onChange={e => setSource(e.target.value)}
              placeholder="e.g. VirusTotal, manual"
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-soc-text placeholder-soc-muted focus:outline-none focus:border-soc-primary transition-all duration-200"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button
              onClick={() => setShowAddModal(false)}
              className="px-4 py-2 text-soc-muted hover:text-soc-text transition-all duration-200"
            >
              Cancel
            </button>
            <button
              onClick={handleAdd}
              disabled={!target.trim() || addLoading}
              className="bg-soc-primary hover:bg-sky-400 disabled:opacity-50 disabled:cursor-not-allowed text-white px-4 py-2 rounded-lg font-medium transition-all duration-200"
            >
              {addLoading ? 'Adding...' : 'Add Entry'}
            </button>
          </div>
        </div>
      </Modal>

      {/* Confirm Delete */}
      <ConfirmDialog
        isOpen={confirmDelete !== null}
        title="Delete Watchlist Entry"
        message={`Remove "${confirmDelete?.target}" from the watchlist?`}
        confirmLabel="Delete"
        onConfirm={() => confirmDelete && handleDelete(confirmDelete)}
        onCancel={() => setConfirmDelete(null)}
        danger
      />
    </div>
  );
};
