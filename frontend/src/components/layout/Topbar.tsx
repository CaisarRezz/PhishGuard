import React, { useState, useEffect } from 'react';
import { Search, Bell, ShieldCheck, ShieldAlert, User, Menu, Moon } from 'lucide-react';
import { getSystemStatus } from '../../services/api';

interface TopbarProps {
  onMobileMenuClick: () => void;
  onGlobalSearch?: (query: string) => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onMobileMenuClick, onGlobalSearch }) => {
  const [systemOnline, setSystemOnline] = useState<boolean | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [notificationCount] = useState(3);

  useEffect(() => {
    let isMounted = true;
    const checkStatus = async () => {
      try {
        const data = await getSystemStatus();
        if (isMounted) setSystemOnline(data.status === 'operational');
      } catch {
        if (isMounted) setSystemOnline(false);
      }
    };
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (onGlobalSearch && searchQuery.trim()) {
      onGlobalSearch(searchQuery.trim());
    }
  };

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between h-16 px-4 sm:px-6 bg-soc-panel/90 backdrop-blur-md border-b border-soc-border">
      <div className="flex items-center gap-3">
        <button
          onClick={onMobileMenuClick}
          className="lg:hidden p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Global Search Bar */}
        <form onSubmit={handleSearchSubmit} className="relative hidden md:block w-72 lg:w-96">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search domain, URL, or hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-12 py-1.5 text-xs rounded-xl bg-slate-950/70 border border-soc-border text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all font-mono"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[9px] font-mono font-bold text-slate-500 bg-slate-800 rounded border border-slate-700">
            Ctrl K
          </kbd>
        </form>
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        {/* System Environment Pulse Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-950/70 border border-soc-border text-xs">
          {systemOnline === null ? (
            <>
              <span className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
              <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">CONNECTING...</span>
            </>
          ) : systemOnline ? (
            <>
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              <span className="text-[11px] font-mono font-bold text-emerald-400 hidden sm:inline">LIVE / SOC READY</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-[11px] font-mono font-bold text-red-400 hidden sm:inline">OFFLINE</span>
            </>
          )}
        </div>

        {/* Theme Toggle Indicator */}
        <div className="p-2 rounded-xl border border-soc-border bg-slate-950/70 text-sky-400" title="Dark SOC Theme Active">
          <Moon className="w-4 h-4" />
        </div>

        {/* Notifications */}
        <button
          className="relative p-2 rounded-xl border border-soc-border bg-slate-950/70 text-slate-400 hover:text-white hover:border-slate-700 transition-colors"
          title="Security Notifications"
        >
          <Bell className="w-4 h-4" />
          {notificationCount > 0 && (
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
          )}
        </button>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 sm:pl-3 border-l border-soc-border">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center text-white font-bold text-xs shadow-inner">
            SA
          </div>
          <div className="hidden sm:flex flex-col text-left">
            <span className="text-xs font-bold text-slate-200">SOC Analyst</span>
            <span className="text-[10px] text-slate-400 font-mono">Tier 2 Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
};
