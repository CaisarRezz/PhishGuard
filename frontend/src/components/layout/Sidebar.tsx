import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Globe,
  QrCode,
  Mail,
  FileCode,
  ShieldAlert,
  BellRing,
  History,
  Sliders,
  Settings,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
} from 'lucide-react';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (c: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (o: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen,
}) => {
  const mainNav = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'URL Scanner', path: '/url-scanner', icon: Globe },
    { name: 'QR Shield', path: '/qr-shield', icon: QrCode },
    { name: 'MailGuard', path: '/mailguard', icon: Mail },
    { name: 'FileGuard', path: '/fileguard', icon: FileCode },
  ];

  const threatNav = [
    { name: 'Threat Watchlist', path: '/watchlist', icon: ShieldAlert },
    { name: 'Security Alerts', path: '/alerts', icon: BellRing },
    { name: 'Scan History', path: '/history', icon: History },
    { name: 'Detection Rules', path: '/rules', icon: Sliders },
  ];

  const systemNav = [
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const renderNavGroup = (title: string, items: typeof mainNav) => (
    <div className="mb-6">
      {!collapsed && (
        <h4 className="px-3 mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
          {title}
        </h4>
      )}
      <div className="space-y-1">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-semibold tracking-wide transition-all duration-200 group relative ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30 shadow-soc-glow'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border border-transparent'
                } ${collapsed ? 'justify-center px-2' : ''}`
              }
              title={collapsed ? item.name : undefined}
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-transform duration-200 group-hover:scale-110 ${
                      isActive ? 'text-sky-400' : 'text-slate-400 group-hover:text-slate-200'
                    }`}
                  />
                  {!collapsed && <span className="truncate">{item.name}</span>}
                  {isActive && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 rounded-r-full bg-sky-400" />
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden animate-in fade-in"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col bg-soc-panel border-r border-soc-border transition-all duration-300 ${
          collapsed ? 'w-20' : 'w-64'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between h-16 px-4 border-b border-soc-border">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-600 to-cyan-400 text-white shadow-soc-glow shrink-0">
              <Shield className="w-5 h-5 fill-white/20" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="text-sm font-black tracking-wider text-white uppercase font-mono">PHISHGUARD</span>
                <span className="text-[10px] text-sky-400 font-medium tracking-tight">Cybersecurity Defense</span>
              </div>
            )}
          </div>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>

          <button
            onClick={() => setMobileOpen(false)}
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 px-3 py-5 overflow-y-auto">
          {renderNavGroup('Main', mainNav)}
          {renderNavGroup('Threat Management', threatNav)}
          {renderNavGroup('System', systemNav)}
        </div>

        {/* SOC Engine Status Badge at Bottom */}
        <div className="p-3 border-t border-soc-border">
          <div
            className={`flex items-center gap-2.5 p-2 rounded-xl bg-slate-950/60 border border-soc-border ${
              collapsed ? 'justify-center' : ''
            }`}
          >
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
            </span>
            {!collapsed && (
              <div className="flex flex-col min-w-0">
                <span className="text-[11px] font-bold text-slate-200 truncate">SOC Core Active</span>
                <span className="text-[9px] text-emerald-400 font-mono uppercase">Offline Heuristic DB</span>
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
};
