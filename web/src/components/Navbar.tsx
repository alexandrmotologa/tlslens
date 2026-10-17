import React, { useState } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  GitBranch, 
  Lock, 
  Terminal, 
  FileCode, 
  CheckCircle2, 
  Loader2,
  RefreshCw,
  GitCompare,
  Layers,
  Bell,
  Network
} from 'lucide-react';
import { CACredentialsInfo, trustCA, untrustCA } from '../lib/api';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  caInfo?: CACredentialsInfo;
  caInitialized: boolean;
  onRefreshCA: () => void;
  wsConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  caInfo,
  caInitialized,
  onRefreshCA,
  wsConnected,
}) => {
  const [loadingTrust, setLoadingTrust] = useState(false);
  const [trustMessage, setTrustMessage] = useState<string | null>(null);

  const handleToggleTrust = async () => {
    if (!caInitialized) return;
    setLoadingTrust(true);
    setTrustMessage(null);
    try {
      if (caInfo?.isTrustedByOS) {
        const res = await untrustCA();
        setTrustMessage(res.message);
      } else {
        const res = await trustCA();
        setTrustMessage(res.message);
      }
      onRefreshCA();
    } catch (err: any) {
      setTrustMessage(err.message || 'Action failed');
    } finally {
      setLoadingTrust(false);
      setTimeout(() => setTrustMessage(null), 4000);
    }
  };

  const navItems = [
    { id: 'ca', label: 'CA Studio', icon: Shield },
    { id: 'handshake', label: 'Handshake Waterfall', icon: Activity },
    { id: 'chain', label: 'Certificate Chain & Linter', icon: GitBranch },
    { id: 'diff', label: 'TLS Diff', icon: GitCompare },
    { id: 'matrix', label: 'Client Matrix', icon: Layers },
    { id: 'mtls', label: 'mTLS Playground', icon: Lock },
    { id: 'audit', label: 'Security Audit', icon: Terminal },
    { id: 'configs', label: 'Configs & K8s', icon: FileCode },
    { id: 'watcher', label: 'Domain Watcher', icon: Bell },
    { id: 'acme', label: 'ACME Server', icon: Network },
  ];

  return (
    <header className="border-b border-[#1e293b] bg-[#090d16]/95 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Tier 1: Top Brand & Utility Header */}
        <div className="flex items-center justify-between h-14 border-b border-[#1e293b]/50">
          {/* Brand */}
          <div className="flex items-center space-x-3">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-md shadow-blue-500/20 border border-blue-400/30 shrink-0">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-base font-bold tracking-tight text-white font-mono">TLSLens</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/40 font-semibold">
                v1.1
              </span>
              <div className="flex items-center space-x-1.5 pl-1.5 border-l border-slate-800">
                <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-amber-500 animate-pulse'}`} />
                <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                  {wsConnected ? 'Live Telemetry' : 'Connecting'}
                </span>
              </div>
              <span className="text-slate-600 hidden md:inline">·</span>
              <span className="text-[11px] text-slate-400 font-mono hidden md:inline">
                PKI &amp; TLS Handshake Inspector
              </span>
            </div>
          </div>

          {/* Right Action: OS Trust Store Status Pill & Refresh */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {caInitialized ? (
              <div className="flex items-center space-x-2">
                <div className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono border transition-colors ${
                  caInfo?.isTrustedByOS 
                    ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40' 
                    : 'bg-amber-950/60 text-amber-300 border-amber-800/40'
                }`}>
                  {caInfo?.isTrustedByOS ? (
                    <>
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="hidden sm:inline">OS Trusted</span>
                      <span className="sm:hidden">Trusted</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      <span className="hidden sm:inline">Not In OS Store</span>
                      <span className="sm:hidden">Not Trusted</span>
                    </>
                  )}
                </div>

                <button
                  onClick={handleToggleTrust}
                  disabled={loadingTrust}
                  className={`text-xs px-2.5 py-1 rounded-md font-mono border transition-all flex items-center space-x-1 ${
                    caInfo?.isTrustedByOS
                      ? 'bg-slate-800/70 hover:bg-red-950/50 text-slate-300 hover:text-red-300 border-slate-700/60 hover:border-red-800/50'
                      : 'bg-blue-600 hover:bg-blue-500 text-white border-blue-500 shadow-sm shadow-blue-500/20'
                  }`}
                  title={caInfo?.isTrustedByOS ? "Remove from OS root store" : "Install into OS root store"}
                >
                  {loadingTrust ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : caInfo?.isTrustedByOS ? (
                    <span>Untrust</span>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3 h-3" />
                      <span>Trust CA</span>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <button
                onClick={() => setActiveTab('ca')}
                className="text-xs px-3 py-1 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-mono transition-colors shadow-sm"
              >
                + Init Root CA
              </button>
            )}

            <button
              onClick={onRefreshCA}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-[#131d35] rounded-md transition-colors"
              title="Refresh state"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Tier 2: Full-Width Studio Subnav Tabs */}
        <div className="flex items-center overflow-x-auto space-x-1.5 py-2 scrollbar-none -mx-4 px-4 sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all whitespace-nowrap shrink-0 ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 shadow-sm shadow-blue-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131d35]/60 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                <span className="whitespace-nowrap">{item.label}</span>
              </button>
            );
          })}
        </div>

        {/* Trust Toast Notification */}
        {trustMessage && (
          <div className="py-1 px-3 bg-blue-950/90 border border-blue-800 text-blue-300 text-xs font-mono rounded my-1 flex items-center justify-between animate-fadeIn">
            <span>{trustMessage}</span>
            <button onClick={() => setTrustMessage(null)} className="text-blue-400 hover:text-white ml-2">×</button>
          </div>
        )}
      </div>
    </header>
  );
};
