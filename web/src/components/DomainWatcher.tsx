import React, { useState, useEffect } from 'react';
import { 
  Bell, 
  Plus, 
  Trash2, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Clock, 
  Loader2, 
  Globe, 
  ShieldAlert, 
  ShieldCheck 
} from 'lucide-react';
import { 
  fetchWatcherDomains, 
  addWatcherDomain, 
  deleteWatcherDomain, 
  checkWatcherDomain, 
  MonitoredDomain 
} from '../lib/api';

export const DomainWatcher: React.FC = () => {
  const [domains, setDomains] = useState<MonitoredDomain[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newInterval, setNewInterval] = useState(300);
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadDomains = async () => {
    try {
      const list = await fetchWatcherDomains();
      setDomains(Array.isArray(list) ? list : []);
    } catch (err: any) {
      console.error('Failed to load monitored domains:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDomains();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;
    setAdding(true);
    setError(null);
    try {
      const added = await addWatcherDomain(newTarget.trim(), newInterval);
      if ((added as any).error) {
        setError((added as any).error);
      } else {
        setNewTarget('');
        loadDomains();
      }
    } catch (err: any) {
      setError(err.message || 'Failed to add target to watcher');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteWatcherDomain(id);
      setDomains((prev) => prev.filter((d) => d.id !== id));
    } catch (err: any) {
      console.error('Failed to delete target:', err);
    }
  };

  const handleCheck = async (id: string) => {
    setCheckingId(id);
    try {
      const updated = await checkWatcherDomain(id);
      setDomains((prev) => prev.map((d) => (d.id === id ? updated : d)));
    } catch (err: any) {
      console.error('Failed to refresh target:', err);
    } finally {
      setCheckingId(null);
    }
  };

  const getStatusBadge = (status: string, daysRemaining: number) => {
    switch (status) {
      case 'healthy':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-800/50">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>Valid ({daysRemaining} days left)</span>
          </span>
        );
      case 'expiring_soon':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/70 text-amber-300 border border-amber-800/50 animate-pulse">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            <span>Expiring Soon ({daysRemaining} days)</span>
          </span>
        );
      case 'expired':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/70 text-rose-300 border border-rose-800/50">
            <XCircle className="w-3 h-3 text-rose-400" />
            <span>Expired Certificate</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <ShieldAlert className="w-3 h-3 text-slate-500" />
            <span>Unreachable</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Bell className="w-5 h-5 text-blue-400" />
          <span>Continuous Domain Watcher &amp; Expiry Alerter</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Monitor certificate lifespans, detect unexpected chain swaps, and trigger WebSocket alerts before production certificates expire.
        </p>
      </div>

      {/* Add Target Card */}
      <form onSubmit={handleAdd} className="p-4 rounded-xl bg-[#0b101b] border border-[#1e293b] space-y-3">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Globe className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              placeholder="e.g. api.local:443 or gateway.company.com"
              className="w-full bg-[#131d35] border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="w-full sm:w-48">
            <select
              value={newInterval}
              onChange={(e) => setNewInterval(Number(e.target.value))}
              className="w-full bg-[#131d35] border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
            >
              <option value={60}>Every 1 Minute</option>
              <option value={300}>Every 5 Minutes</option>
              <option value={900}>Every 15 Minutes</option>
              <option value={3600}>Every 1 Hour</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={adding || !newTarget.trim()}
            className="w-full sm:w-auto flex items-center justify-center space-x-2 px-5 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium transition shadow-md shadow-blue-500/20"
          >
            {adding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            <span>{adding ? 'Checking & Adding...' : 'Add Monitored Host'}</span>
          </button>
        </div>

        {error && (
          <div className="p-2.5 bg-red-950/50 border border-red-800/60 rounded text-red-300 text-xs font-mono">
            {error}
          </div>
        )}
      </form>

      {/* Domain List View */}
      {loading ? (
        <div className="flex items-center justify-center py-12 text-slate-400 font-mono text-xs space-x-2">
          <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
          <span>Loading monitored targets...</span>
        </div>
      ) : domains.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl bg-[#090d16]">
          <ShieldCheck className="w-10 h-10 text-slate-600 mx-auto mb-2" />
          <h3 className="text-sm font-mono text-slate-300">No domains currently monitored</h3>
          <p className="text-xs font-mono text-slate-500 max-w-sm mx-auto mt-1">
            Add internal services, microservices, or public endpoints to track expiration dates and handshake health.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {domains.map((d) => (
            <div
              key={d.id}
              className={`p-4 rounded-xl border bg-[#0b101b] transition space-y-3 ${
                d.status === 'expiring_soon'
                  ? 'border-amber-800/60 shadow-md shadow-amber-950/20'
                  : d.status === 'expired'
                  ? 'border-rose-800/60'
                  : 'border-[#1e293b]'
              }`}
            >
              {/* Card Header */}
              <div className="flex items-center justify-between border-b border-[#1e293b]/70 pb-2.5">
                <div className="flex items-center space-x-2 truncate">
                  <Globe className="w-4 h-4 text-blue-400 shrink-0" />
                  <span className="font-mono font-bold text-sm text-white truncate" title={d.target}>
                    {d.target}
                  </span>
                </div>
                <div className="flex items-center space-x-1.5 shrink-0">
                  <button
                    onClick={() => handleCheck(d.id)}
                    disabled={checkingId === d.id}
                    className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition"
                    title="Force immediate probe"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${checkingId === d.id ? 'animate-spin text-blue-400' : ''}`} />
                  </button>
                  <button
                    onClick={() => handleDelete(d.id)}
                    className="p-1 text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 rounded transition"
                    title="Stop monitoring"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Status Pill */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>{getStatusBadge(d.status, d.daysRemaining)}</div>
                <div className="text-[11px] font-mono text-slate-400">
                  {d.latencyMs > 0 && `${d.latencyMs.toFixed(1)} ms`}
                </div>
              </div>

              {/* Certificate Details */}
              <div className="space-y-1 text-xs font-mono bg-[#11192e]/40 p-2.5 rounded-lg border border-slate-800/50">
                <div className="flex justify-between">
                  <span className="text-slate-400">Common Name:</span>
                  <span className="text-slate-200 truncate max-w-[200px]">{d.commonName || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Issuer:</span>
                  <span className="text-slate-200 truncate max-w-[200px]">{d.issuer || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Expires At:</span>
                  <span className="text-slate-200">{d.expiresAt ? d.expiresAt.split('T')[0] : '—'}</span>
                </div>
                {d.tlsVersion && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">TLS Protocol:</span>
                    <span className="text-blue-300">{d.tlsVersion}</span>
                  </div>
                )}
                {d.lastError && (
                  <div className="text-rose-400 text-[11px] pt-1 border-t border-rose-900/40">
                    Error: {d.lastError}
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="flex flex-wrap items-center justify-between gap-1 text-[10px] font-mono text-slate-500 pt-1">
                <span>Check: Every {d.intervalSeconds / 60}m</span>
                <span>
                  Last checked: {d.lastChecked ? new Date(d.lastChecked).toLocaleTimeString() : 'Never'}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
