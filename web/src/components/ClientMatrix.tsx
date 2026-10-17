import React, { useState } from 'react';
import { 
  Layers, 
  CheckCircle2, 
  XCircle, 
  Loader2, 
  Globe, 
  ShieldCheck, 
  Zap, 
  Smartphone, 
  Laptop, 
  Terminal, 
  Server
} from 'lucide-react';
import { runMatrix, MatrixReport, ClientProbeResult } from '../lib/api';

export const ClientMatrix: React.FC = () => {
  const [target, setTarget] = useState('google.com:443');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<MatrixReport | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (host: string = target) => {
    if (!host.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await runMatrix(host.trim());
      if ((res as any).error) {
        setError((res as any).error);
      } else {
        setReport(res);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to scan client compatibility matrix');
    } finally {
      setLoading(false);
    }
  };

  const categories = ['all', 'Browser', 'Mobile', 'Enterprise', 'CLI'];

  const filteredResults = report
    ? filterCategory === 'all'
      ? report.results
      : report.results.filter((r) => r.profile.category === filterCategory)
    : [];

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case 'Browser':
        return <Laptop className="w-3.5 h-3.5 text-blue-400" />;
      case 'Mobile':
        return <Smartphone className="w-3.5 h-3.5 text-emerald-400" />;
      case 'Enterprise':
        return <Server className="w-3.5 h-3.5 text-amber-400" />;
      case 'CLI':
        return <Terminal className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Layers className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
          <Layers className="w-5 h-5 text-blue-400" />
          <span>Client Compatibility &amp; Cipher Matrix</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Probe endpoint against simulated client stacks (Android, iOS, Chrome, Firefox, Java, OpenSSL) to evaluate protocol negotiation and cipher priorities.
        </p>
      </div>

      {/* Target Input & Action */}
      <div className="p-4 rounded-xl bg-[#0b101b] border border-[#1e293b] space-y-3">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Globe className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. google.com:443"
              className="w-full bg-[#131d35] border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={loading}
            className="w-full sm:w-auto flex items-center justify-center space-x-2 px-5 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium transition shadow-md shadow-blue-500/20"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Layers className="w-3.5 h-3.5" />}
            <span>{loading ? 'Running Matrix Probes...' : 'Scan Compatibility'}</span>
          </button>
        </div>

        {/* Quick Presets */}
        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 pt-1 border-t border-[#1e293b]/60">
          <span>Target Presets:</span>
          {['cloudflare.com:443', 'github.com:443', '127.0.0.1:9443'].map((p) => (
            <button
              key={p}
              onClick={() => {
                setTarget(p);
                handleScan(p);
              }}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700 transition"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-950/50 border border-red-800/60 rounded-lg text-red-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Matrix Report View */}
      {report && (
        <div className="space-y-6">
          {/* Metrics summary */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Compatible Clients</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-xl font-bold font-mono text-white mt-1">
                {report.successfulProfiles} / {report.totalProfiles}
                <span className="text-xs text-emerald-400 font-normal ml-2">
                  ({Math.round((report.successfulProfiles / report.totalProfiles) * 100)}%)
                </span>
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Incompatible / Dropped</span>
                <XCircle className="w-4 h-4 text-rose-400" />
              </div>
              <p className="text-xl font-bold font-mono text-white mt-1">
                {report.failedProfiles}
                <span className="text-xs text-slate-500 font-normal ml-2">clients</span>
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Avg Response Time</span>
                <Zap className="w-4 h-4 text-blue-400" />
              </div>
              <p className="text-xl font-bold font-mono text-white mt-1">
                {(
                  report.results.reduce((acc, curr) => acc + curr.latencyMs, 0) /
                  (report.results.length || 1)
                ).toFixed(1)}{' '}
                <span className="text-xs text-slate-400 font-normal">ms</span>
              </p>
            </div>
          </div>

          {/* Category Filter Pills */}
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Filter by Category:</span>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-3 py-1 rounded-md text-xs font-mono transition ${
                  filterCategory === cat
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-[#131d35] text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {cat === 'all' ? 'All Clients' : cat}
              </button>
            ))}
          </div>

          {/* Matrix Table */}
          <div className="rounded-xl border border-[#1e293b] bg-[#0b101b] overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[#1e293b] bg-[#090d16] text-slate-400 text-[11px] uppercase tracking-wider">
                    <th className="py-3 px-4 font-medium">Client Profile</th>
                    <th className="py-3 px-4 font-medium">Category</th>
                    <th className="py-3 px-4 font-medium">Status</th>
                    <th className="py-3 px-4 font-medium">Protocol</th>
                    <th className="py-3 px-4 font-medium">Negotiated Cipher Suite</th>
                    <th className="py-3 px-4 font-medium text-right">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {filteredResults.map((item, idx) => (
                    <tr
                      key={idx}
                      className={`hover:bg-[#11192e]/40 transition ${
                        !item.success ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white">{item.profile.name}</div>
                        <div className="text-[11px] text-slate-500 leading-tight">
                          {item.profile.description}
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className="flex items-center space-x-1.5 text-slate-300">
                          {getCategoryIcon(item.profile.category)}
                          <span>{item.profile.category}</span>
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {item.success ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            <span>Supported</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-rose-950/60 text-rose-300 border border-rose-800/40">
                            <XCircle className="w-3 h-3 text-rose-400" />
                            <span>Incompatible</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {item.success ? (
                          <span className="px-2 py-0.5 rounded text-[11px] bg-slate-800/80 text-blue-300 border border-slate-700">
                            {item.negotiatedProtocol}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {item.success ? (
                          <div>
                            <div className="text-slate-200 font-medium">{item.negotiatedCipher}</div>
                            {item.isPfs && (
                              <div className="text-[10px] text-emerald-400 flex items-center space-x-1 mt-0.5">
                                <ShieldCheck className="w-3 h-3" />
                                <span>Perfect Forward Secrecy</span>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="text-rose-400/90 text-[11px] italic">
                            {item.error || 'Handshake rejected'}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap font-mono">
                        {item.success ? (
                          <span className="text-slate-300">{item.latencyMs.toFixed(1)} ms</span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
