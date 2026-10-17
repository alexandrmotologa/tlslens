import React, { useState } from 'react';
import { 
  GitCompare, 
  ArrowLeftRight, 
  Loader2, 
  CheckCircle2, 
  AlertTriangle, 
  Zap, 
  ShieldCheck, 
  Clock, 
  Lock,
  Globe
} from 'lucide-react';
import { runDiff, DiffResult } from '../lib/api';

export const TlsDiff: React.FC = () => {
  const [targetA, setTargetA] = useState('google.com:443');
  const [targetB, setTargetB] = useState('cloudflare.com:443');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DiffResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCompare = async (a: string = targetA, b: string = targetB) => {
    if (!a.trim() || !b.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await runDiff(a.trim(), b.trim());
      if ((res as any).error) {
        setError((res as any).error);
      } else {
        setResult(res);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to execute comparative TLS diff');
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (presetA: string, presetB: string) => {
    setTargetA(presetA);
    setTargetB(presetB);
    handleCompare(presetA, presetB);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
          <GitCompare className="w-5 h-5 text-blue-400" />
          <span>Side-by-Side TLS &amp; Certificate Diff</span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Perform concurrent dual-host TLS handshakes and highlight differences in ciphers, SANs, chain depth, and stage latencies.
        </p>
      </div>

      {/* Target Controls & Presets */}
      <div className="p-4 rounded-xl bg-[#0b101b] border border-[#1e293b] space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
              Target A (Baseline)
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={targetA}
                onChange={(e) => setTargetA(e.target.value)}
                placeholder="e.g. google.com:443"
                className="w-full bg-[#131d35] border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
              Target B (Comparison)
            </label>
            <div className="relative">
              <Globe className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                value={targetB}
                onChange={(e) => setTargetB(e.target.value)}
                placeholder="e.g. cloudflare.com:443"
                className="w-full bg-[#131d35] border border-slate-700/80 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-[#1e293b]/60">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
            <span>Presets:</span>
            <button
              onClick={() => applyPreset('google.com:443', 'cloudflare.com:443')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700 transition"
            >
              Google vs Cloudflare
            </button>
            <button
              onClick={() => applyPreset('github.com:443', 'gitlab.com:443')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700 transition"
            >
              GitHub vs GitLab
            </button>
            <button
              onClick={() => applyPreset('127.0.0.1:9443', 'google.com:443')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700 transition"
            >
              Local mTLS vs Cloud
            </button>
          </div>

          <button
            onClick={() => handleCompare()}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium transition shadow-md shadow-blue-500/20"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ArrowLeftRight className="w-3.5 h-3.5" />}
            <span>{loading ? 'Probing Handshakes...' : 'Compare Endpoints'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-950/50 border border-red-800/60 rounded-lg text-red-300 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Summary Badges & Speed Delta */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Differences</span>
                <GitCompare className="w-4 h-4 text-amber-400" />
              </div>
              <p className="text-xl font-bold font-mono text-white mt-1">
                {result.totalDiffCount} <span className="text-xs font-normal text-slate-400">fields</span>
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Protocol Match</span>
                <Lock className={`w-4 h-4 ${result.protocolMatch ? 'text-emerald-400' : 'text-amber-400'}`} />
              </div>
              <p className={`text-base font-bold font-mono mt-1 ${result.protocolMatch ? 'text-emerald-400' : 'text-amber-400'}`}>
                {result.protocolMatch ? 'Identical Version' : 'Version Mismatch'}
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Cipher Match</span>
                <ShieldCheck className={`w-4 h-4 ${result.cipherMatch ? 'text-emerald-400' : 'text-blue-400'}`} />
              </div>
              <p className={`text-base font-bold font-mono mt-1 ${result.cipherMatch ? 'text-emerald-400' : 'text-blue-400'}`}>
                {result.cipherMatch ? 'Same Cipher' : 'Different Ciphers'}
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">Latency Delta</span>
                <Zap className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-sm font-bold font-mono text-white mt-1 truncate">
                {result.fasterTarget === 'equal'
                  ? 'Equal Latency'
                  : `Target ${result.fasterTarget} is ${Math.abs(result.latencyDiffMs).toFixed(1)}ms faster`}
              </p>
            </div>
          </div>

          {/* Side-by-Side Target Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Target A Card */}
            <div className="p-4 rounded-xl bg-[#0b101b] border border-[#1e293b] space-y-3">
              <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                <div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
                    Target A
                  </span>
                  <h3 className="text-sm font-bold text-white font-mono mt-1">{result.targetA}</h3>
                </div>
                <div className="text-right font-mono">
                  <div className="text-base font-bold text-blue-400">{result.probeA.totalDurationMs.toFixed(1)} ms</div>
                  <div className="text-[10px] text-slate-500">total handshake</div>
                </div>
              </div>

              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Protocol:</span>
                  <span className="text-white font-semibold">{result.probeA.tlsVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Cipher Suite:</span>
                  <span className="text-blue-300 truncate max-w-[200px]" title={result.probeA.cipher.name}>
                    {result.probeA.cipher.name}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Forward Secrecy:</span>
                  <span className={result.probeA.cipher.isPfs ? 'text-emerald-400' : 'text-slate-500'}>
                    {result.probeA.cipher.isPfs ? 'PFS Enabled' : 'No PFS'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">ALPN:</span>
                  <span className="text-slate-300">{result.probeA.alpn || 'None'}</span>
                </div>
                {result.probeA.peerCertificates.length > 0 && (
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Common Name:</span>
                    <span className="text-white truncate max-w-[200px]">
                      {result.probeA.peerCertificates[0].commonName || result.probeA.peerCertificates[0].subject}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Target B Card */}
            <div className="p-4 rounded-xl bg-[#0b101b] border border-[#1e293b] space-y-3">
              <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                <div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800">
                    Target B
                  </span>
                  <h3 className="text-sm font-bold text-white font-mono mt-1">{result.targetB}</h3>
                </div>
                <div className="text-right font-mono">
                  <div className="text-base font-bold text-indigo-400">{result.probeB.totalDurationMs.toFixed(1)} ms</div>
                  <div className="text-[10px] text-slate-500">total handshake</div>
                </div>
              </div>

              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Protocol:</span>
                  <span className="text-white font-semibold">{result.probeB.tlsVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Cipher Suite:</span>
                  <span className="text-indigo-300 truncate max-w-[200px]" title={result.probeB.cipher.name}>
                    {result.probeB.cipher.name}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">Forward Secrecy:</span>
                  <span className={result.probeB.cipher.isPfs ? 'text-emerald-400' : 'text-slate-500'}>
                    {result.probeB.cipher.isPfs ? 'PFS Enabled' : 'No PFS'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/40">
                  <span className="text-slate-400">ALPN:</span>
                  <span className="text-slate-300">{result.probeB.alpn || 'None'}</span>
                </div>
                {result.probeB.peerCertificates.length > 0 && (
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Common Name:</span>
                    <span className="text-white truncate max-w-[200px]">
                      {result.probeB.peerCertificates[0].commonName || result.probeB.peerCertificates[0].subject}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Comparative Diff Table */}
          <div className="rounded-xl border border-[#1e293b] bg-[#0b101b] overflow-hidden shadow-sm">
            <div className="p-3 bg-[#11192e] border-b border-[#1e293b] flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-200">Detailed Field Comparison</span>
              <span className="text-[11px] font-mono text-slate-400">
                {result.differences.filter((d) => d.isDifferent).length} Divergent Properties
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-[#1e293b] bg-[#090d16] text-slate-400 text-[11px] uppercase tracking-wider">
                    <th className="py-2.5 px-4 font-medium">Property</th>
                    <th className="py-2.5 px-4 font-medium">Target A</th>
                    <th className="py-2.5 px-4 font-medium">Target B</th>
                    <th className="py-2.5 px-4 font-medium text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {result.differences.map((diff, idx) => (
                    <tr
                      key={idx}
                      className={`hover:bg-[#11192e]/50 transition ${
                        diff.isDifferent ? 'bg-amber-950/10' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-slate-300 font-medium whitespace-nowrap">{diff.field}</td>
                      <td className="py-2.5 px-4 text-slate-200 max-w-xs truncate" title={diff.valueA}>
                        {diff.valueA || '—'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-200 max-w-xs truncate" title={diff.valueB}>
                        {diff.valueB || '—'}
                      </td>
                      <td className="py-2.5 px-4 text-right whitespace-nowrap">
                        {diff.isDifferent ? (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${
                              diff.significance === 'divergence'
                                ? 'bg-amber-950/60 text-amber-300 border-amber-800/50'
                                : diff.significance === 'warning'
                                ? 'bg-amber-950/60 text-amber-400 border-amber-800/50'
                                : 'bg-blue-950/60 text-blue-300 border-blue-800/50'
                            }`}
                          >
                            {diff.significance}
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                            Match
                          </span>
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
