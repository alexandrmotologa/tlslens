import React, { useState } from 'react';
import { 
  Activity, 
  Search, 
  Clock, 
  Layers, 
  ShieldCheck, 
  ShieldAlert, 
  Zap, 
  Globe, 
  Server, 
  ArrowRight,
  Loader2,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { ProbeResult, probeEndpoint } from '../lib/api';

interface HandshakeWaterfallProps {
  onSelectCertForInspection?: (certPEM: string) => void;
}

export const HandshakeWaterfall: React.FC<HandshakeWaterfallProps> = () => {
  const [target, setTarget] = useState('google.com:443');
  const [insecure, setInsecure] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProbeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    { label: 'Google', target: 'google.com:443' },
    { label: 'Cloudflare', target: 'cloudflare.com:443' },
    { label: 'GitHub', target: 'github.com:443' },
    { label: 'Local mTLS (9443)', target: '127.0.0.1:9443' },
  ];

  const handleProbe = async (targetOverride?: string) => {
    const probeTarget = targetOverride || target;
    if (!probeTarget.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await probeEndpoint(probeTarget, undefined, insecure);
      setResult(res);
      if (res.error && !res.peerCertificates?.length) {
        setError(res.error);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to probe target');
    } finally {
      setLoading(false);
    }
  };

  // Stage color scheme
  const getStageColor = (category: string) => {
    switch (category) {
      case 'dns':
        return 'from-sky-500 to-cyan-400 border-sky-400';
      case 'tcp':
        return 'from-emerald-500 to-teal-400 border-emerald-400';
      case 'tls_hello':
        return 'from-amber-500 to-yellow-400 border-amber-400';
      case 'tls_cert':
        return 'from-indigo-500 to-purple-400 border-indigo-400';
      default:
        return 'from-blue-500 to-blue-400 border-blue-400';
    }
  };

  const getStageBadge = (category: string) => {
    switch (category) {
      case 'dns':
        return 'bg-sky-950/80 text-sky-300 border-sky-800/50';
      case 'tcp':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/50';
      case 'tls_hello':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/50';
      case 'tls_cert':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-800/50';
      default:
        return 'bg-blue-950/80 text-blue-300 border-blue-800/50';
    }
  };

  return (
    <div className="space-y-6">
      {/* Target Input Card */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]/70">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Activity className="w-5 h-5 text-blue-400" />
              <span>TLS Handshake Waterfall Profiler</span>
            </h2>
            <p className="text-xs text-slate-400">
              Measure sub-millisecond network latency across TCP SYN, ClientHello, ServerHello, and Key Exchange
            </p>
          </div>

          {/* Quick presets */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 mr-1">Presets:</span>
            {presets.map((p) => (
              <button
                key={p.target}
                onClick={() => {
                  setTarget(p.target);
                  handleProbe(p.target);
                }}
                className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#11192e] hover:bg-[#1a2542] text-slate-300 border border-[#1e293b] hover:border-blue-500/40 transition-colors"
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Search Bar */}
        <div className="mt-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleProbe()}
              placeholder="e.g. google.com:443 or localhost:9443"
              className="w-full bg-[#11192e] border border-[#1e293b] rounded-md pl-9 pr-3 py-2 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
            />
          </div>

          <label className="flex items-center space-x-1.5 text-xs font-mono text-slate-400 cursor-pointer select-none px-2 py-1 bg-[#11192e] rounded border border-[#1e293b]">
            <input
              type="checkbox"
              checked={insecure}
              onChange={(e) => setInsecure(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-0"
            />
            <span>Skip Hostname Check</span>
          </label>

          <button
            onClick={() => handleProbe()}
            disabled={loading}
            className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow flex items-center justify-center space-x-1.5 transition-colors disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>Run Probe</span>
          </button>
        </div>

        {error && (
          <div className="mt-3 p-3 bg-red-950/40 border border-red-800/50 rounded-lg text-xs text-red-300 font-mono flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Profiler Output Results */}
      {result && (
        <div className="space-y-6">
          {/* Top Summary Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">TOTAL LATENCY</div>
              <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">
                {result.totalDurationMs.toFixed(2)} <span className="text-xs text-slate-400 font-normal">ms</span>
              </div>
            </div>

            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">TLS VERSION</div>
              <div className="text-base font-bold text-white font-mono mt-0.5 flex items-center space-x-1">
                <span>{result.tlsVersion || 'Unknown'}</span>
                {result.tlsVersion === 'TLS 1.3' && (
                  <span className="text-[10px] px-1 py-0.2 bg-emerald-950 text-emerald-300 rounded border border-emerald-800">
                    1-RTT
                  </span>
                )}
              </div>
            </div>

            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">ALPN PROTOCOL</div>
              <div className="text-base font-bold text-blue-400 font-mono mt-0.5">
                {result.alpn || 'None'}
              </div>
            </div>

            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">RESOLVED IP</div>
              <div className="text-xs font-bold text-slate-200 font-mono mt-1 break-all">
                {result.resolvedIp}:{result.port}
              </div>
            </div>

            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">FORWARD SECRECY</div>
              <div className="text-xs font-bold text-white font-mono mt-1 flex items-center space-x-1">
                {result.cipher.isPfs ? (
                  <span className="text-emerald-400 flex items-center space-x-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>PFS Active</span>
                  </span>
                ) : (
                  <span className="text-amber-400 flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>No PFS</span>
                  </span>
                )}
              </div>
            </div>

            <div className="bg-[#0c1222] border border-[#1e293b] p-3 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400">OCSP STAPLING</div>
              <div className="text-xs font-bold font-mono mt-1">
                {result.ocspStapled ? (
                  <span className="text-emerald-400">Stapled</span>
                ) : (
                  <span className="text-slate-400">Not Stapled</span>
                )}
              </div>
            </div>
          </div>

          {/* Negotiated Cipher Banner */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded bg-indigo-950/80 border border-indigo-800/40 text-indigo-400">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <div className="text-xs font-mono text-slate-400">NEGOTIATED CIPHER SUITE</div>
                <div className="text-sm font-bold text-white font-mono mt-0.5">
                  {result.cipher.name} <span className="text-xs text-indigo-400 font-normal">({result.cipher.hex})</span>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Key Exchange: {result.cipher.keyExchange}
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Encryption: {result.cipher.encryption}
              </span>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                result.cipher.securityStatus === 'recommended' || result.cipher.securityStatus === 'secure'
                  ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/50'
                  : 'bg-amber-950/70 text-amber-300 border-amber-800/50'
              }`}>
                {result.cipher.securityStatus}
              </span>
            </div>
          </div>

          {/* Gantt Waterfall Visualizer */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-6 shadow-sm space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-[#1e293b]/70">
              <div>
                <h3 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                  Handshake Timeline Waterfall
                </h3>
                <p className="text-xs text-slate-400">Cumulative record delivery and packet processing progression</p>
              </div>

              <div className="text-xs font-mono text-slate-400">
                Total: <span className="text-white font-semibold">{result.totalDurationMs.toFixed(2)} ms</span>
              </div>
            </div>

            {/* Stages Stack */}
            <div className="space-y-4">
              {result.timings.map((stage, idx) => {
                const total = Math.max(result.totalDurationMs, 0.1);
                const offsetPct = (stage.startOffsetMs / total) * 100;
                const widthPct = Math.max((stage.durationMs / total) * 100, 2);

                return (
                  <div key={idx} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${getStageBadge(stage.category)}`}>
                          {stage.category.toUpperCase()}
                        </span>
                        <span className="text-slate-200 font-medium">{stage.name}</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <span className="text-slate-500 text-[11px] hidden sm:inline">{stage.description}</span>
                        <span className="text-white font-bold">{stage.durationMs.toFixed(2)} ms</span>
                      </div>
                    </div>

                    {/* Timeline Bar Track */}
                    <div className="h-6 w-full bg-[#11192e] rounded-md overflow-hidden relative border border-[#1e293b]/50">
                      {/* Grid tick marks */}
                      <div className="absolute inset-0 flex justify-between px-2 pointer-events-none opacity-20">
                        <span className="border-r border-slate-500 h-full" />
                        <span className="border-r border-slate-500 h-full" />
                        <span className="border-r border-slate-500 h-full" />
                        <span className="border-r border-slate-500 h-full" />
                      </div>

                      {/* Bar */}
                      <div
                        className={`absolute top-0 bottom-0 rounded-sm bg-gradient-to-r border ${getStageColor(stage.category)} shadow-sm transition-all`}
                        style={{
                          left: `${offsetPct}%`,
                          width: `${widthPct}%`,
                        }}
                      >
                        <span className="absolute inset-y-0 right-1.5 flex items-center text-[10px] font-mono font-bold text-white drop-shadow">
                          {stage.durationMs > 3 ? `${stage.durationMs.toFixed(1)}ms` : ''}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Scale legend */}
            <div className="flex justify-between text-[10px] font-mono text-slate-500 pt-2 border-t border-[#1e293b]/50">
              <span>0 ms</span>
              <span>{(result.totalDurationMs * 0.25).toFixed(1)} ms</span>
              <span>{(result.totalDurationMs * 0.5).toFixed(1)} ms</span>
              <span>{(result.totalDurationMs * 0.75).toFixed(1)} ms</span>
              <span>{result.totalDurationMs.toFixed(1)} ms</span>
            </div>
          </div>

          {/* Peer Certificate Chain Summary Cards */}
          {result.peerCertificates && result.peerCertificates.length > 0 && (
            <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
              <h3 className="text-sm font-semibold text-white font-mono uppercase tracking-wider flex items-center space-x-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <span>Presented Peer Certificates ({result.peerCertificates.length})</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {result.peerCertificates.map((cert, i) => {
                  const isLeaf = i === 0;
                  const isRoot = cert.isCA && i === result.peerCertificates.length - 1;

                  return (
                    <div
                      key={i}
                      className={`p-3.5 rounded-lg border transition-all ${
                        isLeaf
                          ? 'bg-[#11192e] border-blue-500/40 shadow-sm'
                          : 'bg-[#0f172a]/70 border-[#1e293b]'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          isLeaf 
                            ? 'bg-blue-950 text-blue-300 border border-blue-800' 
                            : isRoot 
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-purple-950 text-purple-300 border border-purple-800'
                        }`}>
                          {isLeaf ? 'Leaf Certificate' : isRoot ? 'Root CA' : 'Intermediate'}
                        </span>

                        <span className={`text-xs font-mono ${cert.isExpired ? 'text-red-400' : 'text-slate-400'}`}>
                          {cert.daysRemaining}d left
                        </span>
                      </div>

                      <div className="text-sm font-bold text-white font-mono truncate" title={cert.commonName}>
                        {cert.commonName || 'Unnamed Cert'}
                      </div>

                      <div className="text-xs text-slate-400 font-mono mt-1 truncate" title={cert.issuer}>
                        Issuer: {cert.issuer}
                      </div>

                      <div className="mt-2 text-[11px] font-mono text-slate-400 flex items-center justify-between pt-2 border-t border-[#1e293b]/50">
                        <span>{cert.keyType} ({cert.keyLength}b)</span>
                        <span className="text-slate-500">Exp: {new Date(cert.notAfter).toLocaleDateString()}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
