import React, { useState } from 'react';
import { 
  Terminal, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  Cpu, 
  Lock, 
  Clock, 
  Loader2,
  ExternalLink
} from 'lucide-react';
import { AuditResult, runSecurityAudit } from '../lib/api';

export const SecurityAudit: React.FC = () => {
  const [target, setTarget] = useState('google.com:443');
  const [loading, setLoading] = useState(false);
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    { label: 'Google', target: 'google.com:443' },
    { label: 'Cloudflare', target: 'cloudflare.com:443' },
    { label: 'GitHub', target: 'github.com:443' },
    { label: 'Local Server', target: '127.0.0.1:9443' },
  ];

  const handleAudit = async (targetOverride?: string) => {
    const auditTarget = targetOverride || target;
    if (!auditTarget.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await runSecurityAudit(auditTarget);
      setAuditResult(res);
    } catch (err: any) {
      setError(err.message || 'Security audit failed');
    } finally {
      setLoading(false);
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-emerald-400 bg-emerald-950/70 border-emerald-800';
      case 'B':
        return 'text-blue-400 bg-blue-950/70 border-blue-800';
      case 'C':
        return 'text-amber-400 bg-amber-950/70 border-amber-800';
      case 'F':
      default:
        return 'text-red-400 bg-red-950/70 border-red-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]/70">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Terminal className="w-5 h-5 text-indigo-400" />
              <span>TLS Security &amp; Cipher Strength Auditor</span>
            </h2>
            <p className="text-xs text-slate-400">
              Evaluates cryptographic posture, deprecation risks, and calculates an overall security grade (A+ to F)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 mr-1">Presets:</span>
            {presets.map((p) => (
              <button
                key={p.target}
                onClick={() => {
                  setTarget(p.target);
                  handleAudit(p.target);
                }}
                className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#11192e] hover:bg-[#1a2542] text-slate-300 border border-[#1e293b] transition-colors"
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAudit()}
            placeholder="e.g. cloudflare.com:443"
            className="flex-1 bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-2 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
          />
          <button
            onClick={() => handleAudit()}
            disabled={loading}
            className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow flex items-center justify-center space-x-2 transition-colors disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>Run Audit</span>
          </button>
        </div>

        {error && (
          <div className="mt-3 p-3 bg-red-950/40 border border-red-800/50 rounded-lg text-xs text-red-300 font-mono flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Audit Report */}
      {auditResult && (
        <div className="space-y-6">
          {/* Top Score Banner */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-6 shadow-sm flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center space-x-5">
              <div className={`w-20 h-20 rounded-2xl border-2 flex items-center justify-center text-3xl font-extrabold font-mono shadow-lg ${getGradeColor(auditResult.grade)}`}>
                {auditResult.grade}
              </div>

              <div>
                <div className="text-xs font-mono text-slate-400">TARGET ENDPOINT</div>
                <div className="text-lg font-bold text-white font-mono">{auditResult.target}</div>
                <div className="text-xs text-slate-400 mt-1 flex items-center space-x-2">
                  <span>Security Score: <strong className="text-white">{auditResult.score}/100</strong></span>
                  <span>·</span>
                  <span>Duration: {auditResult.durationMs.toFixed(1)} ms</span>
                </div>
              </div>
            </div>

            {/* Quick summary status tags */}
            <div className="flex flex-wrap gap-2 text-xs font-mono">
              <div className={`px-3 py-1.5 rounded-lg border flex items-center space-x-1.5 ${
                auditResult.hasTls13 ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50' : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}>
                {auditResult.hasTls13 ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                <span>TLS 1.3 Active</span>
              </div>

              <div className={`px-3 py-1.5 rounded-lg border flex items-center space-x-1.5 ${
                auditResult.hasPfs ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50' : 'bg-amber-950/60 text-amber-300 border-amber-800/50'
              }`}>
                {auditResult.hasPfs ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                <span>Forward Secrecy (PFS)</span>
              </div>

              <div className={`px-3 py-1.5 rounded-lg border flex items-center space-x-1.5 ${
                auditResult.hasDeprecatedTls ? 'bg-red-950/60 text-red-300 border-red-800/50' : 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50'
              }`}>
                {auditResult.hasDeprecatedTls ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                <span>{auditResult.hasDeprecatedTls ? 'Deprecated Protocols' : 'Modern Protocols Only'}</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Protocol Compatibility Matrix */}
            <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
              <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Protocol Version Compatibility Matrix
              </h3>

              <div className="space-y-2.5">
                {auditResult.protocols.map((proto) => {
                  const isAccepted = proto.allowed;
                  const isSecure = proto.secure;

                  return (
                    <div
                      key={proto.version}
                      className="p-3 bg-[#11192e] rounded-lg border border-[#1e293b]/60 flex items-center justify-between text-xs font-mono"
                    >
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-white">{proto.version}</span>
                        {!isSecure && isAccepted && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                            DEPRECATED
                          </span>
                        )}
                      </div>

                      <div className="flex items-center space-x-1.5">
                        {isAccepted ? (
                          <span className={isSecure ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                            ENABLED
                          </span>
                        ) : (
                          <span className="text-slate-500">DISABLED</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Identified Risks & Remediation Plan */}
            <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
              <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Security Findings &amp; Remediation ({auditResult.risks.length})
              </h3>

              {auditResult.risks.length === 0 ? (
                <div className="p-8 text-center bg-[#11192e] rounded-lg border border-[#1e293b]/60 text-xs font-mono text-emerald-400 space-y-1">
                  <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
                  <div className="font-bold">No High Severity Vulnerabilities Detected</div>
                  <div className="text-slate-400">Target server adheres to contemporary TLS standards.</div>
                </div>
              ) : (
                <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                  {auditResult.risks.map((risk, idx) => (
                    <div
                      key={idx}
                      className={`p-3.5 rounded-lg border text-xs font-mono space-y-2 ${
                        risk.severity === 'critical'
                          ? 'bg-red-950/20 border-red-800/40 text-red-300'
                          : risk.severity === 'warning'
                          ? 'bg-amber-950/20 border-amber-800/40 text-amber-300'
                          : 'bg-blue-950/20 border-blue-800/40 text-blue-300'
                      }`}
                    >
                      <div className="flex items-center justify-between font-bold">
                        <span>{risk.title}</span>
                        <span className="text-[10px] uppercase px-1.5 py-0.5 rounded border">
                          {risk.severity}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-300 leading-relaxed">{risk.description}</p>

                      <div className="text-[11px] bg-black/40 p-2 rounded border border-white/5 text-slate-200">
                        <strong className="text-blue-400">Fix:</strong> {risk.remediation}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
