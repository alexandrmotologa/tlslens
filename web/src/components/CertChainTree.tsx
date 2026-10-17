import React, { useState } from 'react';
import { 
  GitBranch, 
  ShieldCheck, 
  ShieldAlert, 
  Search, 
  Copy, 
  Check, 
  Key, 
  Hash, 
  Calendar, 
  Layers, 
  ArrowDown, 
  FileText,
  AlertCircle,
  ExternalLink,
  Loader2
} from 'lucide-react';
import { CertSummary, ChainHierarchy, inspectChain, probeEndpoint } from '../lib/api';

export const CertChainTree: React.FC = () => {
  const [target, setTarget] = useState('google.com:443');
  const [pemInput, setPemInput] = useState('');
  const [showPemInput, setShowPemInput] = useState(false);
  const [loading, setLoading] = useState(false);
  const [hierarchy, setHierarchy] = useState<ChainHierarchy | null>(null);
  const [selectedNode, setSelectedNode] = useState<CertSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleInspect = async () => {
    setLoading(true);
    setError(null);
    try {
      if (showPemInput && pemInput.trim()) {
        const res = await inspectChain(pemInput);
        setHierarchy(res);
        setSelectedNode(res.leaf);
      } else if (target.trim()) {
        // Probe endpoint and extract peer certs
        const probeRes = await probeEndpoint(target, undefined, true);
        if (probeRes.peerCertificates && probeRes.peerCertificates.length > 0) {
          const leaf = probeRes.peerCertificates[0];
          const intermediates = probeRes.peerCertificates.slice(1, probeRes.peerCertificates.length - 1);
          let root: CertSummary | undefined = undefined;
          if (probeRes.peerCertificates.length > 1) {
            root = probeRes.peerCertificates[probeRes.peerCertificates.length - 1];
          }

          const h: ChainHierarchy = {
            leaf,
            intermediates,
            root,
            chainLength: probeRes.peerCertificates.length,
            isValid: !probeRes.error || probeRes.error === '',
            validationError: probeRes.error,
          };
          setHierarchy(h);
          setSelectedNode(leaf);
        } else {
          setError(probeRes.error || 'No certificates presented by endpoint');
        }
      }
    } catch (err: any) {
      setError(err.message || 'Inspection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target & Query Panel */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]/70">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <GitBranch className="w-5 h-5 text-indigo-400" />
              <span>X.509 Certificate Chain Hierarchy</span>
            </h2>
            <p className="text-xs text-slate-400">
              Interactive tree visualizer for Root, Intermediate, and Leaf certification paths
            </p>
          </div>

          <button
            onClick={() => setShowPemInput(!showPemInput)}
            className="text-xs font-mono px-3 py-1 rounded bg-[#11192e] hover:bg-[#1a2542] text-slate-300 border border-[#1e293b] transition-colors"
          >
            {showPemInput ? 'Switch to Target Host' : 'Paste Raw PEM Bundle'}
          </button>
        </div>

        {/* Input Bar */}
        <div className="mt-4">
          {showPemInput ? (
            <div className="space-y-3">
              <textarea
                value={pemInput}
                onChange={(e) => setPemInput(e.target.value)}
                rows={5}
                placeholder="Paste PEM certificate blocks (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)"
                className="w-full bg-[#11192e] border border-[#1e293b] rounded-md p-3 text-xs text-slate-200 font-mono focus:border-blue-500 focus:outline-none"
              />
              <button
                onClick={handleInspect}
                disabled={loading}
                className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow flex items-center space-x-2 transition-colors disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                <span>Inspect PEM Chain</span>
              </button>
            </div>
          ) : (
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleInspect()}
                placeholder="e.g. google.com:443 or localhost:9443"
                className="flex-1 bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-2 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
              />
              <button
                onClick={handleInspect}
                disabled={loading}
                className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow flex items-center justify-center space-x-2 transition-colors disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                <span>Trace Chain</span>
              </button>
            </div>
          )}
        </div>

        {error && (
          <div className="mt-3 p-3 bg-red-950/40 border border-red-800/50 rounded-lg text-xs text-red-300 font-mono flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Main Hierarchy Workspace */}
      {hierarchy && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Visual Vertical Hierarchy Tree */}
          <div className="lg:col-span-5 bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1e293b]/70">
              <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Certification Path ({hierarchy.chainLength} Nodes)
              </span>

              <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                hierarchy.isValid
                  ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/50'
                  : 'bg-red-950/70 text-red-300 border-red-800/50'
              }`}>
                {hierarchy.isValid ? 'Chain Validated' : 'Validation Error'}
              </span>
            </div>

            {/* Tree Nodes Flow: Root -> Intermediates -> Leaf */}
            <div className="flex flex-col items-center space-y-2 py-2">
              {/* 1. Root Node (if present) */}
              {hierarchy.root && (
                <>
                  <div
                    onClick={() => setSelectedNode(hierarchy.root!)}
                    className={`w-full p-3.5 rounded-xl border cursor-pointer transition-all ${
                      selectedNode === hierarchy.root
                        ? 'bg-blue-950/40 border-blue-500 shadow-md shadow-blue-500/10'
                        : 'bg-[#11192e] border-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold uppercase">
                        Root Authority
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        {hierarchy.root.daysRemaining}d left
                      </span>
                    </div>
                    <div className="text-sm font-bold text-white font-mono mt-1.5 truncate">
                      {hierarchy.root.commonName || hierarchy.root.subject}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                      {hierarchy.root.keyType} ({hierarchy.root.keyLength}b) · {hierarchy.root.signatureAlgorithm}
                    </div>
                  </div>

                  <div className="flex flex-col items-center my-1 text-slate-600">
                    <div className="w-0.5 h-4 bg-[#1e293b]" />
                    <ArrowDown className="w-4 h-4 -my-1 text-blue-500" />
                    <div className="w-0.5 h-4 bg-[#1e293b]" />
                  </div>
                </>
              )}

              {/* 2. Intermediates */}
              {hierarchy.intermediates.map((inter, idx) => (
                <React.Fragment key={idx}>
                  <div
                    onClick={() => setSelectedNode(inter)}
                    className={`w-full p-3.5 rounded-xl border cursor-pointer transition-all ${
                      selectedNode === inter
                        ? 'bg-blue-950/40 border-blue-500 shadow-md shadow-blue-500/10'
                        : 'bg-[#11192e] border-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-bold uppercase">
                        Intermediate CA [{idx + 1}]
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        {inter.daysRemaining}d left
                      </span>
                    </div>
                    <div className="text-sm font-bold text-white font-mono mt-1.5 truncate">
                      {inter.commonName || inter.subject}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                      {inter.keyType} ({inter.keyLength}b) · Issuer: {inter.issuer}
                    </div>
                  </div>

                  <div className="flex flex-col items-center my-1 text-slate-600">
                    <div className="w-0.5 h-4 bg-[#1e293b]" />
                    <ArrowDown className="w-4 h-4 -my-1 text-blue-500" />
                    <div className="w-0.5 h-4 bg-[#1e293b]" />
                  </div>
                </React.Fragment>
              ))}

              {/* 3. Leaf Node */}
              <div
                onClick={() => setSelectedNode(hierarchy.leaf)}
                className={`w-full p-3.5 rounded-xl border cursor-pointer transition-all ${
                  selectedNode === hierarchy.leaf
                    ? 'bg-blue-950/40 border-blue-500 shadow-md shadow-blue-500/10'
                    : 'bg-[#11192e] border-[#1e293b] hover:border-slate-600'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 font-bold uppercase">
                    Leaf Certificate (End Entity)
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {hierarchy.leaf.daysRemaining}d left
                  </span>
                </div>
                <div className="text-sm font-bold text-white font-mono mt-1.5 truncate">
                  {hierarchy.leaf.commonName || hierarchy.leaf.subject}
                </div>
                <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                  SANs: {hierarchy.leaf.dnsNames?.join(', ') || 'None'}
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Detailed Node Inspector Card */}
          <div className="lg:col-span-7 bg-[#0c1222] border border-[#1e293b] rounded-xl p-6 shadow-sm space-y-5">
            {selectedNode ? (
              <div className="space-y-4">
                <div className="pb-3 border-b border-[#1e293b]/70 flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-bold text-white font-mono">{selectedNode.commonName}</h3>
                    <p className="text-xs text-slate-400">Detailed ASN.1 fields, extensions, and cryptographic parameters</p>
                  </div>
                  <span className={`text-xs font-mono px-2.5 py-1 rounded border ${
                    selectedNode.isExpired
                      ? 'bg-red-950 text-red-300 border-red-800'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                  }`}>
                    {selectedNode.isExpired ? 'EXPIRED' : 'VALID'}
                  </span>
                </div>

                {/* Grid details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">SUBJECT</span>
                    <span className="text-slate-200 break-all">{selectedNode.subject}</span>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">ISSUER</span>
                    <span className="text-slate-200 break-all">{selectedNode.issuer}</span>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">VALID FROM</span>
                    <span className="text-slate-200">{new Date(selectedNode.notBefore).toUTCString()}</span>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">VALID UNTIL</span>
                    <span className="text-slate-200">{new Date(selectedNode.notAfter).toUTCString()}</span>
                    <div className="text-[11px] text-emerald-400 mt-0.5">({selectedNode.daysRemaining} days remaining)</div>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">KEY ALGORITHM</span>
                    <span className="text-slate-200">{selectedNode.keyType} ({selectedNode.keyLength} bits)</span>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-0.5">SIGNATURE ALGORITHM</span>
                    <span className="text-slate-200">{selectedNode.signatureAlgorithm}</span>
                  </div>
                </div>

                {/* Subject Alternative Names (SANs) */}
                {selectedNode.dnsNames && selectedNode.dnsNames.length > 0 && (
                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] font-mono text-slate-400 block mb-1.5">
                      SUBJECT ALTERNATIVE NAMES (DNS) ({selectedNode.dnsNames.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedNode.dnsNames.map((d, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-blue-950/80 border border-blue-800/40 text-blue-300 text-xs font-mono">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Key Usage & Extended Key Usage */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-1">KEY USAGE</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.keyUsage && selectedNode.keyUsage.length > 0 ? (
                        selectedNode.keyUsage.map((u, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                            {u}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-[11px]">Standard / Not Specified</span>
                      )}
                    </div>
                  </div>

                  <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                    <span className="text-[11px] text-slate-500 block mb-1">EXTENDED KEY USAGE</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.extKeyUsage && selectedNode.extKeyUsage.length > 0 ? (
                        selectedNode.extKeyUsage.map((u, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 text-[10px] border border-indigo-800/40">
                            {u}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-[11px]">Standard / Not Specified</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* CAB Forum & RFC 5280 Compliance Linter Section */}
                {selectedNode.lint && (
                  <div className="bg-[#11192e] p-3.5 rounded-lg border border-[#1e293b]/80 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider">
                          CAB Forum &amp; RFC 5280 Compliance
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                            selectedNode.lint.status === 'pass'
                              ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/50'
                              : selectedNode.lint.status === 'warning'
                              ? 'bg-amber-950/70 text-amber-300 border-amber-800/50'
                              : 'bg-rose-950/70 text-rose-300 border-rose-800/50'
                          }`}
                        >
                          {selectedNode.lint.status}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        {selectedNode.lint.findings.length} findings
                      </span>
                    </div>

                    {selectedNode.lint.findings.length === 0 ? (
                      <p className="text-xs text-emerald-400 font-mono flex items-center space-x-1.5">
                        <ShieldCheck className="w-4 h-4 shrink-0" />
                        <span>All CAB Forum Baseline Requirements and RFC 5280 constraints satisfied.</span>
                      </p>
                    ) : (
                      <div className="space-y-2 pt-1">
                        {selectedNode.lint.findings.map((f, i) => (
                          <div
                            key={i}
                            className={`p-2.5 rounded border text-xs font-mono space-y-1 ${
                              f.severity === 'error'
                                ? 'bg-rose-950/30 border-rose-800/40 text-rose-200'
                                : f.severity === 'warning'
                                ? 'bg-amber-950/30 border-amber-800/40 text-amber-200'
                                : 'bg-blue-950/30 border-blue-800/40 text-blue-200'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold flex items-center space-x-1">
                                <span>{f.title}</span>
                              </span>
                              <span className="text-[10px] opacity-75 uppercase">{f.standard}</span>
                            </div>
                            <p className="text-[11px] opacity-90 leading-relaxed">{f.message}</p>
                            <div className="text-[11px] text-slate-300 pt-1 border-t border-white/10 flex items-start space-x-1">
                              <span className="text-emerald-400 shrink-0">Fix:</span>
                              <span>{f.remediation}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Fingerprint block */}
                <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mb-1">
                    <span>SHA-256 FINGERPRINT</span>
                    <button
                      onClick={() => handleCopy('node-fp', selectedNode.fingerprintSHA256)}
                      className="text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                    >
                      {copiedKey === 'node-fp' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === 'node-fp' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="text-xs font-mono text-slate-300 break-all bg-[#090d16] p-2 rounded border border-[#1e293b]/40">
                    {selectedNode.fingerprintSHA256}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs font-mono">
                Click any node in the certification tree to inspect its ASN.1 extensions.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
