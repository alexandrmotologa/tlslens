import React, { useState } from 'react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Key, 
  Download, 
  Copy, 
  Check, 
  Plus, 
  X, 
  Clock, 
  Calendar,
  FileCheck,
  Cpu,
  Hash,
  Loader2,
  FolderOpen
} from 'lucide-react';
import { CACredentialsInfo, IssueCertRequest, IssuedCertResponse, initCA, issueCertificate, trustCA, untrustCA } from '../lib/api';

interface CaManagerProps {
  caInfo?: CACredentialsInfo;
  caInitialized: boolean;
  onRefreshCA: () => void;
}

export const CaManager: React.FC<CaManagerProps> = ({
  caInfo,
  caInitialized,
  onRefreshCA,
}) => {
  // Init form state
  const [initCN, setInitCN] = useState('TLSLens Local Development Root CA');
  const [initOrg, setInitOrg] = useState('TLSLens');
  const [initKeyType, setInitKeyType] = useState('ecdsa');
  const [initDays, setInitDays] = useState(3650);
  const [initLoading, setInitLoading] = useState(false);

  // Issue form state
  const [issueCN, setIssueCN] = useState('api.local.test');
  const [domainInput, setDomainInput] = useState('');
  const [domains, setDomains] = useState<string[]>(['api.local.test', '*.local.test', 'localhost']);
  const [ipInput, setIpInput] = useState('');
  const [ips, setIps] = useState<string[]>(['127.0.0.1', '::1']);
  const [validityDays, setValidityDays] = useState(365);
  const [issueKeyType, setIssueKeyType] = useState('ecdsa');
  const [p12Password, setP12Password] = useState('');
  const [issueLoading, setIssueLoading] = useState(false);
  const [issuedResult, setIssuedResult] = useState<IssuedCertResponse | null>(null);

  // Copy notification state
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleAddDomain = () => {
    const trimmed = domainInput.trim();
    if (trimmed && !domains.includes(trimmed)) {
      setDomains([...domains, trimmed]);
      setDomainInput('');
    }
  };

  const handleRemoveDomain = (d: string) => {
    setDomains(domains.filter((item) => item !== d));
  };

  const handleAddIp = () => {
    const trimmed = ipInput.trim();
    if (trimmed && !ips.includes(trimmed)) {
      setIps([...ips, trimmed]);
      setIpInput('');
    }
  };

  const handleRemoveIp = (ip: string) => {
    setIps(ips.filter((item) => item !== ip));
  };

  const handleInitCA = async (e: React.FormEvent) => {
    e.preventDefault();
    setInitLoading(true);
    try {
      await initCA({
        commonName: initCN,
        organization: initOrg,
        keyType: initKeyType,
        validityDays: initDays,
      });
      onRefreshCA();
    } catch (err) {
      console.error(err);
    } finally {
      setInitLoading(false);
    }
  };

  const handleIssueCert = async (e: React.FormEvent) => {
    e.preventDefault();
    setIssueLoading(true);
    try {
      const res = await issueCertificate({
        commonName: issueCN,
        domains,
        ips,
        validityDays,
        keyType: issueKeyType,
        p12Password: p12Password || undefined,
      });
      setIssuedResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIssueLoading(false);
    }
  };

  const downloadFile = (filename: string, content: string | Blob, mime: string) => {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Root CA Management Header */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: CA Details or Init Form */}
        <div className="lg:col-span-2 bg-[#0c1222] border border-[#1e293b] rounded-xl p-6 shadow-sm">
          <div className="flex items-center justify-between pb-4 border-b border-[#1e293b]/70">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-blue-950/80 border border-blue-800/40 text-blue-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">Local Root Certificate Authority</h2>
                <p className="text-xs text-slate-400">Local trust anchor managing wildcard and development certificates</p>
              </div>
            </div>

            {caInitialized && (
              <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-medium border flex items-center space-x-1.5 ${
                caInfo?.isTrustedByOS 
                  ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/40' 
                  : 'bg-amber-950/60 text-amber-300 border-amber-800/40'
              }`}>
                {caInfo?.isTrustedByOS ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                <span>{caInfo?.isTrustedByOS ? 'OS Trusted' : 'Not Trusted In OS'}</span>
              </span>
            )}
          </div>

          {caInitialized && caInfo ? (
            <div className="mt-5 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#11192e] p-3.5 rounded-lg border border-[#1e293b]/60">
                  <div className="text-[11px] text-slate-400 font-mono flex items-center space-x-1 mb-1">
                    <FileCheck className="w-3.5 h-3.5 text-blue-400" />
                    <span>COMMON NAME</span>
                  </div>
                  <div className="text-sm font-semibold text-white font-mono break-all">{caInfo.commonName}</div>
                  <div className="text-xs text-slate-400 mt-1">Org: {caInfo.organization} · {caInfo.country}</div>
                </div>

                <div className="bg-[#11192e] p-3.5 rounded-lg border border-[#1e293b]/60">
                  <div className="text-[11px] text-slate-400 font-mono flex items-center space-x-1 mb-1">
                    <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                    <span>CRYPTOGRAPHIC KEY</span>
                  </div>
                  <div className="text-sm font-semibold text-white font-mono">
                    {caInfo.keyType} ({caInfo.keyLength} bits)
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">{caInfo.signatureAlgorithm}</div>
                </div>

                <div className="bg-[#11192e] p-3.5 rounded-lg border border-[#1e293b]/60">
                  <div className="text-[11px] text-slate-400 font-mono flex items-center space-x-1 mb-1">
                    <Calendar className="w-3.5 h-3.5 text-emerald-400" />
                    <span>VALIDITY WINDOW</span>
                  </div>
                  <div className="text-xs font-mono text-slate-200">
                    Expires: {new Date(caInfo.notAfter).toLocaleDateString()}
                  </div>
                  <div className="text-xs text-emerald-400 font-mono mt-1 font-medium">
                    {caInfo.daysRemaining} days remaining
                  </div>
                </div>

                <div className="bg-[#11192e] p-3.5 rounded-lg border border-[#1e293b]/60">
                  <div className="text-[11px] text-slate-400 font-mono flex items-center space-x-1 mb-1">
                    <Hash className="w-3.5 h-3.5 text-cyan-400" />
                    <span>SERIAL NUMBER</span>
                  </div>
                  <div className="text-xs font-mono text-slate-300 break-all">{caInfo.serialNumber}</div>
                </div>
              </div>

              {/* Fingerprint block */}
              <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60">
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono mb-1">
                  <span>SHA-256 FINGERPRINT</span>
                  <button
                    onClick={() => handleCopy('ca-fp', caInfo.fingerprintSHA256)}
                    className="text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                  >
                    {copiedKey === 'ca-fp' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'ca-fp' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="text-xs font-mono text-slate-300 break-all bg-[#090d16] p-2 rounded border border-[#1e293b]/40">
                  {caInfo.fingerprintSHA256}
                </div>
              </div>

              {/* Actions row */}
              <div className="flex flex-wrap items-center justify-between pt-2 gap-3">
                <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                  <FolderOpen className="w-3.5 h-3.5" />
                  <span className="truncate max-w-xs">{caInfo.storageDir}</span>
                </div>

                <div className="flex items-center space-x-2">
                  <a
                    href="/api/ca/download?type=cert"
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-[#172554] hover:bg-blue-900/60 text-blue-300 text-xs font-mono border border-blue-800/40 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>root-ca.crt</span>
                  </a>
                  <a
                    href="/api/ca/download?type=key"
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>root-ca.key</span>
                  </a>
                </div>
              </div>
            </div>
          ) : (
            /* Root CA Initializer Form */
            <form onSubmit={handleInitCA} className="mt-5 space-y-4">
              <div className="p-3 bg-blue-950/30 border border-blue-800/40 rounded-lg text-xs text-blue-300">
                No Root CA found in storage. Generate a local CA with 1 click to begin signing development and wildcard certificates.
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Common Name (CN)</label>
                  <input
                    type="text"
                    value={initCN}
                    onChange={(e) => setInitCN(e.target.value)}
                    className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Organization (O)</label>
                  <input
                    type="text"
                    value={initOrg}
                    onChange={(e) => setInitOrg(e.target.value)}
                    className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Key Algorithm</label>
                  <select
                    value={initKeyType}
                    onChange={(e) => setInitKeyType(e.target.value)}
                    className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                  >
                    <option value="ecdsa">ECDSA P-256 (Fastest Handshakes)</option>
                    <option value="rsa2048">RSA 2048 (Maximum Legacy Support)</option>
                    <option value="rsa4096">RSA 4096 (High Security)</option>
                    <option value="ed25519">Ed25519 (Modern Curve)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Validity Period (Days)</label>
                  <input
                    type="number"
                    value={initDays}
                    onChange={(e) => setInitDays(parseInt(e.target.value) || 365)}
                    className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={initLoading}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow flex items-center space-x-2 transition-colors disabled:opacity-50"
                >
                  {initLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                  <span>Generate Root CA</span>
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Right: Quick Instructions & Environment Snippet */}
        <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
          <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            <span>Developer Trust Setup</span>
          </h3>

          <p className="text-xs text-slate-400 leading-relaxed">
            Once installed via <strong>Trust CA</strong>, all certificates issued by TLSLens are trusted by Chrome, Edge, Safari, and system libraries without security warnings.
          </p>

          <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60 space-y-2">
            <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>NODE.JS TRUST VARIABLE</span>
              <button
                onClick={() => handleCopy('env-node', `NODE_EXTRA_CA_CERTS="${caInfo?.certPath || '~/.tlslens/ca/root-ca.crt'}"`)}
                className="text-blue-400 hover:text-blue-300"
              >
                {copiedKey === 'env-node' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <code className="block text-[11px] font-mono text-emerald-400 bg-[#090d16] p-2 rounded overflow-x-auto">
              NODE_EXTRA_CA_CERTS="{caInfo?.certPath || '~/.tlslens/ca/root-ca.crt'}"
            </code>
          </div>

          <div className="bg-[#11192e] p-3 rounded-lg border border-[#1e293b]/60 space-y-2">
            <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>PYTHON / CURL TRUST</span>
              <button
                onClick={() => handleCopy('env-py', `SSL_CERT_FILE="${caInfo?.certPath || '~/.tlslens/ca/root-ca.crt'}"`)}
                className="text-blue-400 hover:text-blue-300"
              >
                {copiedKey === 'env-py' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <code className="block text-[11px] font-mono text-emerald-400 bg-[#090d16] p-2 rounded overflow-x-auto">
              SSL_CERT_FILE="{caInfo?.certPath || '~/.tlslens/ca/root-ca.crt'}"
            </code>
          </div>
        </div>
      </div>

      {/* Leaf Certificate Issuance Section */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-6 shadow-sm">
        <div className="pb-4 border-b border-[#1e293b]/70 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Issue SAN Leaf Certificate</h2>
            <p className="text-xs text-slate-400">Generate wildcards, domain certificates, and client authentication certs</p>
          </div>
          <span className="text-xs font-mono text-blue-400 px-2.5 py-1 rounded bg-blue-950/60 border border-blue-800/40">
            Signed by Local CA
          </span>
        </div>

        <form onSubmit={handleIssueCert} className="mt-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Common Name (CN)</label>
              <input
                type="text"
                value={issueCN}
                onChange={(e) => setIssueCN(e.target.value)}
                placeholder="api.local.test"
                className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Key Algorithm</label>
              <select
                value={issueKeyType}
                onChange={(e) => setIssueKeyType(e.target.value)}
                className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
              >
                <option value="ecdsa">ECDSA P-256 (Default)</option>
                <option value="rsa2048">RSA 2048</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Validity (Days)</label>
              <input
                type="number"
                value={validityDays}
                onChange={(e) => setValidityDays(parseInt(e.target.value) || 365)}
                className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          {/* DNS Names Tag Input */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">Subject Alternative Names (DNS Names)</label>
            <div className="flex flex-wrap items-center gap-1.5 p-2 bg-[#11192e] border border-[#1e293b] rounded-md">
              {domains.map((d) => (
                <span
                  key={d}
                  className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-blue-950/70 border border-blue-800/40 text-blue-300 text-xs font-mono"
                >
                  <span>{d}</span>
                  <button type="button" onClick={() => handleRemoveDomain(d)} className="text-blue-400 hover:text-white">
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
              <div className="flex items-center space-x-1 flex-1 min-w-[150px]">
                <input
                  type="text"
                  value={domainInput}
                  onChange={(e) => setDomainInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddDomain();
                    }
                  }}
                  placeholder="Type domain and hit Enter..."
                  className="bg-transparent text-xs text-white font-mono focus:outline-none w-full"
                />
                <button
                  type="button"
                  onClick={handleAddDomain}
                  className="text-xs px-2 py-0.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-mono"
                >
                  Add
                </button>
              </div>
            </div>
          </div>

          {/* IP Addresses Tag Input */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">IP Alternative Names (SAN IPs)</label>
            <div className="flex flex-wrap items-center gap-1.5 p-2 bg-[#11192e] border border-[#1e293b] rounded-md">
              {ips.map((ip) => (
                <span
                  key={ip}
                  className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-indigo-950/70 border border-indigo-800/40 text-indigo-300 text-xs font-mono"
                >
                  <span>{ip}</span>
                  <button type="button" onClick={() => handleRemoveIp(ip)} className="text-indigo-400 hover:text-white">
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
              <div className="flex items-center space-x-1 flex-1 min-w-[150px]">
                <input
                  type="text"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddIp();
                    }
                  }}
                  placeholder="Type IP and hit Enter (e.g. 127.0.0.1)..."
                  className="bg-transparent text-xs text-white font-mono focus:outline-none w-full"
                />
                <button
                  type="button"
                  onClick={handleAddIp}
                  className="text-xs px-2 py-0.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded font-mono"
                >
                  Add
                </button>
              </div>
            </div>
          </div>

          {/* PKCS#12 Optional Password */}
          <div className="max-w-xs">
            <label className="block text-xs font-mono text-slate-400 mb-1">PKCS#12 Password (Optional)</label>
            <input
              type="password"
              value={p12Password}
              onChange={(e) => setP12Password(e.target.value)}
              placeholder="Leave empty or set password"
              className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={issueLoading || !caInitialized}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded-md shadow-md flex items-center space-x-2 transition-colors disabled:opacity-50"
          >
            {issueLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            <span>Issue SAN Certificate</span>
          </button>
        </form>

        {/* Issued Certificate Result Drawer */}
        {issuedResult && (
          <div className="mt-6 p-4 rounded-xl bg-[#090d16] border border-blue-900/60 space-y-4 animate-fadeIn">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1e293b] pb-3">
              <div className="flex items-center space-x-2">
                <Check className="w-5 h-5 text-emerald-400" />
                <div>
                  <h4 className="text-sm font-semibold text-white font-mono">{issuedResult.commonName}</h4>
                  <p className="text-xs text-slate-400">
                    Serial: {issuedResult.serialNumber} · Expires: {new Date(issuedResult.notAfter).toLocaleDateString()}
                  </p>
                </div>
              </div>

              {/* Download buttons */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => downloadFile(`${issuedResult.commonName}-cert.pem`, issuedResult.certPEM, 'application/x-pem-file')}
                  className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700"
                >
                  <Download className="w-3 h-3" />
                  <span>cert.pem</span>
                </button>

                <button
                  onClick={() => downloadFile(`${issuedResult.commonName}-key.pem`, issuedResult.keyPEM, 'application/x-pem-file')}
                  className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700"
                >
                  <Download className="w-3 h-3" />
                  <span>key.pem</span>
                </button>

                <button
                  onClick={() => downloadFile(`${issuedResult.commonName}-bundle.pem`, issuedResult.bundlePEM, 'application/x-pem-file')}
                  className="flex items-center space-x-1 px-2.5 py-1 bg-blue-900/40 hover:bg-blue-900/70 text-blue-300 text-xs font-mono rounded border border-blue-700/50"
                >
                  <Download className="w-3 h-3" />
                  <span>bundle.pem</span>
                </button>

                {issuedResult.p12Base64 && (
                  <button
                    onClick={() => {
                      const byteChars = atob(issuedResult.p12Base64!);
                      const byteNumbers = new Array(byteChars.length);
                      for (let i = 0; i < byteChars.length; i++) {
                        byteNumbers[i] = byteChars.charCodeAt(i);
                      }
                      const byteArray = new Uint8Array(byteNumbers);
                      downloadFile(`${issuedResult.commonName}.p12`, new Blob([byteArray]), 'application/x-pkcs12');
                    }}
                    className="flex items-center space-x-1 px-2.5 py-1 bg-indigo-900/40 hover:bg-indigo-900/70 text-indigo-300 text-xs font-mono rounded border border-indigo-700/50"
                  >
                    <Download className="w-3 h-3" />
                    <span>cert.p12</span>
                  </button>
                )}
              </div>
            </div>

            {/* Code views */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                  <span>CERTIFICATE PEM</span>
                  <button
                    onClick={() => handleCopy('res-cert', issuedResult.certPEM)}
                    className="text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                  >
                    {copiedKey === 'res-cert' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'res-cert' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <textarea
                  readOnly
                  rows={5}
                  value={issuedResult.certPEM}
                  className="w-full bg-[#11192e] border border-[#1e293b] rounded p-2 text-[10px] font-mono text-slate-300 focus:outline-none"
                />
              </div>

              <div>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                  <span>PRIVATE KEY PEM</span>
                  <button
                    onClick={() => handleCopy('res-key', issuedResult.keyPEM)}
                    className="text-blue-400 hover:text-blue-300 flex items-center space-x-1"
                  >
                    {copiedKey === 'res-key' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'res-key' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <textarea
                  readOnly
                  rows={5}
                  value={issuedResult.keyPEM}
                  className="w-full bg-[#11192e] border border-[#1e293b] rounded p-2 text-[10px] font-mono text-slate-300 focus:outline-none"
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
