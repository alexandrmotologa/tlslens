import React, { useState, useEffect } from 'react';
import { 
  FileCode, 
  Copy, 
  Check, 
  Sliders, 
  Download, 
  Terminal, 
  Server, 
  Layers 
} from 'lucide-react';
import { ConfigSnippet, fetchConfigSnippets, generateK8s, ManifestBundle } from '../lib/api';

export const ConfigGenerator: React.FC = () => {
  const [snippets, setSnippets] = useState<ConfigSnippet[]>([]);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Parameter states
  const [domain, setDomain] = useState('api.local.test');
  const [port, setPort] = useState(443);
  const [backendAddr, setBackendAddr] = useState('127.0.0.1:3000');
  const [certPath, setCertPath] = useState('/etc/ssl/certs/cert.pem');
  const [keyPath, setKeyPath] = useState('/etc/ssl/private/key.pem');
  const [caPath, setCAPath] = useState('/etc/ssl/certs/root-ca.crt');
  const [showFilters, setShowFilters] = useState(false);

  // Kubernetes Manifest states
  const [k8sName, setK8sName] = useState('web-gateway');
  const [k8sNamespace, setK8sNamespace] = useState('default');
  const [k8sBundle, setK8sBundle] = useState<ManifestBundle | null>(null);
  const [k8sLoading, setK8sLoading] = useState(false);

  const loadSnippets = async () => {
    try {
      const res = await fetchConfigSnippets({
        domain,
        port,
        backendAddr,
        certPath,
        keyPath,
        caPath,
      });
      if (res.snippets) {
        setSnippets(res.snippets);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateK8s = async () => {
    setK8sLoading(true);
    try {
      const bundle = await generateK8s({
        name: k8sName,
        namespace: k8sNamespace,
        domains: [domain, 'localhost'],
        serviceName: k8sName,
        servicePort: port,
      });
      setK8sBundle(bundle);
    } catch (err) {
      console.error(err);
    } finally {
      setK8sLoading(false);
    }
  };

  useEffect(() => {
    loadSnippets();
    handleGenerateK8s();
  }, [domain, port, backendAddr, certPath, keyPath, caPath, k8sName, k8sNamespace]);

  const handleCopy = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const categories = [
    { id: 'all', label: 'All Snippets' },
    { id: 'k8s', label: 'Kubernetes' },
    { id: 'proxy', label: 'Reverse Proxies' },
    { id: 'client', label: 'Client CLI' },
    { id: 'runtime', label: 'Runtimes' },
    { id: 'env', label: 'Environment' },
  ];

  const filtered = activeCategory === 'all' 
    ? snippets 
    : snippets.filter((s) => s.category === activeCategory);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]/70">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <FileCode className="w-5 h-5 text-indigo-400" />
              <span>TLS &amp; mTLS Configuration Studio</span>
            </h2>
            <p className="text-xs text-slate-400">
              Export validated server configurations and development runtime environment variables
            </p>
          </div>

          <button
            onClick={() => setShowFilters(!showFilters)}
            className="text-xs font-mono px-3 py-1.5 rounded bg-[#11192e] hover:bg-[#1a2542] text-slate-300 border border-[#1e293b] flex items-center space-x-1.5 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5 text-blue-400" />
            <span>{showFilters ? 'Hide Parameters' : 'Customize File Paths'}</span>
          </button>
        </div>

        {/* Customization Drawer */}
        {showFilters && (
          <div className="mt-4 p-4 bg-[#11192e] rounded-lg border border-[#1e293b]/70 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono animate-fadeIn">
            <div>
              <label className="text-slate-400 block mb-1">Domain Name</label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Server Port</label>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(parseInt(e.target.value) || 443)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Upstream Backend</label>
              <input
                type="text"
                value={backendAddr}
                onChange={(e) => setBackendAddr(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Cert Path</label>
              <input
                type="text"
                value={certPath}
                onChange={(e) => setCertPath(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Key Path</label>
              <input
                type="text"
                value={keyPath}
                onChange={(e) => setKeyPath(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Root CA Path</label>
              <input
                type="text"
                value={caPath}
                onChange={(e) => setCAPath(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] rounded px-2.5 py-1 text-white focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Category Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 mt-4">
          {categories.map((c) => (
            <button
              key={c.id}
              onClick={() => setActiveCategory(c.id)}
              className={`text-xs font-mono px-3 py-1.5 rounded-md border transition-all ${
                activeCategory === c.id
                  ? 'bg-blue-600/20 text-blue-400 border-blue-500/40 shadow-sm'
                  : 'bg-[#11192e] text-slate-400 border-[#1e293b] hover:text-slate-200'
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>

      {/* Kubernetes Manifest Studio View */}
      {activeCategory === 'k8s' ? (
        <div className="space-y-6 animate-fadeIn">
          <div className="p-4 bg-[#0c1222] border border-[#1e293b] rounded-xl space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white font-mono flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-blue-400" />
                  <span>Kubernetes TLS &amp; cert-manager Manifest Studio</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Production manifests for kubernetes.io/tls Secrets, CA ConfigMaps, cert-manager ClusterIssuers, and Ingress.
                </p>
              </div>

              {k8sBundle && (
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleCopy('k8s-cmd', k8sBundle.kubectlCommand)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded border border-slate-700 transition"
                  >
                    {copiedId === 'k8s-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Terminal className="w-3.5 h-3.5 text-blue-400" />}
                    <span>{copiedId === 'k8s-cmd' ? 'Copied Command' : 'Copy kubectl Command'}</span>
                  </button>

                  <button
                    onClick={() => handleCopy('k8s-all', k8sBundle.allInOne)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded shadow transition"
                  >
                    {copiedId === 'k8s-all' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'k8s-all' ? 'Copied Bundle' : 'Copy All-In-One YAML'}</span>
                  </button>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-[#1e293b]/60">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Resource Name</label>
                <input
                  type="text"
                  value={k8sName}
                  onChange={(e) => setK8sName(e.target.value)}
                  className="w-full bg-[#11192e] border border-slate-700 rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Target Namespace</label>
                <input
                  type="text"
                  value={k8sNamespace}
                  onChange={(e) => setK8sNamespace(e.target.value)}
                  className="w-full bg-[#11192e] border border-slate-700 rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>

          {k8sBundle && (
            <div className="space-y-4">
              {/* TLS Secret Card */}
              <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl overflow-hidden">
                <div className="px-5 py-3 bg-[#11192e] border-b border-[#1e293b]/70 flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white">1. kubernetes.io/tls Secret</span>
                  <button
                    onClick={() => handleCopy('k8s-sec', k8sBundle.tlsSecret)}
                    className="text-xs font-mono text-blue-400 hover:text-white flex items-center space-x-1"
                  >
                    {copiedId === 'k8s-sec' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'k8s-sec' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-4 bg-[#090d16] text-xs font-mono text-emerald-300/90 whitespace-pre overflow-x-auto">
                  {k8sBundle.tlsSecret}
                </pre>
              </div>

              {/* CA ConfigMap Card */}
              <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl overflow-hidden">
                <div className="px-5 py-3 bg-[#11192e] border-b border-[#1e293b]/70 flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white">2. Root CA ConfigMap</span>
                  <button
                    onClick={() => handleCopy('k8s-cm', k8sBundle.caConfigMap)}
                    className="text-xs font-mono text-blue-400 hover:text-white flex items-center space-x-1"
                  >
                    {copiedId === 'k8s-cm' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'k8s-cm' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-4 bg-[#090d16] text-xs font-mono text-blue-300/90 whitespace-pre overflow-x-auto">
                  {k8sBundle.caConfigMap}
                </pre>
              </div>

              {/* cert-manager ClusterIssuer Card */}
              <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl overflow-hidden">
                <div className="px-5 py-3 bg-[#11192e] border-b border-[#1e293b]/70 flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white">3. cert-manager ClusterIssuer &amp; Certificate</span>
                  <button
                    onClick={() => handleCopy('k8s-iss', k8sBundle.certManagerIssuer)}
                    className="text-xs font-mono text-blue-400 hover:text-white flex items-center space-x-1"
                  >
                    {copiedId === 'k8s-iss' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === 'k8s-iss' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="p-4 bg-[#090d16] text-xs font-mono text-purple-300/90 whitespace-pre overflow-x-auto">
                  {k8sBundle.certManagerIssuer}
                </pre>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Standard Snippets Grid */
        <div className="grid grid-cols-1 gap-6">
          {filtered.map((snip) => (
            <div
              key={snip.id}
              className="bg-[#0c1222] border border-[#1e293b] rounded-xl overflow-hidden shadow-sm"
            >
              {/* Snippet Header */}
              <div className="px-5 py-3.5 bg-[#11192e] border-b border-[#1e293b]/70 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">{snip.title}</h3>
                  <p className="text-xs text-slate-400 mt-0.5">{snip.description}</p>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                    {snip.language}
                  </span>

                  <button
                    onClick={() => handleCopy(snip.id, snip.code)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono rounded shadow transition-colors"
                  >
                    {copiedId === snip.id ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId === snip.id ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>

              {/* Code Body */}
              <div className="p-4 bg-[#090d16] overflow-x-auto">
                <pre className="text-xs font-mono text-slate-200 leading-relaxed whitespace-pre">
                  {snip.code}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
