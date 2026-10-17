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
import { ConfigSnippet, fetchConfigSnippets } from '../lib/api';

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

  useEffect(() => {
    loadSnippets();
  }, [domain, port, backendAddr, certPath, keyPath, caPath]);

  const handleCopy = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const categories = [
    { id: 'all', label: 'All Snippets' },
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

      {/* Snippets Grid */}
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
    </div>
  );
};
