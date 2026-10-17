import React, { useState, useEffect } from 'react';
import { 
  Network, 
  Copy, 
  Check, 
  CheckCircle2, 
  Clock, 
  ShieldCheck, 
  FileCode, 
  Terminal, 
  RefreshCw,
  Loader2
} from 'lucide-react';
import { fetchAcmeStatus, AcmeStatusReport } from '../lib/api';

export const AcmeStudio: React.FC = () => {
  const [status, setStatus] = useState<AcmeStatusReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeClient, setActiveClient] = useState<'caddy' | 'traefik' | 'certbot' | 'certmanager'>('caddy');
  const [copied, setCopied] = useState<string | null>(null);

  const loadStatus = async () => {
    try {
      const data = await fetchAcmeStatus();
      setStatus(data);
    } catch (err) {
      console.error('Failed to fetch ACME status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const directoryUrl = status?.directoryUrl || `http://${window.location.host}/acme/directory`;

  const clientSnippets = {
    caddy: `# Caddyfile: automatically obtain locally-trusted certificates from TLSLens
app.local {
    tls {
        ca ${directoryUrl}
    }
    reverse_proxy localhost:3000
}`,
    traefik: `# traefik.yml: ACME Resolver configuration
certificatesResolvers:
  tlslens:
    acme:
      email: dev@localhost
      caServer: "${directoryUrl}"
      storage: acme.json
      httpChallenge:
        entryPoint: web`,
    certbot: `# Request a certificate from TLSLens via Certbot
certbot certonly --standalone \\
  --server ${directoryUrl} \\
  --register-unsafely-without-email \\
  --agree-tos \\
  -d app.local -d api.local`,
    certmanager: `# Kubernetes cert-manager ACME ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: tlslens-acme-issuer
spec:
  acme:
    server: "${directoryUrl}"
    email: dev@localhost
    privateKeySecretRef:
      name: tlslens-acme-account-key
    solvers:
      - http01:
          ingress:
            class: nginx`,
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Network className="w-5 h-5 text-blue-400" />
            <span>Local ACME Server (RFC 8555 Directory)</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Embedded zero-configuration ACME directory providing automatic certificate issuance to Caddy, Traefik, Certbot, and cert-manager.
          </p>
        </div>
        <button
          onClick={loadStatus}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#11192e] hover:bg-[#16213c] text-slate-300 text-xs font-mono border border-slate-800 transition"
        >
          <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Directory URL Hero Box */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/40 to-indigo-950/40 border border-blue-800/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-semibold">
              ACME v2 Directory Online
            </span>
          </div>
          <div className="text-xs font-mono text-slate-300 mt-1 select-all break-all">
            {directoryUrl}
          </div>
        </div>
        <button
          onClick={() => handleCopy(directoryUrl, 'dir')}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono transition shrink-0 shadow-md shadow-blue-500/20"
        >
          {copied === 'dir' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied === 'dir' ? 'Copied' : 'Copy Directory URL'}</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
          <span className="text-[11px] font-mono text-slate-400 uppercase">Registered Accounts</span>
          <p className="text-xl font-bold font-mono text-white mt-1">
            {status?.totalAccounts ?? 0}
          </p>
        </div>

        <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
          <span className="text-[11px] font-mono text-slate-400 uppercase">Orders Processed</span>
          <p className="text-xl font-bold font-mono text-white mt-1">
            {status?.totalOrders ?? 0}
          </p>
        </div>

        <div className="p-3.5 rounded-lg bg-[#0b101b] border border-[#1e293b]">
          <span className="text-[11px] font-mono text-slate-400 uppercase">Certificates Issued</span>
          <p className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {status?.totalCertificates ?? 0}
          </p>
        </div>
      </div>

      {/* Client Configuration Studio Tabs */}
      <div className="rounded-xl border border-[#1e293b] bg-[#0b101b] overflow-hidden">
        <div className="p-3 bg-[#11192e] border-b border-[#1e293b] flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1.5">
            {(['caddy', 'traefik', 'certbot', 'certmanager'] as const).map((client) => (
              <button
                key={client}
                onClick={() => setActiveClient(client)}
                className={`px-3 py-1 rounded text-xs font-mono transition uppercase ${
                  activeClient === client
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {client}
              </button>
            ))}
          </div>

          <button
            onClick={() => handleCopy(clientSnippets[activeClient], activeClient)}
            className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition border border-slate-700"
          >
            {copied === activeClient ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied === activeClient ? 'Copied Snippet' : 'Copy Snippet'}</span>
          </button>
        </div>

        <div className="p-4 bg-[#080c14]">
          <pre className="text-xs font-mono text-blue-300/90 whitespace-pre overflow-x-auto leading-relaxed">
            {clientSnippets[activeClient]}
          </pre>
        </div>
      </div>

      {/* Recent Orders Log Table */}
      <div className="rounded-xl border border-[#1e293b] bg-[#0b101b] overflow-hidden">
        <div className="p-3 bg-[#11192e] border-b border-[#1e293b] flex items-center justify-between">
          <span className="text-xs font-mono font-bold text-slate-200">ACME Activity &amp; Issued Orders</span>
          <span className="text-[11px] font-mono text-slate-400">
            {status?.recentOrders.length ?? 0} Orders Recorded
          </span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            <Loader2 className="w-4 h-4 animate-spin mx-auto mb-2 text-blue-400" />
            Loading ACME orders...
          </div>
        ) : !status?.recentOrders || status.recentOrders.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No ACME orders issued yet. Point Caddy or Traefik to the Directory URL above to automatically generate certificates.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1e293b] bg-[#090d16] text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="py-2.5 px-4 font-medium">Order ID</th>
                  <th className="py-2.5 px-4 font-medium">Domains</th>
                  <th className="py-2.5 px-4 font-medium">Status</th>
                  <th className="py-2.5 px-4 font-medium">Created At</th>
                  <th className="py-2.5 px-4 font-medium text-right">Certificate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {status.recentOrders.map((ord) => (
                  <tr key={ord.id} className="hover:bg-[#11192e]/40 transition">
                    <td className="py-2.5 px-4 text-slate-300 font-medium">{ord.id}</td>
                    <td className="py-2.5 px-4 text-white">
                      {ord.domains.join(', ')}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        <span>{ord.status}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {new Date(ord.createdAt).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {ord.certificate ? (
                        <a
                          href={ord.certificate}
                          target="_blank"
                          rel="noreferrer"
                          className="text-blue-400 hover:text-blue-300 underline"
                        >
                          Download PEM
                        </a>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
