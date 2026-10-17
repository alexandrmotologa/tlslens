import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { CaManager } from './components/CaManager';
import { HandshakeWaterfall } from './components/HandshakeWaterfall';
import { CertChainTree } from './components/CertChainTree';
import { MtlsPlayground } from './components/MtlsPlayground';
import { SecurityAudit } from './components/SecurityAudit';
import { ConfigGenerator } from './components/ConfigGenerator';
import { CACredentialsInfo, connectWebSocket, fetchCAStatus } from './lib/api';
import { ShieldCheck, Info } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('ca');
  const [caInfo, setCaInfo] = useState<CACredentialsInfo | undefined>(undefined);
  const [caInitialized, setCaInitialized] = useState<boolean>(false);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [liveBanner, setLiveBanner] = useState<string | null>(null);

  const loadCA = async () => {
    try {
      const res = await fetchCAStatus();
      setCaInitialized(res.initialized);
      setCaInfo(res.ca);
    } catch (err) {
      console.error('Failed to load CA status:', err);
    }
  };

  useEffect(() => {
    loadCA();

    const cleanupWs = connectWebSocket((msg) => {
      setWsConnected(true);
      if (msg.type === 'ca_update') {
        loadCA();
        setLiveBanner('Root CA state updated');
        setTimeout(() => setLiveBanner(null), 3000);
      } else if (msg.type === 'mtls_event') {
        const payload = msg.payload;
        setLiveBanner(`mTLS event: ${payload.success ? 'Accepted' : 'Rejected'} from ${payload.remoteAddr}`);
        setTimeout(() => setLiveBanner(null), 4000);
      }
    });

    return () => {
      cleanupWs();
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f0] flex flex-col selection:bg-blue-600/30">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        caInfo={caInfo}
        caInitialized={caInitialized}
        onRefreshCA={loadCA}
        wsConnected={wsConnected}
      />

      {/* Real-time Event Notification Toast */}
      {liveBanner && (
        <div className="fixed bottom-4 right-4 z-50 bg-[#11192e] border border-blue-500/50 text-blue-300 px-4 py-2 rounded-lg text-xs font-mono shadow-xl flex items-center space-x-2 animate-bounce">
          <Info className="w-4 h-4 text-blue-400" />
          <span>{liveBanner}</span>
        </div>
      )}

      {/* Main Workspace View */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'ca' && (
          <CaManager
            caInfo={caInfo}
            caInitialized={caInitialized}
            onRefreshCA={loadCA}
          />
        )}

        {activeTab === 'handshake' && (
          <HandshakeWaterfall />
        )}

        {activeTab === 'chain' && (
          <CertChainTree />
        )}

        {activeTab === 'mtls' && (
          <MtlsPlayground caCertPEM={caInfo?.certPath ? undefined : undefined} />
        )}

        {activeTab === 'audit' && (
          <SecurityAudit />
        )}

        {activeTab === 'configs' && (
          <ConfigGenerator />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1e293b] py-4 bg-[#090d16] text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <span className="text-slate-400 font-bold">TLSLens</span>
            <span>·</span>
            <span>Zero-Config Local Certificate Authority &amp; Handshake Profiler</span>
          </div>
          <div className="flex items-center space-x-4">
            <span>Go 1.23 crypto/tls</span>
            <span>·</span>
            <span>React 19 + Tailwind CSS</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
