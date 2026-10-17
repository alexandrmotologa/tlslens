import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  Unlock, 
  Play, 
  Square, 
  AlertTriangle, 
  CheckCircle2, 
  FileText, 
  Terminal, 
  RefreshCw, 
  Send,
  Loader2,
  HelpCircle,
  ShieldCheck,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { 
  ClientTestResult, 
  ConnectionEvent, 
  fetchMTLSStatus, 
  startMTLSServer, 
  stopMTLSServer, 
  testMTLSClient,
  simulateMTLSAlert,
  SimulationProbeResult
} from '../lib/api';

interface MtlsPlaygroundProps {
  caCertPEM?: string;
}

export const MtlsPlayground: React.FC<MtlsPlaygroundProps> = ({ caCertPEM }) => {
  // Server state
  const [serverRunning, setServerRunning] = useState(false);
  const [serverPort, setServerPort] = useState(9443);
  const [clientAuth, setClientAuth] = useState('require_and_verify');
  const [serverLoading, setServerLoading] = useState(false);
  const [events, setEvents] = useState<ConnectionEvent[]>([]);

  // Client test state
  const [targetUrl, setTargetUrl] = useState('https://127.0.0.1:9443');
  const [clientCertPEM, setClientCertPEM] = useState('');
  const [clientKeyPEM, setClientKeyPEM] = useState('');
  const [testScenario, setTestScenario] = useState<'valid' | 'nocert' | 'custom'>('nocert');
  const [clientLoading, setClientLoading] = useState(false);
  const [testResult, setTestResult] = useState<ClientTestResult | null>(null);

  // Alert simulation state
  const [simAlertCode, setSimAlertCode] = useState<number>(48);
  const [simLoading, setSimLoading] = useState<boolean>(false);
  const [simResult, setSimResult] = useState<SimulationProbeResult | null>(null);

  const loadStatus = async () => {
    try {
      const res = await fetchMTLSStatus();
      setServerRunning(res.running);
      if (res.port) setServerPort(res.port);
      if (res.events) setEvents(res.events);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleStartServer = async () => {
    setServerLoading(true);
    try {
      await startMTLSServer({
        port: serverPort,
        clientAuth,
        clientCaPem: caCertPEM,
      });
      await loadStatus();
    } catch (err) {
      console.error(err);
    } finally {
      setServerLoading(false);
    }
  };

  const handleStopServer = async () => {
    setServerLoading(true);
    try {
      await stopMTLSServer();
      await loadStatus();
    } catch (err) {
      console.error(err);
    } finally {
      setServerLoading(false);
    }
  };

  const handleRunClientTest = async () => {
    setClientLoading(true);
    try {
      const res = await testMTLSClient({
        targetUrl,
        clientCertPem: testScenario === 'nocert' ? undefined : clientCertPEM,
        clientKeyPem: testScenario === 'nocert' ? undefined : clientKeyPEM,
        insecureSkipVerify: true,
      });
      setTestResult(res);
      await loadStatus();
    } catch (err) {
      console.error(err);
    } finally {
      setClientLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Playground Header Banner */}
      <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Lock className="w-5 h-5 text-indigo-400" />
              <span>Interactive Mutual TLS (mTLS) Playground</span>
            </h2>
            <p className="text-xs text-slate-400">
              Run test mTLS server, trigger client validation rules, and troubleshoot raw TLS alert codes
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-medium border flex items-center space-x-1.5 ${
              serverRunning
                ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/50'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              <span className={`w-2 h-2 rounded-full ${serverRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
              <span>{serverRunning ? `Listening on :${serverPort}` : 'Server Offline'}</span>
            </span>

            {serverRunning ? (
              <button
                onClick={handleStopServer}
                disabled={serverLoading}
                className="px-3 py-1.5 bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 text-xs font-mono rounded-md flex items-center space-x-1.5 transition-colors disabled:opacity-50"
              >
                {serverLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Square className="w-3.5 h-3.5" />}
                <span>Stop Server</span>
              </button>
            ) : (
              <button
                onClick={handleStartServer}
                disabled={serverLoading}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono rounded-md shadow flex items-center space-x-1.5 transition-colors disabled:opacity-50"
              >
                {serverLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                <span>Start Server</span>
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Server Configuration & Event Log */}
        <div className="lg:col-span-5 space-y-6">
          {/* Server Config Card */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
            <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
              mTLS Server Policy Configuration
            </h3>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Client Authentication Policy</label>
                <select
                  value={clientAuth}
                  disabled={serverRunning}
                  onChange={(e) => setClientAuth(e.target.value)}
                  className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none disabled:opacity-60"
                >
                  <option value="require_and_verify">RequireAndVerifyClientCert (Strict mTLS)</option>
                  <option value="verify_if_given">VerifyClientCertIfGiven (Optional Verified)</option>
                  <option value="require_any">RequireAnyClientCert (Any Valid Cert)</option>
                  <option value="request">RequestClientCert (Request Only)</option>
                  <option value="none">NoClientCert (Standard HTTPS)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  Enforces how the server evaluates client certificates during the TLS handshake.
                </p>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Port</label>
                <input
                  type="number"
                  value={serverPort}
                  disabled={serverRunning}
                  onChange={(e) => setServerPort(parseInt(e.target.value) || 9443)}
                  className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none disabled:opacity-60"
                />
              </div>
            </div>
          </div>

          {/* Real-time Handshake Event Log */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#1e293b]/70">
              <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Connection Event Log ({events.length})
              </span>
              <button onClick={loadStatus} className="text-slate-400 hover:text-white p-1">
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            {events.length === 0 ? (
              <div className="text-center py-8 text-xs font-mono text-slate-500">
                No connection events recorded yet. Run a client test to observe handshake logs.
              </div>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {events.map((evt) => (
                  <div
                    key={evt.id}
                    className={`p-2.5 rounded-lg border text-xs font-mono transition-all ${
                      evt.success
                        ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                        : 'bg-red-950/20 border-red-800/40 text-red-300'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span>{evt.success ? 'ACCEPTED' : 'REJECTED'}</span>
                      <span className="text-[10px] text-slate-500">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="text-slate-300 mt-1">
                      Client CN: <span className="text-white">{evt.clientCommonName || '(None)'}</span>
                    </div>

                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {evt.remoteAddr} · {evt.tlsVersion} · {evt.cipherSuite}
                    </div>

                    {evt.error && (
                      <div className="text-[11px] text-red-400 mt-1 font-mono">
                        Error: {evt.error}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Client Probe Tester & Alert Diagnostics */}
        <div className="lg:col-span-7 space-y-6">
          {/* Client Probe Execution Card */}
          <div className="bg-[#0c1222] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
            <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
              Execute mTLS Client Test Probe
            </h3>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">Target Endpoint</label>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-[#11192e] border border-[#1e293b] rounded-md px-3 py-1.5 text-xs text-white font-mono focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1.5">Test Scenario</label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setTestScenario('nocert')}
                    className={`px-3 py-2 rounded-md text-xs font-mono border text-left transition-all ${
                      testScenario === 'nocert'
                        ? 'bg-amber-950/60 text-amber-300 border-amber-600'
                        : 'bg-[#11192e] text-slate-400 border-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <div className="font-bold">No Client Cert</div>
                    <div className="text-[10px] text-slate-400">Triggers Alert 42/41/116</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setTestScenario('custom')}
                    className={`px-3 py-2 rounded-md text-xs font-mono border text-left transition-all ${
                      testScenario === 'custom'
                        ? 'bg-blue-950/60 text-blue-300 border-blue-600'
                        : 'bg-[#11192e] text-slate-400 border-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <div className="font-bold">Paste Cert/Key</div>
                    <div className="text-[10px] text-slate-400">Custom PEM Keypair</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setTestScenario('valid')}
                    className={`px-3 py-2 rounded-md text-xs font-mono border text-left transition-all ${
                      testScenario === 'valid'
                        ? 'bg-emerald-950/60 text-emerald-300 border-emerald-600'
                        : 'bg-[#11192e] text-slate-400 border-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <div className="font-bold">Auto CA Cert</div>
                    <div className="text-[10px] text-slate-400">Valid Client Cert</div>
                  </button>
                </div>
              </div>

              {testScenario === 'custom' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">Client Certificate PEM</label>
                    <textarea
                      value={clientCertPEM}
                      onChange={(e) => setClientCertPEM(e.target.value)}
                      rows={4}
                      placeholder="-----BEGIN CERTIFICATE-----"
                      className="w-full bg-[#11192e] border border-[#1e293b] rounded p-2 text-[10px] font-mono text-slate-300 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-slate-400 mb-1">Client Private Key PEM</label>
                    <textarea
                      value={clientKeyPEM}
                      onChange={(e) => setClientKeyPEM(e.target.value)}
                      rows={4}
                      placeholder="-----BEGIN PRIVATE KEY-----"
                      className="w-full bg-[#11192e] border border-[#1e293b] rounded p-2 text-[10px] font-mono text-slate-300 focus:outline-none"
                    />
                  </div>
                </div>
              )}

              <button
                onClick={handleRunClientTest}
                disabled={clientLoading}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono rounded-md shadow flex items-center space-x-2 transition-colors disabled:opacity-50"
              >
                {clientLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                <span>Execute Handshake Probe</span>
              </button>
            </div>
          </div>

          {/* Diagnostic Report Result */}
          {testResult && (
            <div className={`p-5 rounded-xl border shadow-sm space-y-4 animate-fadeIn ${
              testResult.success
                ? 'bg-[#0a1820] border-emerald-800/60'
                : 'bg-[#180f1b] border-red-800/60'
            }`}>
              {/* Header result */}
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-white/10">
                <div className="flex items-center space-x-2.5">
                  {testResult.success ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 flex-shrink-0" />
                  ) : (
                    <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
                  )}
                  <div>
                    <div className="text-sm font-bold font-mono text-white">
                      {testResult.success
                        ? `Handshake Accepted (HTTP ${testResult.statusCode})`
                        : `Handshake Failed / Rejected`}
                    </div>
                    <div className="text-xs text-slate-400">
                      Duration: {testResult.durationMs.toFixed(2)} ms · {testResult.tlsVersion || 'TLS'}
                    </div>
                  </div>
                </div>

                {testResult.diagnostics.alertCode && (
                  <span className="px-3 py-1 rounded bg-red-950 text-red-300 border border-red-800 text-xs font-mono font-bold">
                    ALERT {testResult.diagnostics.alertCode}: {testResult.diagnostics.alertName?.toUpperCase()}
                  </span>
                )}
              </div>

              {/* Diagnosis Summary & Cause */}
              <div className="space-y-2 text-xs font-mono">
                <div className="text-slate-200 font-semibold">
                  {testResult.diagnostics.summary}
                </div>

                {testResult.diagnostics.probableCause && (
                  <div className="p-3 bg-black/40 rounded-lg border border-white/5 text-slate-300">
                    <span className="text-slate-500 block text-[10px] mb-1">PROBABLE ROOT CAUSE</span>
                    {testResult.diagnostics.probableCause}
                  </div>
                )}
              </div>

              {/* Remediation Steps */}
              {testResult.diagnostics.remediationSteps && testResult.diagnostics.remediationSteps.length > 0 && (
                <div className="space-y-1.5 text-xs font-mono">
                  <span className="text-slate-400 block text-[11px] font-semibold">REMEDIATION STEPS:</span>
                  <ul className="space-y-1 pl-4 list-disc text-slate-300">
                    {testResult.diagnostics.remediationSteps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Verification Tip */}
              {testResult.diagnostics.verificationTip && (
                <div className="text-[11px] font-mono text-indigo-300 bg-indigo-950/40 p-2.5 rounded border border-indigo-900/50">
                  Tip: {testResult.diagnostics.verificationTip}
                </div>
              )}

              {/* Certificate Audit Checks */}
              {testResult.diagnostics.certificateAudit && (
                <div className="pt-2 border-t border-white/10 space-y-2">
                  <span className="text-[11px] font-mono text-slate-400 block font-semibold">CLIENT CERTIFICATE AUDIT</span>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2 bg-black/30 rounded border border-white/5">
                      <span className="text-slate-500 text-[10px] block">Client Auth Extension</span>
                      <span className={testResult.diagnostics.certificateAudit.hasClientAuthExt ? 'text-emerald-400' : 'text-red-400'}>
                        {testResult.diagnostics.certificateAudit.hasClientAuthExt ? 'Present (Valid)' : 'Missing'}
                      </span>
                    </div>

                    <div className="p-2 bg-black/30 rounded border border-white/5">
                      <span className="text-slate-500 text-[10px] block">Digital Signature Usage</span>
                      <span className={testResult.diagnostics.certificateAudit.hasDigitalSig ? 'text-emerald-400' : 'text-red-400'}>
                        {testResult.diagnostics.certificateAudit.hasDigitalSig ? 'Present (Valid)' : 'Missing'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Interactive TLS Alert Simulator Studio */}
      <div className="p-5 rounded-xl bg-[#0c1222] border border-[#1e293b] shadow-sm space-y-4">
        <div>
          <h3 className="text-base font-semibold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <span>Interactive TLS Alert &amp; Failure Simulator</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Force standard RFC fatal alert records to test how client applications, microservices, and retry loops handle specific TLS alerts.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="sm:col-span-2">
            <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
              Select Fatal TLS Alert Code
            </label>
            <select
              value={simAlertCode}
              onChange={(e) => setSimAlertCode(Number(e.target.value))}
              className="w-full bg-[#11192e] border border-slate-700/80 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
            >
              <option value={40}>Alert 40: Handshake Failure (handshake_failure)</option>
              <option value={41}>Alert 41: No Certificate (no_certificate)</option>
              <option value={42}>Alert 42: Bad Certificate (bad_certificate)</option>
              <option value={45}>Alert 45: Certificate Expired (certificate_expired)</option>
              <option value={46}>Alert 46: Certificate Unknown (certificate_unknown)</option>
              <option value={48}>Alert 48: Unknown CA / Authority (unknown_ca)</option>
              <option value={112}>Alert 112: Unrecognized Name / SNI Mismatch (unrecognized_name)</option>
              <option value={116}>Alert 116: Certificate Required (certificate_required)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={async () => {
                setSimLoading(true);
                try {
                  const res = await simulateMTLSAlert(simAlertCode);
                  setSimResult(res);
                } catch (err) {
                  console.error(err);
                } finally {
                  setSimLoading(false);
                }
              }}
              disabled={simLoading}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-medium transition shadow-md shadow-amber-600/20"
            >
              {simLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{simLoading ? 'Simulating Alert...' : 'Simulate & Probe Alert'}</span>
            </button>
          </div>
        </div>

        {simResult && (
          <div className="p-4 rounded-lg bg-[#11192e] border border-amber-800/40 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <span className="text-amber-400 font-bold">
                SIMULATED ALERT {simResult.alertCode}: {simResult.alertName.toUpperCase()}
              </span>
              <span className="text-[11px] text-slate-400">
                Raw Frame: <code className="text-blue-300 font-mono bg-black/40 px-1.5 py-0.5 rounded">{simResult.rawHex}</code>
              </span>
            </div>

            <div>
              <span className="text-[11px] text-slate-500 block mb-0.5">CLIENT-SIDE ERROR STRING</span>
              <p className="text-rose-300 bg-rose-950/40 p-2 rounded border border-rose-900/50 break-all">
                {simResult.clientError || 'Handshake terminated by remote alert'}
              </p>
            </div>

            <div>
              <span className="text-[11px] text-slate-500 block mb-0.5">ROOT CAUSE SUMMARY</span>
              <p className="text-slate-200">{simResult.diagnostics.summary}</p>
            </div>

            {simResult.diagnostics.remediationSteps && simResult.diagnostics.remediationSteps.length > 0 && (
              <div className="space-y-1">
                <span className="text-[11px] text-slate-500 block">REMEDIATION GUIDANCE</span>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-300 text-[11px]">
                  {simResult.diagnostics.remediationSteps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
