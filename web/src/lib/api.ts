export interface CACredentialsInfo {
  commonName: string;
  organization: string;
  country: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: int;
  keyType: string;
  keyLength: number;
  signatureAlgorithm: string;
  fingerprintSHA256: string;
  fingerprintSHA1: string;
  certPath: string;
  keyPath: string;
  isTrustedByOS: boolean;
  storageDir: string;
}

export type int = number;

export interface CAStatusResponse {
  initialized: boolean;
  storageDir?: string;
  ca?: CACredentialsInfo;
}

export interface IssueCertRequest {
  commonName?: string;
  domains: string[];
  ips: string[];
  validityDays: number;
  keyType: string;
  organization?: string;
  p12Password?: string;
}

export interface IssuedCertResponse {
  success: boolean;
  commonName: string;
  dnsNames: string[];
  ipAddresses: string[];
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  fingerprintSHA256: string;
  certPEM: string;
  keyPEM: string;
  bundlePEM: string;
  p12Base64?: string;
}

export interface TimingStage {
  name: string;
  category: 'dns' | 'tcp' | 'tls_hello' | 'tls_cert' | 'tls_finish';
  startOffsetMs: number;
  durationMs: number;
  description: string;
}

export interface LintFinding {
  code: string;
  severity: 'error' | 'warning' | 'info';
  title: string;
  message: string;
  standard: string;
  remediation: string;
}

export interface LintResult {
  subject: string;
  commonName: string;
  isCA: boolean;
  status: 'pass' | 'warning' | 'fail';
  errorCount: number;
  warningCount: number;
  infoCount: number;
  findings: LintFinding[];
}

export interface CertSummary {
  commonName: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  daysRemaining: number;
  isExpired: boolean;
  expiresSoon: boolean;
  dnsNames: string[];
  ipAddresses: string[];
  keyType: string;
  keyLength: number;
  signatureAlgorithm: string;
  fingerprintSHA256: string;
  isCA: boolean;
  keyUsage?: string[];
  extKeyUsage?: string[];
  ocspServers?: string[];
  crlDistribution?: string[];
  lint?: LintResult;
}

export interface CipherInfo {
  id: number;
  hex: string;
  name: string;
  protocol: string;
  keyExchange: string;
  encryption: string;
  isPfs: boolean;
  securityStatus: 'recommended' | 'secure' | 'weak' | 'insecure';
}

export interface ProbeResult {
  target: string;
  host: string;
  port: string;
  resolvedIp: string;
  tlsVersion: string;
  tlsVersionId: number;
  cipher: CipherInfo;
  alpn: string;
  serverName: string;
  didResume: boolean;
  ocspStapled: boolean;
  timings: TimingStage[];
  totalDurationMs: number;
  peerCertificates: CertSummary[];
  verifiedChainCount: number;
  error?: string;
}

export interface ChainHierarchy {
  leaf: CertSummary;
  intermediates: CertSummary[];
  root?: CertSummary;
  chainLength: number;
  isValid: boolean;
  validationError?: string;
}

export interface ConnectionEvent {
  id: string;
  timestamp: string;
  remoteAddr: string;
  clientCertPresented: boolean;
  clientCommonName: string;
  clientIssuer: string;
  clientSerialNumber: string;
  tlsVersion: string;
  cipherSuite: string;
  success: boolean;
  error?: string;
  diagnosis?: string;
}

export interface MTLSStatusResponse {
  running: boolean;
  port: number;
  events: ConnectionEvent[];
}

export interface DiagnosticReport {
  originalError: string;
  alertCode?: number;
  alertName?: string;
  summary: string;
  probableCause: string;
  remediationSteps: string[];
  verificationTip: string;
  certificateAudit?: {
    hasClientCert: boolean;
    commonName: string;
    isExpired: boolean;
    notBefore: string;
    notAfter: string;
    hasClientAuthExt: boolean;
    hasDigitalSig: boolean;
    issuerMatchesCa: boolean;
    auditFindings: string[];
  };
}

export interface ClientTestResult {
  success: boolean;
  statusCode?: number;
  responseBody?: string;
  tlsVersion?: string;
  cipherSuite?: string;
  peerCertificates?: CertSummary[];
  diagnostics: DiagnosticReport;
  durationMs: number;
}

export interface AuditRiskItem {
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  remediation: string;
}

export interface ProtocolCheck {
  version: string;
  allowed: boolean;
  secure: boolean;
}

export interface AuditResult {
  target: string;
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
  protocols: ProtocolCheck[];
  supportedCiphers: CipherInfo[];
  hasPfs: boolean;
  hasTls13: boolean;
  hasDeprecatedTls: boolean;
  hasWeakCiphers: boolean;
  certificateValid: boolean;
  risks: AuditRiskItem[];
  durationMs: number;
}

export interface ConfigSnippet {
  id: string;
  title: string;
  category: string;
  language: string;
  description: string;
  code: string;
}

const API_BASE = '/api';

export async function fetchCAStatus(): Promise<CAStatusResponse> {
  const res = await fetch(`${API_BASE}/ca/status`);
  return res.json();
}

export async function initCA(data: { commonName?: string; organization?: string; validityDays?: number; keyType?: string }): Promise<{ success: boolean; ca: CACredentialsInfo }> {
  const res = await fetch(`${API_BASE}/ca/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function trustCA(): Promise<{ success: boolean; isTrusted: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/ca/trust`, { method: 'POST' });
  return res.json();
}

export async function untrustCA(): Promise<{ success: boolean; isTrusted: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/ca/untrust`, { method: 'POST' });
  return res.json();
}

export async function issueCertificate(req: IssueCertRequest): Promise<IssuedCertResponse> {
  const res = await fetch(`${API_BASE}/ca/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  return res.json();
}

export async function probeEndpoint(target: string, serverName?: string, insecureSkipVerify = true): Promise<ProbeResult> {
  const res = await fetch(`${API_BASE}/probe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, serverName, insecureSkipVerify }),
  });
  return res.json();
}

export async function inspectChain(pemData?: string, target?: string): Promise<ChainHierarchy> {
  const res = await fetch(`${API_BASE}/inspect/chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pemData, target }),
  });
  return res.json();
}

export async function fetchMTLSStatus(): Promise<MTLSStatusResponse> {
  const res = await fetch(`${API_BASE}/mtls/status`);
  return res.json();
}

export async function startMTLSServer(data: { port?: number; clientAuth?: string; serverCertPem?: string; serverKeyPem?: string; clientCaPem?: string }) {
  const res = await fetch(`${API_BASE}/mtls/server/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function stopMTLSServer() {
  const res = await fetch(`${API_BASE}/mtls/server/stop`, { method: 'POST' });
  return res.json();
}

export async function testMTLSClient(data: {
  targetUrl: string;
  rootCaPem?: string;
  clientCertPem?: string;
  clientKeyPem?: string;
  insecureSkipVerify?: boolean;
}): Promise<ClientTestResult> {
  const res = await fetch(`${API_BASE}/mtls/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function runSecurityAudit(target: string): Promise<AuditResult> {
  const res = await fetch(`${API_BASE}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  return res.json();
}

export async function fetchConfigSnippets(params?: {
  certPath?: string;
  keyPath?: string;
  caPath?: string;
  domain?: string;
  port?: number;
  backendAddr?: string;
}): Promise<{ snippets: ConfigSnippet[] }> {
  const res = await fetch(`${API_BASE}/configs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  });
  return res.json();
}

export function connectWebSocket(onMessage: (msg: { type: string; payload: any }) => void): () => void {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/events`;
  let ws: WebSocket | null = null;
  let timer: any = null;

  function connect() {
    try {
      ws = new WebSocket(wsUrl);
      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          onMessage(parsed);
        } catch {}
      };
      ws.onclose = () => {
        timer = setTimeout(connect, 3000);
      };
    } catch {
      timer = setTimeout(connect, 3000);
    }
  }

  connect();

  return () => {
    if (timer) clearTimeout(timer);
    if (ws) ws.close();
  };
}

// ---------------- Expanded Features API ----------------

export interface FieldDiff {
  field: string;
  valueA: string;
  valueB: string;
  isDifferent: boolean;
  significance: 'match' | 'info' | 'warning' | 'divergence';
}

export interface DiffResult {
  targetA: string;
  targetB: string;
  probeA: ProbeResult;
  probeB: ProbeResult;
  hierarchyA?: ChainHierarchy;
  hierarchyB?: ChainHierarchy;
  latencyDiffMs: number;
  fasterTarget: 'A' | 'B' | 'equal';
  totalDiffCount: number;
  protocolMatch: boolean;
  cipherMatch: boolean;
  alpnMatch: boolean;
  issuerMatch: boolean;
  differences: FieldDiff[];
}

export async function runDiff(targetA: string, targetB: string): Promise<DiffResult> {
  const res = await fetch(`${API_BASE}/diff`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetA, targetB }),
  });
  return res.json();
}

export interface ClientProfile {
  id: string;
  name: string;
  category: 'Browser' | 'Mobile' | 'Enterprise' | 'CLI';
  description: string;
  minVersion: number;
  maxVersion: number;
  ciphers: number[];
  alpn: string[];
}

export interface ClientProbeResult {
  profile: ClientProfile;
  success: boolean;
  negotiatedProtocol: string;
  negotiatedCipher: string;
  isPfs: boolean;
  alpn: string;
  latencyMs: number;
  error?: string;
}

export interface MatrixReport {
  target: string;
  host: string;
  port: string;
  timestamp: string;
  totalProfiles: number;
  successfulProfiles: number;
  failedProfiles: number;
  results: ClientProbeResult[];
}

export async function runMatrix(target: string): Promise<MatrixReport> {
  const res = await fetch(`${API_BASE}/matrix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  return res.json();
}

export async function runLinter(params: { target?: string; pemData?: string }): Promise<LintResult> {
  const res = await fetch(`${API_BASE}/linter`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return res.json();
}

export interface ManifestBundle {
  tlsSecret: string;
  caConfigMap: string;
  certManagerIssuer: string;
  ingress: string;
  allInOne: string;
  kubectlCommand: string;
}

export async function generateK8s(params: {
  name?: string;
  namespace?: string;
  certPem?: string;
  keyPem?: string;
  caPem?: string;
  domains?: string[];
  serviceName?: string;
  servicePort?: number;
}): Promise<ManifestBundle> {
  const res = await fetch(`${API_BASE}/k8s/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return res.json();
}

export interface SimulationProbeResult {
  alertCode: number;
  alertName: string;
  clientError: string;
  detectedAlert: number;
  diagnostics: DiagnosticReport;
  rawHex: string;
}

export async function simulateMTLSAlert(alertCode: number): Promise<SimulationProbeResult> {
  const res = await fetch(`${API_BASE}/mtls/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alertCode }),
  });
  return res.json();
}

export interface MonitoredDomain {
  id: string;
  target: string;
  host: string;
  port: string;
  intervalSeconds: number;
  status: 'healthy' | 'expiring_soon' | 'expired' | 'unreachable';
  commonName: string;
  issuer: string;
  daysRemaining: number;
  expiresAt: string;
  fingerprintSHA256: string;
  tlsVersion: string;
  cipherSuite: string;
  latencyMs: number;
  lastChecked: string;
  lastError?: string;
  addedAt: string;
}

export async function fetchWatcherDomains(): Promise<MonitoredDomain[]> {
  const res = await fetch(`${API_BASE}/watcher`);
  return res.json();
}

export async function addWatcherDomain(target: string, intervalSeconds: number = 300): Promise<MonitoredDomain> {
  const res = await fetch(`${API_BASE}/watcher`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, intervalSeconds }),
  });
  return res.json();
}

export async function deleteWatcherDomain(id: string): Promise<{ success: boolean; id: string }> {
  const res = await fetch(`${API_BASE}/watcher/${id}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function checkWatcherDomain(id: string): Promise<MonitoredDomain> {
  const res = await fetch(`${API_BASE}/watcher/${id}/check`, {
    method: 'POST',
  });
  return res.json();
}

export interface AcmeOrder {
  id: string;
  status: string;
  expires: string;
  identifiers: { type: string; value: string }[];
  finalize: string;
  certificate?: string;
  createdAt: string;
  domains: string[];
}

export interface AcmeStatusReport {
  directoryUrl: string;
  totalAccounts: number;
  totalOrders: number;
  totalCertificates: number;
  recentOrders: AcmeOrder[];
}

export async function fetchAcmeStatus(): Promise<AcmeStatusReport> {
  const res = await fetch(`${API_BASE}/acme/status`);
  return res.json();
}

