# TLSLens: Master Implementation Plan

> Local Certificate Authority, mTLS Playground, and TLS Handshake Inspector with PKI Visualizer.
>
> Developer diagnostics and PKI workbench in Go 1.23 and React 19. Generates trusted local root CAs with 1 click, inspects remote and local X.509 certificate chains, troubleshoots mutual TLS (mTLS) client authentication failures with alert codes, and visualizes TLS 1.3 and 1.2 handshake timelines.

---

## 1. Project Overview and Architecture

Modern cloud engineering, Kubernetes ingress controllers, Envoy proxies, and microservices rely on strict HTTPS and mutual TLS (mTLS). Engineers frequently hit friction with:
1. Self-signed certificate friction: browser warnings, OpenSSL configuration complexity, missing Subject Alternative Names (SANs), and manual trust store installation.
2. Opaque mTLS failures: handshakes failing with generic `bad_certificate` or `unknown_ca` alert codes without actionable diagnostics.
3. Handshake latency overhead: inability to isolate latency bottlenecks across TCP SYN/ACK, TLS ClientHello, server certificate validation, and key exchange.
4. Certificate expiration and chain drift: multi-tier intermediate certificate chain mismatches, outdated cipher suites, and invalid key usage extensions (`digitalSignature`, `keyEncipherment`).

TLSLens delivers a single-binary PKI engine and visual studio:
- Zero-config local CA: generates root and intermediate CAs, with automated registration in OS root stores (Windows CertStore, macOS Keychain, Linux ca-certificates).
- Wildcard certificate issuer: issues SAN certificates (`*.local.test`, `localhost`, `127.0.0.1`) with configurable key types (ECDSA P-256, Ed25519, RSA 2048/4096).
- Interactive mTLS playground: runs an embedded mTLS test server and client probe to test bidirectional authentication and diagnose alert codes.
- Handshake waterfall profiler: measures sub-millisecond timings across each stage of TLS 1.3 and 1.2 handshakes.
- X.509 visual hierarchy inspector: provides an interactive certificate chain tree, expiration status, key usage flags, and OCSP/CRL revocation verification.
- Security and cipher strength auditor: evaluates cipher suites, forward secrecy, key sizes, and assigns security grades (A+ to F).
- Reverse proxy and client config generator: generates ready-to-use configuration files for Nginx, Caddy, Envoy, Apache, Docker, cURL, Go, Node.js, and Python.

```
+-----------------------------------------------------------------------------------+
|                                      TLSLENS                                      |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|     Local CA & Cert Issuer      |                 |    TLS Handshake Profiler     |
|  * Ephemeral & Root CA Init     |                 |  * TLS 1.3 & 1.2 Record Probe |
|  * OS Root Store Registration   |                 |  * TCP vs Handshake Latency   |
|  * ECDSA P-256 / RSA 2048/4096  |                 |  * ALPN (h2, http/1.1, h3)    |
+-------+-------------------------+                 +-----------------------+-------+
        |                                                                   |
        +---------------------------------+---------------------------------+
                                          |
                        +-----------------v-----------------+
                        |     mTLS Playground & Tester      |
                        |  * Bidirectional Auth Probe       |
                        |  * Client Cert / Key Validator    |
                        |  * Handshake Alert Diagnosis      |
                        +-----------------+-----------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|   Security & Cipher Auditor     |                 |   Config & Snippet Studio     |
|  * Cipher grading (A+ to F)     |                 |  * Nginx, Caddy, Envoy, cURL  |
|  * Weak ciphers & PFS check     |                 |  * Docker, Go, Node, Python   |
+-------+-------------------------+                 +-----------------------+-------+
                                          |
                        +-----------------v-----------------+
                        |   Embedded Studio & REST API      |
                        |  * Visual X.509 Chain Hierarchy   |
                        |  * Handshake Gantt Waterfall      |
                        |  * 1-Click PEM / P12 Export       |
                        |  * Live WebSocket Event Stream    |
                        +-----------------------------------+
```

---

## 2. Directory Structure

```
tlslens/
├── cmd/
│   └── tlslens/
│       └── main.go                 # Unified CLI and daemon entrypoint
├── internal/
│   ├── ca/
│   │   ├── ca.go                   # Root and intermediate CA generator
│   │   ├── truststore_windows.go   # Windows certutil integration
│   │   ├── truststore_darwin.go    # macOS security CLI integration
│   │   ├── truststore_linux.go     # Linux ca-certificates / update-ca-trust
│   │   ├── truststore_stub.go      # Fallback stub for other OSes
│   │   └── cert_issuer.go          # Leaf certificate issuance with SANs and P12
│   ├── inspector/
│   │   ├── chain_parser.go         # X.509 ASN.1 certificate chain parser
│   │   ├── extensions.go           # KeyUsage, ExtKeyUsage, SAN, BasicConstraints
│   │   └── revocation.go           # OCSP probe and CRL fetcher & validator
│   ├── handshake/
│   │   ├── probe.go                # Custom dialer and sub-millisecond stage timer
│   │   ├── timeline.go             # Handshake timeline data structures
│   │   ├── alpn.go                 # ALPN protocol negotiation inspector
│   │   └── ciphers.go              # Cipher suite registry and metadata
│   ├── mtls/
│   │   ├── mock_server.go          # Configurable in-memory mTLS test server
│   │   ├── test_client.go          # Configurable mTLS client probe
│   │   └── diagnostics.go          # Root cause analyzer for TLS alert codes
│   ├── audit/
│   │   └── auditor.go              # TLS security grader (A+ to F) and cipher evaluator
│   ├── configs/
│   │   └── generator.go            # Nginx, Caddy, Envoy, Docker, curl, Go, Node snippets
│   └── server/
│       ├── http_server.go          # REST API router and static file server
│       ├── handlers.go             # HTTP handlers for CA, probe, mTLS, and audit
│       └── websocket.go            # Live event stream broadcaster
├── web/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx          # App header with CA trust status indicator
│   │   │   ├── CertChainTree.tsx   # Interactive SVG certificate hierarchy
│   │   │   ├── HandshakeWaterfall.tsx # Timeline waterfall of TLS records
│   │   │   ├── MtlsPlayground.tsx  # Interactive client/server mTLS test panel
│   │   │   ├── CaManager.tsx       # Root CA generator, trust toggle, and leaf issuer
│   │   │   ├── SecurityAudit.tsx   # Security grading and cipher score card
│   │   │   ├── ConfigGenerator.tsx # Reverse proxy and runtime config snippet viewer
│   │   │   └── AlertBadge.tsx      # TLS alert badge with diagnostic explanation
│   │   ├── lib/
│   │   │   ├── api.ts              # Typed API client for TLSLens backend
│   │   │   └── utils.ts            # Formatting utilities and timing calculations
│   │   ├── App.tsx                 # Tab navigation and active view controller
│   │   ├── index.css               # Tailwind CSS and Cerulean tokens
│   │   └── main.tsx                # React 19 entrypoint
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── index.html
├── docs/
│   ├── images/                     # UI screenshots and demo recording
│   └── architecture.md             # In-depth architectural documentation
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

---

## 3. Detailed Implementation Roadmap

### Phase 1: Core PKI Engine and Local Trust Store Automation
- [x] Task 1.1: Go module setup (`github.com/alexandrmotologa/tlslens`) with Go 1.23 compatibility.
- [x] Task 1.2: Root CA generation in `internal/ca/ca.go`:
  - ECDSA P-256 (default), Ed25519, and RSA 2048/4096 key support.
  - Proper X.509 v3 fields: `IsCA: true`, `BasicConstraintsValid: true`, `KeyUsage: KeyUsageCertSign | KeyUsageCRLSign`.
  - Serial number generation with cryptographically secure random integers.
  - PEM encoding for certificate and private key with automatic storage in standard path.
- [x] Task 1.3: Leaf certificate issuer in `internal/ca/cert_issuer.go`:
  - Configurable SANs (DNS names, IPv4, IPv6).
  - Configurable validity periods (1 day to 365 days).
  - Appropriate key usage: `KeyUsageDigitalSignature | KeyUsageKeyEncipherment`, `ExtKeyUsageServerAuth`, `ExtKeyUsageClientAuth`.
  - Export to PEM, PKCS#12 (.p12) with password protection, and combined bundles.
- [x] Task 1.4: Cross-platform OS trust store installer:
  - Windows (`internal/ca/truststore_windows.go`): `certutil.exe -addstore -f "ROOT"` and `-delstore "ROOT"`, plus verification query.
  - macOS (`internal/ca/truststore_darwin.go`): `security add-trusted-cert` and `security remove-trusted-cert`.
  - Linux (`internal/ca/truststore_linux.go`): `/usr/local/share/ca-certificates/` and `/etc/pki/ca-trust/source/anchors/` with `update-ca-certificates` or `update-ca-trust`.
  - Trust store status detector returning whether the root certificate is currently trusted by the OS.

### Phase 2: TLS Handshake Profiler and X.509 Chain Inspector
- [x] Task 2.1: TLS handshake dialer and timeline profiler in `internal/handshake/probe.go`:
  - Measure DNS resolution duration (`t_dns`).
  - Measure TCP 3-way handshake roundtrip time (`t_tcp`).
  - Measure TLS ClientHello to ServerHello latency (`t_server_hello`).
  - Measure certificate transfer and validation time (`t_cert_validation`).
  - Measure key exchange and handshake completion (`t_handshake_finish`).
  - Record TLS version (TLS 1.3, TLS 1.2), cipher suite, ALPN protocol (`h2`, `http/1.1`, `h3`), SNI, and session ticket status.
- [x] Task 2.2: X.509 certificate chain parser in `internal/inspector/chain_parser.go`:
  - Traverse full chain: Leaf -> Intermediate(s) -> Root.
  - Extract SANs (DNS, IP, URI), KeyUsage, ExtendedKeyUsage, AuthorityKeyIdentifier, SubjectKeyIdentifier.
  - Expiration calculations: NotBefore, NotAfter, days remaining, expiration status flags.
  - SHA-256 and SHA-1 fingerprints.
- [x] Task 2.3: Revocation inspector in `internal/inspector/revocation.go`:
  - OCSP stapling verification from handshake response.
  - Direct OCSP responder HTTP probe when URLs exist in Authority Information Access (AIA).
  - CRL distribution point parser and HTTP fetcher.

### Phase 3: Interactive mTLS Playground and Alert Diagnostics Engine
- [x] Task 3.1: Configurable mTLS test server in `internal/mtls/mock_server.go`:
  - In-memory TLS listener with dynamic port allocation or fixed port.
  - Configurable client authentication policy:
    - `RequireAndVerifyClientCert`
    - `VerifyClientCertIfGiven`
    - `RequireAnyClientCert`
    - `RequestClientCert`
    - `NoClientCert`
  - Dynamic client CA certificate pool updates.
  - Connection event logger capturing client certificate details and handshake outcomes.
- [x] Task 3.2: Configurable mTLS client probe in `internal/mtls/test_client.go`:
  - Connects to arbitrary targets or local test server with specified client cert and key.
  - Captures exact TLS alert codes and connection errors.
- [x] Task 3.3: TLS alert diagnostics analyzer in `internal/mtls/diagnostics.go`:
  - Map alert codes to root causes and concrete remediation instructions:
    - Alert 42 (`bad_certificate`): malformed certificate, signature failure, or invalid ASN.1.
    - Alert 46 (`certificate_unknown`): client certificate not signed by trusted CA.
    - Alert 45 (`certificate_expired`): validity date outside current time window.
    - Alert 40 (`handshake_failure`): incompatible cipher suites or protocol versions.
    - Alert 48 (`unknown_ca`): root or intermediate CA not in server trust store.
    - Alert 112 (`unrecognized_name`): SNI mismatch with server configuration.

### Phase 4: Security Auditor and Configuration Snippet Studio
- [x] Task 4.1: Security and cipher strength auditor in `internal/audit/auditor.go`:
  - Probe target endpoint for supported TLS versions and cipher suites.
  - Check for weak ciphers (CBC mode, 3DES, RC4), lack of forward secrecy (non-ECDHE), small key sizes (< 2048-bit RSA), and SHA-1 signatures.
  - Assign overall security grade (A+, A, B, C, F) with specific risk items.
- [x] Task 4.2: Reverse proxy and runtime config generator in `internal/configs/generator.go`:
  - Produce validated configuration blocks for Nginx, Caddy, Envoy, Apache, Docker Compose, cURL commands, Go `tls.Config`, Node.js `https.createServer`, and Python `ssl.SSLContext`.
  - Include environment variables for local trust (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`).

### Phase 5: REST API, WebSocket Stream, and CLI Engine
- [x] Task 5.1: REST API server in `internal/server/`:
  - `/api/ca/status`, `/api/ca/init`, `/api/ca/trust`, `/api/ca/untrust`, `/api/ca/issue`
  - `/api/probe` (handshake timeline, chain details, OCSP)
  - `/api/mtls/server/start`, `/api/mtls/server/stop`, `/api/mtls/server/status`, `/api/mtls/test`
  - `/api/audit`
  - `/api/configs`
  - `/ws/events` live event streaming for probes and mTLS events.
- [x] Task 5.2: CLI commands in `cmd/tlslens/main.go`:
  - `tlslens serve [--port 8080] [--dev]`
  - `tlslens ca init [--key-type ecdsa|rsa]`
  - `tlslens ca trust` / `tlslens ca untrust`
  - `tlslens cert issue --domains localhost,api.test --ips 127.0.0.1`
  - `tlslens inspect <host:port>`
  - `tlslens mtls test --target <host:port> --cert <path> --key <path>`
  - `tlslens audit <host:port>`

### Phase 6: Embedded React 19 Web Studio
- [x] Task 6.1: React 19 + TypeScript + Vite + Tailwind CSS scaffolding with Cerulean design kit tokens (near-black background, steel-blue accents, monospace telemetry typography).
- [x] Task 6.2: App shell and header with live OS trust status badge, quick actions, and tab navigation.
- [x] Task 6.3: CA Manager tab:
  - 1-click root CA generation with key type selector.
  - OS trust installation and removal button with status indicator.
  - Leaf certificate issuance form with live DNS/IP tag inputs.
  - Download buttons for PEM, Key, and PKCS#12 (.p12).
- [x] Task 6.4: Handshake Profiler tab:
  - Target input field (`host:port`) with preset chips (`google.com:443`, `cloudflare.com:443`, `localhost:9443`).
  - Interactive Gantt waterfall chart visualizing TCP connect, TLS ClientHello, ServerHello, Certificate Validation, and Key Exchange.
  - Summary metrics: total handshake time, TLS version, cipher suite, ALPN, session resumption.
- [x] Task 6.5: Certificate Chain Inspector tab:
  - Hierarchical visual tree displaying Leaf -> Intermediate -> Root.
  - Node inspection card showing Subject, Issuer, Validity countdown, SAN list, Key Usage flags, and SHA-256 fingerprint.
  - Real-time OCSP and CRL status pill.
- [x] Task 6.6: mTLS Playground tab:
  - In-browser test server controls (toggle server, set client auth policy, select trusted CA).
  - Client probe executor with custom certificate / key upload or 1-click selection from issued certs.
  - Real-time handshake log with TLS alert decoding, root cause analysis, and remediation cards.
- [x] Task 6.7: Security Audit tab:
  - Security grade badge (A+ to F), protocol matrix, cipher scorecard, and vulnerability notices.
- [x] Task 6.8: Config Generator tab:
  - Filterable tabs for Nginx, Caddy, Envoy, cURL, Docker, Go, Node.js, and Python.
  - 1-click copy with instant visual confirmation.

### Phase 7: Verification Suite, Visual Assets, and Release
- [x] Task 7.1: Go unit and integration tests:
  - CA generation, SAN issuance, and key encoding tests.
  - Trust store installer mocking and status checks.
  - Handshake probe timing verification.
  - mTLS failure scenarios (expired cert, unknown CA, mismatched key).
- [x] Task 7.2: Single-binary embedding:
  - Build web assets with Vite.
  - Embed assets in Go binary using `//go:embed`.
  - Verify standalone binary runs without Node.js or external dependencies.
- [x] Task 7.3: Visual documentation and demo generation:
  - Capture real UI screenshots of all tabs.
  - Record animated demo GIF (`docs/images/tlslens_demo.gif`).
  - Write humanized `README.md` embedding demo GIF and screenshots.
- [x] Task 7.4: Portfolio sync Phase 2:
  - Copy screenshots and demo GIF to `mtlg-site` and `mtlglabs-space`.
  - Update `projects.json` with LIVE badges, finalized humanized copy, and image lists.
  - Run sync scripts, commit, and push.
  - Run `broadcast_x.js` preview.
