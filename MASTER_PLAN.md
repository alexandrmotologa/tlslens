# TLSLens: Master Implementation Plan

> Local Certificate Authority, mTLS Playground, and TLS Handshake Inspector with PKI Visualizer.
>
> Developer diagnostics and PKI workbench in Go 1.23 and React 19. Generates trusted local root CAs with 1 click, inspects remote and local X.509 certificate chains, troubleshoots mutual TLS (mTLS) client authentication failures with alert codes, simulates real-world client handshakes, audits CAB Forum compliance rules, and visualizes TLS 1.3 and 1.2 handshake timelines.

---

## 1. Project Overview and Architecture

Modern cloud engineering, Kubernetes ingress controllers, Envoy proxies, and microservices rely on strict HTTPS and mutual TLS (mTLS). Engineers frequently hit friction with:
1. Self-signed certificate friction: browser warnings, OpenSSL configuration complexity, missing Subject Alternative Names (SANs), and manual trust store installation.
2. Opaque mTLS failures: handshakes failing with generic `bad_certificate` or `unknown_ca` alert codes without actionable diagnostics.
3. Handshake latency overhead: inability to isolate latency bottlenecks across TCP SYN/ACK, TLS ClientHello, server certificate validation, and key exchange.
4. Certificate expiration and chain drift: multi-tier intermediate certificate chain mismatches, outdated cipher suites, and invalid key usage extensions (`digitalSignature`, `keyEncipherment`).
5. Client compatibility blindspots: lack of clarity on whether legacy clients (Android 7, Java 8, OpenSSL 1.0.2) or modern clients (iOS 17, Chrome 130) will negotiate successfully.

TLSLens delivers a single-binary PKI engine and visual studio:
- **Zero-config local CA**: generates root and intermediate CAs, with automated registration in OS root stores (Windows CertStore, macOS Keychain, Linux ca-certificates).
- **Wildcard certificate issuer**: issues SAN certificates (`*.local.test`, `localhost`, `127.0.0.1`) with configurable key types (ECDSA P-256, Ed25519, RSA 2048/4096).
- **Embedded RFC 8555 ACME Server**: provides a local ACME directory (`/acme/directory`) for automated issuance to Caddy, Traefik, Certbot, and cert-manager without external rate limits.
- **Side-by-Side TLS & Certificate Diff**: runs concurrent dual-host handshakes to highlight differences in ciphers, SANs, chain depth, and stage latencies.
- **X.509 Compliance & CAB Forum Linter**: evaluates certificates against CAB Forum Baseline Requirements and RFC 5280 constraints, flagging key sizes, SAN deprecation, and lifespan limits.
- **Client Compatibility Matrix Scanner**: probes targets against real-world client configurations (Android, iOS, Chrome, Firefox, Java, OpenSSL) to evaluate protocol negotiation.
- **Interactive mTLS Playground & Alert Simulator**: runs an in-memory mTLS server with configurable client authentication policies and simulates fatal TLS alerts (40, 42, 45, 46, 48, 112, 116).
- **Handshake Waterfall Profiler**: measures sub-millisecond breakdowns across DNS resolution, TCP SYN/ACK, ClientHello, ServerHello, Certificate Validation, and Key Exchange.
- **Continuous Domain Watcher**: tracks expiration dates and certificate fingerprints in the background, broadcasting WebSocket alerts before expiration.
- **Kubernetes Native Export Studio**: generates kubernetes.io/tls Secrets, CA ConfigMaps, cert-manager ClusterIssuers, and Ingress TLS definitions.
- **Security & Cipher Strength Auditor**: grades target endpoints (A+ to F) evaluating forward secrecy (PFS), cipher algorithms, key sizes, and protocol versions.
- **Reverse Proxy & Client Config Studio**: generates validated configuration snippets for Nginx, Caddy, Envoy, Apache, Docker, cURL, Go, Node.js, and Python.

```
+-----------------------------------------------------------------------------------+
|                                      TLSLENS                                      |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|     Local CA & ACME Server      |                 |    TLS Handshake Profiler     |
|  * Ephemeral & Root CA Init     |                 |  * TLS 1.3 & 1.2 Record Probe |
|  * OS Root Store Registration   |                 |  * TCP vs Handshake Latency   |
|  * RFC 8555 ACME Directory      |                 |  * ALPN (h2, http/1.1, h3)    |
+-------+-------------------------+                 +-----------------------+-------+
        |                                                                   |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
+-------v-------------------------+       |         +-----------------------v-------+
|    Side-by-Side TLS Diff        |       |         |   Client Matrix Scanner       |
|  * Concurrent Target A vs B     |       |         |  * Android, iOS, Chrome, Java |
|  * Cipher & SAN Differences     |       |         |  * OpenSSL compatibility      |
+-------+-------------------------+       |         +-----------------------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                        +-----------------v-----------------+
                        |     mTLS Playground & Tester      |
                        |  * Bidirectional Auth Probe       |
                        |  * Alert Simulator (40, 42, 48)   |
                        |  * Handshake Alert Diagnostics    |
                        +-----------------+-----------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|   Security & Compliance Audit   |                 |   K8s & Proxy Config Studio   |
|  * CAB Forum & RFC 5280 Linter  |                 |  * kubernetes.io/tls Secrets  |
|  * Cipher grading (A+ to F)     |                 |  * Nginx, Caddy, Envoy, cURL  |
|  * Continuous Domain Watcher    |                 |  * Docker, Go, Node, Python   |
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
│   ├── acme/
│   │   ├── acme.go                 # RFC 8555 local ACME directory server
│   │   └── acme_test.go            # ACME order and issuance flow tests
│   ├── audit/
│   │   ├── auditor.go              # TLS security scanner and grading engine
│   │   └── auditor_test.go         # Security audit unit tests
│   ├── ca/
│   │   ├── ca.go                   # Root and intermediate CA generator
│   │   ├── cert_issuer.go          # Leaf certificate and CSR signer
│   │   ├── truststore_windows.go   # Windows certutil integration
│   │   ├── truststore_darwin.go    # macOS security CLI integration
│   │   ├── truststore_linux.go     # Linux ca-certificates / update-ca-trust
│   │   ├── truststore_stub.go      # Portable fallback
│   │   └── ca_test.go              # CA initialization and verification tests
│   ├── configs/
│   │   ├── generator.go            # Proxy and client snippet generator
│   │   └── generator_test.go       # Config generator unit tests
│   ├── diff/
│   │   ├── diff.go                 # Side-by-side TLS & certificate diff engine
│   │   └── diff_test.go            # Comparative handshake tests
│   ├── handshake/
│   │   ├── probe.go                # Timed connection prober and TLS dialer
│   │   ├── timeline.go             # Sub-millisecond timing stage models
│   │   ├── ciphers.go              # TLS 1.2 / 1.3 cipher registry and PFS tags
│   │   ├── alpn.go                 # ALPN protocol identifiers
│   │   └── probe_test.go           # Handshake probe tests against mock server
│   ├── inspector/
│   │   ├── chain_parser.go         # X.509 certificate chain builder
│   │   ├── extensions.go           # ASN.1 extension formatting and key usage
│   │   ├── revocation.go           # OCSP and CRL distribution checks
│   │   └── chain_parser_test.go    # Parser and hierarchy verification tests
│   ├── k8s/
│   │   ├── k8s.go                  # Kubernetes Secret, ConfigMap & cert-manager generator
│   │   └── k8s_test.go             # Kubernetes manifest tests
│   ├── linter/
│   │   ├── linter.go               # CAB Forum & RFC 5280 compliance linter
│   │   └── linter_test.go          # Linter rule unit tests
│   ├── matrix/
│   │   ├── matrix.go               # Client compatibility matrix scanner
│   │   └── matrix_test.go          # Matrix probe tests
│   ├── mtls/
│   │   ├── mock_server.go          # Embedded TLS test server
│   │   ├── test_client.go          # Configurable mTLS probe client
│   │   ├── alert_simulator.go      # Fatal TLS alert frame simulator
│   │   ├── diagnostics.go          # Alert code root-cause mapper
│   │   ├── alert_simulator_test.go # Alert simulator unit tests
│   │   └── mtls_test.go            # Handshake and alert diagnosis tests
│   ├── server/
│   │   ├── http_server.go          # HTTP REST API server
│   │   ├── handlers.go             # REST endpoint handlers
│   │   ├── websocket.go            # Live event stream hub
│   │   └── server_test.go          # HTTP and WebSocket tests
│   └── watcher/
│       ├── watcher.go              # Continuous domain monitoring and expiry alerts
│       └── watcher_test.go         # Domain watcher tests
├── web/
│   ├── embed.go                    # Go 1.23 embed directive for built frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── AcmeStudio.tsx      # RFC 8555 directory studio and orders log
│   │   │   ├── CaManager.tsx       # Local CA control and cert generator
│   │   │   ├── CertChainTree.tsx   # Interactive chain hierarchy and linter
│   │   │   ├── ClientMatrix.tsx    # Client compatibility matrix view
│   │   │   ├── ConfigGenerator.tsx # Proxy and Kubernetes manifest studio
│   │   │   ├── DomainWatcher.tsx   # Continuous domain expiry monitor
│   │   │   ├── HandshakeWaterfall.tsx # Gantt-style handshake breakdown
│   │   │   ├── MtlsPlayground.tsx  # mTLS tester and alert simulator
│   │   │   ├── Navbar.tsx          # Top navigation and trust pill
│   │   │   ├── SecurityAudit.tsx   # Security grading and cipher checklist
│   │   │   └── TlsDiff.tsx         # Side-by-side TLS diff comparator
│   │   ├── lib/
│   │   │   └── api.ts              # Typed REST client and WebSocket connector
│   │   ├── App.tsx                 # Main layout and tab router
│   │   └── index.css               # Tailwind CSS v4 styling
│   └── dist/                       # Compiled production web assets
├── docs/
│   └── images/                     # Screenshots and demo GIF
├── go.mod
├── go.sum
└── README.md
```

---

## 3. Implementation Phases & Status

- [x] **Phase 1: Core PKI & Local Trust Store Automation**
  - Root CA generator with ECDSA P-256 and RSA 2048/4096.
  - Windows `certutil`, macOS `security`, and Linux `update-ca-certificates` integration.
  - Wildcard certificate issuance with custom SANs and PKCS#12 export.
  
- [x] **Phase 2: TLS Handshake Profiler & Chain Inspector**
  - Network dialer instrumenting DNS, TCP, and TLS record stages.
  - TLS 1.2 and 1.3 cipher registry with PFS detection and ALPN parsing.
  - X.509 hierarchy builder and OCSP/CRL reachability checks.

- [x] **Phase 3: Interactive mTLS Playground & Diagnostics**
  - Configurable in-memory HTTPS mTLS server.
  - Client authentication probe and alert code diagnosis (Alert 40, 42, 45, 46, 48, 112, 116).

- [x] **Phase 4: Security Auditor & Configuration Studio**
  - Security grader evaluating TLS versions, cipher strength, and PFS.
  - Reverse proxy configurations for Nginx, Caddy, Envoy, Apache, Docker, and runtimes.

- [x] **Phase 5: REST API, WebSocket Stream & Embedded Web Studio**
  - Embedded React 19 single-page application inside Go binary via `go:embed`.
  - Real-time WebSocket event broadcaster.

- [x] **Phase 6: X.509 Compliance & CAB Forum Linter**
  - CAB Forum Baseline Requirements and RFC 5280 compliance rules.
  - Checks for 398-day validity limit, SAN presence/CN deprecation, key sizes, and EKU coherence.
  - Integrated into chain inspector and CLI `tlslens lint`.

- [x] **Phase 7: Side-by-Side TLS & Certificate Diff**
  - Concurrent dual-host probing and automated delta detection.
  - Comparison of protocol, cipher, ALPN, latency, and leaf certificate properties.
  - Integrated into CLI `tlslens diff` and web view.

- [x] **Phase 8: Client Compatibility & Cipher Matrix Scanner**
  - Predefined client profiles (Android 7/14, iOS 12/17+, Chrome, Firefox, Java 8/17, OpenSSL 1.0.2/3.0).
  - Accurate fingerprint simulation testing protocol negotiation and cipher selection.
  - Integrated into CLI `tlslens matrix` and web view.

- [x] **Phase 9: Interactive TLS Alert Simulator**
  - Fatal TLS alert frame generator testing client error handling and retry loops.
  - Diagnostic breakdown and remediation guidance.

- [x] **Phase 10: Kubernetes Native Export Studio**
  - Generates kubernetes.io/tls Secrets, CA ConfigMaps, cert-manager ClusterIssuers, and Ingress TLS snippets.
  - Integrated into CLI `tlslens k8s` and Config Studio web view.

- [x] **Phase 11: Continuous Domain Watcher & Expiry Alerter**
  - Thread-safe background monitoring engine with configurable check intervals.
  - Real-time countdowns and WebSocket alert broadcasts.
  - Integrated into CLI `tlslens watch` and web view.

- [x] **Phase 12: Embedded RFC 8555 ACME Server**
  - Zero-configuration local ACME directory (`/acme/directory`) signing with local CA.
  - Direct integration with Caddy, Traefik, Certbot, and cert-manager.
  - ACME orders feed and status view in web studio.

---

## 4. Verification and Parity

All unit, integration, and CLI tests pass with 100% success rate:
- `go test ./...`: 12 packages tested, all passing.
- `tlslens.exe`: Single-binary standalone executable with embedded web studio.
- Live CLI commands verified: `serve`, `ca`, `cert`, `inspect`, `diff`, `matrix`, `lint`, `k8s`, `watch`, `mtls`, `audit`, `configs`.
