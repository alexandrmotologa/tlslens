# TLSLens Architecture and Design

TLSLens is a local certificate authority, mTLS testing playground, and TLS handshake timing inspector built with Go 1.23 and React 19. This document details the component architecture, cryptographic flows, and network probe models.

## 1. System Overview

TLSLens operates as a standalone binary combining an embedded cryptographic engine, a low-level network probe, an in-memory mTLS test server, and a web studio served via Go embed.

```
+-----------------------------------------------------------------------------------+
|                                  HTTP REST & WS                                   |
|                             (internal/server package)                             |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|          PKI Engine             |                 |       Handshake Probe         |
|      (internal/ca package)      |                 |   (internal/handshake pack)   |
| - Root CA Generation            |                 | - Low-level TCP Dialing       |
| - Leaf Certificate Issuance     |                 | - TLS Trace & State Recording |
| - OS Trust Store Automation     |                 | - Sub-millisecond Timings     |
| - PKCS#12 & PEM Export          |                 | - ALPN & Cipher Negotiation   |
+---------------------------------+                 +-------------------------------+
        |                                                           |
        +---------------------------------+-------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                 +-----------------------v-------+
|         mTLS Sandbox            |                 |       Security Auditor        |
|     (internal/mtls package)     |                 |     (internal/audit pack)     |
| - In-memory HTTPS Server        |                 | - Weak Cipher Detection       |
| - Configurable ClientAuth       |                 | - Forward Secrecy Checks      |
| - Alert Code Diagnosis          |                 | - Protocol Version Grading    |
| - Remediation Guidance          |                 | - Key Length Verification     |
+---------------------------------+                 +-------------------------------+
```

## 2. Cryptographic Engine (internal/ca)

The PKI engine uses Go's standard `crypto/x509`, `crypto/ecdsa`, `crypto/rsa`, and `crypto/ed25519` packages.

### Root CA Lifecycle
1. Generation:
   - Key: ECDSA P-256 (default for fast handshake execution) or RSA 2048/4096.
   - Subject: `CN=TLSLens Local Development Root CA, O=TLSLens, C=US`.
   - Serial number: 128-bit cryptographically secure integer via `crypto/rand`.
   - Extensions:
     - `IsCA: true`
     - `BasicConstraintsValid: true`
     - `KeyUsage: KeyUsageCertSign | KeyUsageCRLSign`
     - `SubjectKeyId`: SHA-1 hash of public key bytes.
   - Validity: 10 years by default.
2. Storage:
   - Default directory: `~/.tlslens/ca/` (or specified directory in configuration).
   - Files: `root-ca.crt` (PEM certificate) and `root-ca.key` (PEM encrypted or restricted permissions private key).

### Leaf Certificate Issuance
1. Parameters:
   - Subject Alternative Names (SANs): DNS names (such as `localhost`, `*.local.test`, `app.internal`), IPv4 and IPv6 addresses (such as `127.0.0.1`, `::1`).
   - Validity: Configurable, typically 365 days for development.
   - Key Usage: `KeyUsageDigitalSignature | KeyUsageKeyEncipherment`.
   - Extended Key Usage: `ExtKeyUsageServerAuth` and `ExtKeyUsageClientAuth` (allowing certificates to function for both HTTPS server hosting and mTLS client authentication).
2. Export formats:
   - Individual PEM files: `cert.pem` and `key.pem`.
   - Combined PEM file: `bundle.pem`.
   - PKCS#12 bundle (`.p12` / `.pfx`) with optional password for import into Windows cert store, Java keystores, or browser profiles.

### OS Trust Store Integration
- Windows: Uses `certutil.exe -addstore -f "ROOT" <cert-path>` to add the root CA to the Local Machine Root store, and `certutil.exe -delstore "ROOT" <serial-or-cn>` for removal.
- macOS: Uses `/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert-path>`.
- Linux: Supports both Debian/Ubuntu (`/usr/local/share/ca-certificates/tlslens.crt` with `update-ca-certificates`) and RHEL/Fedora/CentOS (`/etc/pki/ca-trust/source/anchors/tlslens.crt` with `update-ca-trust`).

## 3. Handshake Profiler (internal/handshake)

To measure accurate sub-millisecond network breakdowns, TLSLens implements a custom network dialer that wraps `net.Conn` and monitors state transitions through `crypto/tls`.

### Timing Stages
1. `t_dns`: DNS resolution duration via `net.LookupIP`.
2. `t_tcp`: TCP 3-way handshake roundtrip time from `net.Dialer.DialContext`.
3. `t_tls_hello`: Time elapsed between sending TLS ClientHello and receiving ServerHello.
4. `t_cert_validation`: Time required to parse the peer certificate chain and verify signatures.
5. `t_handshake_finish`: Complete TLS handshake duration.
6. `t_total`: Cumulative latency from initial dial to ready connection.

### Extracted Metadata
- TLS Version: TLS 1.3 (`0x0304`) or TLS 1.2 (`0x0303`).
- Cipher Suite: IANA name, key exchange mechanism, encryption algorithm, and MAC/AEAD mode.
- ALPN: Negotiated application protocol (such as `h2`, `http/1.1`, `h3`).
- Server Name Indication (SNI) verification.
- Peer certificates: Complete chain including intermediate and root certificates.
- OCSP Stapling: Checks whether the server provided a stapled OCSP response in the handshake.

## 4. mTLS Sandbox and Diagnostics (internal/mtls)

The mTLS sandbox provides both a live configurable test server and a diagnostic client probe.

### In-Memory Server
The server runs on an ephemeral or dedicated port (e.g. `127.0.0.1:9443`). It exposes configurable `tls.ClientAuthType` modes:
- `NoClientCert`: Regular HTTPS without client cert request.
- `RequestClientCert`: Server asks for a certificate but proceeds if none is provided.
- `RequireAnyClientCert`: Server demands a client certificate but does not verify against a trusted CA.
- `VerifyClientCertIfGiven`: Verifies client cert against trusted CA pool if one is supplied.
- `RequireAndVerifyClientCert`: Enforces mutual TLS with strict CA chain validation.

### Alert Diagnostics
When a handshake fails, TLSLens inspects the error returned by `crypto/tls` and categorizes the underlying alert code:

| Alert Code | Alert Name | Root Cause | Remediation |
|---|---|---|---|
| 40 | handshake_failure | No mutual cipher suites or unsupported protocol version | Check supported cipher suites on both client and server; align TLS 1.2/1.3 configurations |
| 42 | bad_certificate | Certificate signature is corrupt, ASN.1 is malformed, or missing required key usage | Re-issue client certificate with proper KeyUsageDigitalSignature and ClientAuth ExtKeyUsage |
| 45 | certificate_expired | Certificate NotAfter date has passed or NotBefore is in the future | Check system clock synchronization or issue a new client certificate with valid date range |
| 46 | certificate_unknown | Client certificate was not issued by any CA in the server's trusted CA pool | Add client certificate's issuer CA to server's client CA bundle, or issue client cert using trusted CA |
| 48 | unknown_ca | CA chain could not be built to a trusted root | Provide intermediate CA certificates in client bundle or configure server trust pool |
| 112 | unrecognized_name | Server does not recognize the SNI hostname sent by client | Ensure client SNI matches one of the SAN DNS names on the server certificate |

## 5. Security Auditor (internal/audit)

The security auditor evaluates an endpoint against industry cryptographic baselines:
- Score Calculation:
  - Base: 100 points (Grade A+).
  - Protocol deductions: -30 for TLS 1.0, -20 for TLS 1.1, -10 if TLS 1.3 is not supported.
  - Cipher deductions: -40 for RC4 or 3DES, -20 for CBC-mode ciphers, -15 if forward secrecy (PFS) is missing.
  - Certificate deductions: -30 for expired or self-signed non-root certificates, -20 for RSA key length below 2048 bits, -25 for SHA-1 signatures.
- Letter Grades:
  - 95 to 100: A+
  - 90 to 94: A
  - 80 to 89: B
  - 70 to 79: C
  - Below 70: F

## 6. Frontend Architecture (web/)

The web studio is built with React 19, TypeScript, Tailwind CSS, and Lucide icons following the Cerulean design kit tokens:
- Primary dark palette with high-contrast monospace typography for cryptographic data.
- Responsive layout split across five dedicated views:
  1. CA Studio: Manage root CA, toggle OS trust, issue leaf certificates, and export in PEM/P12 formats.
  2. Handshake Profiler: Run probes against local or remote endpoints with interactive Gantt timeline visualization.
  3. Certificate Hierarchy: Interactive node graph showing the leaf, intermediate, and root certificate hierarchy.
  4. mTLS Sandbox: Control test server, execute client probes with uploaded certificates, and view real-time alert diagnostics.
  5. Security Audit & Config Studio: Security scorecards and 1-click configuration snippets for reverse proxies and development runtimes.
