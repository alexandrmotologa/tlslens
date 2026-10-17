# TLSLens

<p align="center">
  <strong>Local Certificate Authority, mTLS Playground, and TLS Handshake Inspector with PKI Visualizer</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go" alt="Go 1.23+" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react" alt="React 19" />
  <img src="https://img.shields.io/badge/Tailwind-CSS-38B2AC?style=flat&logo=tailwind-css" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License" />
</p>

<p align="center">
  <img src="docs/images/tlslens_demo.gif" alt="TLSLens Handshake Profiler and PKI Studio Demo" width="90%" />
</p>

TLSLens is a developer diagnostics tool and PKI workbench for debugging TLS configurations, mutual TLS (mTLS) authentication failures, and certificate chains. It generates trusted local root CAs with 1 click, registers them in the operating system root store (Windows, macOS, Linux), troubleshoots mTLS connection alerts, and visualizes sub-millisecond TLS 1.3 and 1.2 handshake timelines.

---

## Capabilities

- **Zero-Config Local CA**: Generates ECDSA P-256 and RSA root CAs with automatic registration in Windows CertStore, macOS Keychain, and Linux ca-certificates.
- **Wildcard Certificate Issuer**: Issues valid SAN certificates (`*.local.test`, `localhost`, `127.0.0.1`) with configurable validity and key algorithms.
- **Interactive mTLS Playground**: Runs an in-memory mTLS server with configurable client authentication policies (`RequireAndVerifyClientCert`, `VerifyClientCertIfGiven`, etc.) and a client test probe.
- **Handshake Alert Diagnostics**: Detects and translates raw TLS alert codes (alert 40 `handshake_failure`, alert 42 `bad_certificate`, alert 45 `certificate_expired`, alert 46 `certificate_unknown`, alert 48 `unknown_ca`) into concrete remediation steps.
- **TLS Handshake Waterfall Profiler**: Measures sub-millisecond breakdowns across DNS resolution, TCP SYN/ACK, ClientHello, ServerHello, Certificate Validation, and Key Exchange.
- **X.509 Visual Hierarchy Inspector**: Interactive tree showing Leaf -> Intermediate -> Root relationships with validity countdowns, SAN badges, key usage flags, and fingerprints.
- **Security & Cipher Suite Auditor**: Grades target endpoints (A+ to F) evaluating forward secrecy (PFS), cipher algorithms, key sizes, and protocol versions.
- **Configuration Studio**: Generates validated configuration snippets for Nginx, Caddy, Envoy, Apache, Docker, cURL, Go, Node.js, and Python.

---

## Interface Overview

| Feature | Description |
|---|---|
| **CA Studio** | Generate local Root CA, install or remove from OS trust store, issue leaf certificates, and export PEM/PKCS#12 bundles |
| **Handshake Waterfall** | Measure sub-millisecond latency for TCP Connect, TLS ClientHello, ServerHello, Certificate Validation, and Key Exchange |
| **Certificate Chain** | Visual hierarchy displaying Subject, Issuer, Expiration countdown, Key Usage extensions, and OCSP status |
| **mTLS Sandbox** | Test bidirectional client certificate verification, inspect client credentials, and decode TLS alert codes |
| **Security Audit** | Security grading (A+ to F), protocol compatibility matrix, and cipher suite evaluation |
| **Config Generator** | Export reverse proxy configurations and local runtime environment variables |

<p align="center">
  <img src="docs/images/tlslens-1.png" alt="TLSLens Handshake Profiler" width="48%" />
  <img src="docs/images/tlslens-2.png" alt="TLSLens Certificate Chain Inspector" width="48%" />
</p>

<p align="center">
  <img src="docs/images/tlslens-3.png" alt="TLSLens CA Studio" width="48%" />
  <img src="docs/images/tlslens-4.png" alt="TLSLens mTLS Sandbox" width="48%" />
</p>

---

## Quick Start

### Installation

Download the pre-compiled binary for your operating system or compile from source:

```bash
# Clone the repository
git clone https://github.com/alexandrmotologa/tlslens.git
cd tlslens

# Build the embedded single binary
go build -o bin/tlslens ./cmd/tlslens
```

### Starting the Studio

Run the integrated web studio and API server:

```bash
./bin/tlslens serve --port 8080
```

Open `http://localhost:8080` in your browser.

---

## Command Line Usage

TLSLens can be operated both via the visual web studio and directly through the command line.

### Initialize Local Root CA

```bash
# Generate root CA with ECDSA P-256 (default)
tlslens ca init

# Or generate with RSA 2048
tlslens ca init --key-type rsa
```

### Manage OS Trust Store

```bash
# Register the local root CA in your operating system trust store
tlslens ca trust

# Verify trust store status
tlslens ca status

# Remove root CA from trust store
tlslens ca untrust
```

### Issue Leaf Certificates

```bash
# Issue a wildcard development certificate with SANs
tlslens cert issue --domains "localhost,api.local.test,*.local.test" --ips "127.0.0.1,::1" --out ./certs
```

This creates:
- `./certs/cert.pem`: Leaf certificate with full SAN extensions
- `./certs/key.pem`: Private key
- `./certs/bundle.pem`: Combined leaf and root CA chain
- `./certs/cert.p12`: PKCS#12 archive for browser or system import

### Inspect a Remote or Local TLS Endpoint

```bash
# Run handshake probe and chain inspection
tlslens inspect google.com:443

# Output raw JSON for automation or CI pipelines
tlslens inspect localhost:9443 --json
```

### Test Mutual TLS (mTLS)

```bash
# Test client authentication against an mTLS server
tlslens mtls test --target localhost:9443 --ca ./certs/root-ca.crt --cert ./certs/client.crt --key ./certs/client.key
```

### Run Security Audit

```bash
# Audit TLS versions and cipher suites on a host
tlslens audit cloudflare.com:443
```

---

## Operating System Trust Store Details

| Operating System | Command / Mechanism | Trust Location |
|---|---|---|
| **Windows** | `certutil.exe -addstore -f "ROOT" <file>` | Local Machine Root Certification Authorities |
| **macOS** | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <file>` | System Keychain |
| **Linux (Debian/Ubuntu)** | Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |
| **Linux (RHEL/Fedora)** | Copy to `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust` | System trust anchor bundle |

---

## License

MIT License. Copyright (c) 2026 Alexandr Motologa. See [LICENSE](LICENSE) for details.
