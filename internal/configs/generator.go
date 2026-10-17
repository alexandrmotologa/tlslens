package configs

import (
	"fmt"
	"strings"
)

// ConfigSnippet contains title, description, language, and formatted configuration code.
type ConfigSnippet struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"` // "proxy", "client", "runtime", "env"
	Language    string `json:"language"`
	Description string `json:"description"`
	Code        string `json:"code"`
}

// ConfigParameters defines customizable paths and names for snippet generation.
type ConfigParameters struct {
	CertPath    string `json:"certPath"`
	KeyPath     string `json:"keyPath"`
	CAPath      string `json:"caPath"`
	Domain      string `json:"domain"`
	Port        int    `json:"port"`
	BackendAddr string `json:"backendAddr"`
}

// GenerateSnippets builds verified configurations for proxies and programming languages.
func GenerateSnippets(params ConfigParameters) []ConfigSnippet {
	if params.CertPath == "" {
		params.CertPath = "/etc/ssl/certs/cert.pem"
	}
	if params.KeyPath == "" {
		params.KeyPath = "/etc/ssl/private/key.pem"
	}
	if params.CAPath == "" {
		params.CAPath = "/etc/ssl/certs/root-ca.crt"
	}
	if params.Domain == "" {
		params.Domain = "api.local.test"
	}
	if params.Port <= 0 {
		params.Port = 443
	}
	if params.BackendAddr == "" {
		params.BackendAddr = "127.0.0.1:3000"
	}

	return []ConfigSnippet{
		{
			ID:          "nginx-mtls",
			Title:       "Nginx Reverse Proxy with mTLS",
			Category:    "proxy",
			Language:    "nginx",
			Description: "Terminates HTTPS and verifies client certificates using the trusted CA bundle.",
			Code: fmt.Sprintf(`server {
    listen %d ssl http2;
    server_name %s;

    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Mutual TLS (mTLS) Client Verification
    ssl_client_certificate %s;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location / {
        proxy_pass http://%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forward authenticated client identity to upstream
        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header X-SSL-Client-DN $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
    }
}`, params.Port, params.Domain, params.CertPath, params.KeyPath, params.CAPath, params.BackendAddr),
		},
		{
			ID:          "caddy",
			Title:       "Caddyfile with Custom Local CA",
			Category:    "proxy",
			Language:    "caddyfile",
			Description: "Configures Caddy with static certificates issued by TLSLens.",
			Code: fmt.Sprintf(`%s {
    tls %s %s {
        client_auth {
            mode require_and_verify
            trusted_ca_cert_file %s
        }
    }

    reverse_proxy %s
}`, params.Domain, params.CertPath, params.KeyPath, params.CAPath, params.BackendAddr),
		},
		{
			ID:          "envoy",
			Title:       "Envoy Proxy Downstream mTLS",
			Category:    "proxy",
			Language:    "yaml",
			Description: "Envoy transport socket configuration for strict mutual TLS verification.",
			Code: fmt.Sprintf(`transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_certificates:
        - certificate_chain:
            filename: "%s"
          private_key:
            filename: "%s"
      validation_context:
        trusted_ca:
          filename: "%s"
    require_client_certificate: true`, params.CertPath, params.KeyPath, params.CAPath),
		},
		{
			ID:          "curl",
			Title:       "cURL CLI Client Command",
			Category:    "client",
			Language:    "bash",
			Description: "Executes an mTLS request passing client cert, client key, and CA certificate.",
			Code: fmt.Sprintf(`curl -v \
  --cacert %s \
  --cert %s \
  --key %s \
  https://%s:%d/`, params.CAPath, params.CertPath, params.KeyPath, params.Domain, params.Port),
		},
		{
			ID:          "go-client",
			Title:       "Go http.Client mTLS",
			Category:    "runtime",
			Language:    "go",
			Description: "Type-safe Go client configuration for mutual TLS connections.",
			Code: fmt.Sprintf(`package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

func createMTLSClient() (*http.Client, error) {
	// 1. Load client certificate and key
	cert, err := tls.LoadX509KeyPair("%s", "%s")
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert: %%w", err)
	}

	// 2. Load trusted CA pool
	caCert, err := os.ReadFile("%s")
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %%w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "%s",
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}`, params.CertPath, params.KeyPath, params.CAPath, params.Domain),
		},
		{
			ID:          "node-server",
			Title:       "Node.js HTTPS Server with mTLS",
			Category:    "runtime",
			Language:    "javascript",
			Description: "Native Node.js HTTPS server demanding and verifying client certificates.",
			Code: fmt.Sprintf(`const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('%s'),
  cert: fs.readFileSync('%s'),
  ca: fs.readFileSync('%s'),
  requestCert: true,
  rejectUnauthorized: true
};

https.createServer(options, (req, res) => {
  const clientCert = req.socket.getPeerCertificate();
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    authenticated: true,
    client: clientCert.subject
  }));
}).listen(%d, () => {
  console.log('mTLS server running on port %d');
});`, params.KeyPath, params.CertPath, params.CAPath, params.Port, params.Port),
		},
		{
			ID:          "python-client",
			Title:       "Python requests / httpx mTLS",
			Category:    "runtime",
			Language:    "python",
			Description: "Python requests mTLS authentication snippet.",
			Code: fmt.Sprintf(`import requests

# Supply client (cert, key) tuple and CA bundle
response = requests.get(
    "https://%s:%d/api",
    cert=("%s", "%s"),
    verify="%s"
)

print(response.status_code, response.json())`, params.Domain, params.Port, params.CertPath, params.KeyPath, params.CAPath),
		},
		{
			ID:          "env-vars",
			Title:       "Local Trust Environment Variables",
			Category:    "env",
			Language:    "bash",
			Description: "System and runtime environment variables to trust the local CA without modifying system stores.",
			Code: fmt.Sprintf(`# Node.js
export NODE_EXTRA_CA_CERTS="%s"

# Python (requests / urllib3)
export REQUESTS_CA_BUNDLE="%s"
export SSL_CERT_FILE="%s"

# Go & OpenSSL applications
export SSL_CERT_FILE="%s"
export SSL_CERT_DIR="%s"

# AWS CLI
export AWS_CA_BUNDLE="%s"`, params.CAPath, params.CAPath, params.CAPath, params.CAPath, "/etc/ssl/certs", params.CAPath),
		},
	}
}

// GenerateComposeBlock creates a docker-compose snippet mounting certificates.
func GenerateComposeBlock(serviceName, certsDir string) string {
	if certsDir == "" {
		certsDir = "./certs"
	}
	return strings.TrimSpace(fmt.Sprintf(`services:
  %s:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - %s:/etc/ssl/certs:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro`, serviceName, certsDir))
}
