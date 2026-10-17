package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
	"github.com/alexandrmotologa/tlslens/internal/inspector"
)

// ClientTestRequest configures an mTLS client connection probe.
type ClientTestRequest struct {
	TargetURL          string `json:"targetUrl"`
	RootCAPEM          []byte `json:"rootCaPem,omitempty"`
	ClientCertPEM      []byte `json:"clientCertPem,omitempty"`
	ClientKeyPEM       []byte `json:"clientKeyPem,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	ServerName         string `json:"serverName,omitempty"`
	TimeoutMs          int    `json:"timeoutMs,omitempty"`
}

// ClientTestResult returns the outcome of an mTLS probe attempt.
type ClientTestResult struct {
	Success          bool                    `json:"success"`
	StatusCode       int                     `json:"statusCode,omitempty"`
	ResponseBody     string                  `json:"responseBody,omitempty"`
	TLSVersion       string                  `json:"tlsVersion,omitempty"`
	CipherSuite      string                  `json:"cipherSuite,omitempty"`
	PeerCertificates []handshake.CertSummary `json:"peerCertificates,omitempty"`
	Diagnostics      DiagnosticReport        `json:"diagnostics"`
	DurationMs       float64                 `json:"durationMs"`
}

// RunClientTest executes a full HTTPS request with client certificate authentication.
func RunClientTest(ctx context.Context, req ClientTestRequest) (*ClientTestResult, error) {
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 5000
	}

	target := req.TargetURL
	if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") {
		target = "https://" + target
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: req.InsecureSkipVerify,
		ServerName:         req.ServerName,
	}

	var parsedClientCert *x509.Certificate
	if len(req.ClientCertPEM) > 0 && len(req.ClientKeyPEM) > 0 {
		clientCert, err := tls.X509KeyPair(req.ClientCertPEM, req.ClientKeyPEM)
		if err != nil {
			report := DiagnoseError(fmt.Errorf("failed to parse client certificate or key: %w", err), nil, nil)
			return &ClientTestResult{
				Success:     false,
				Diagnostics: report,
			}, nil
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}

		// Also parse x509 cert for diagnostic auditing
		if parsed, err := ParseCertificateFromPEMBytes(req.ClientCertPEM); err == nil {
			parsedClientCert = parsed
		}
	}

	var parsedRootCA *x509.Certificate
	if len(req.RootCAPEM) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(req.RootCAPEM) {
			tlsConfig.RootCAs = pool
		}
		if parsed, err := ParseCertificateFromPEMBytes(req.RootCAPEM); err == nil {
			parsedRootCA = parsed
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext:     (&http.Transport{}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(req.TimeoutMs) * time.Millisecond,
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request URL: %w", err)
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(start)
	durationMs := float64(duration.Microseconds()) / 1000.0

	if err != nil {
		diag := DiagnoseError(err, parsedClientCert, parsedRootCA)
		return &ClientTestResult{
			Success:     false,
			Diagnostics: diag,
			DurationMs:  durationMs,
		}, nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*16))

	result := &ClientTestResult{
		Success:      resp.StatusCode >= 200 && resp.StatusCode < 400,
		StatusCode:   resp.StatusCode,
		ResponseBody: string(bodyBytes),
		DurationMs:   durationMs,
		Diagnostics:  DiagnoseError(nil, parsedClientCert, parsedRootCA),
	}

	if resp.TLS != nil {
		result.TLSVersion = handshake.GetTLSVersionName(resp.TLS.Version)
		result.CipherSuite = handshake.GetCipherInfo(resp.TLS.CipherSuite).Name

		for _, cert := range resp.TLS.PeerCertificates {
			result.PeerCertificates = append(result.PeerCertificates, inspector.ParseCertSummary(cert))
		}
	}

	return result, nil
}
