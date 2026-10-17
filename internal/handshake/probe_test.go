package handshake

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/ca"
)

func TestProbeEndpoint(t *testing.T) {
	tempDir, err := osMkdirTemp()
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Probe Test Root CA",
		ValidityDays: 1,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	leaf, err := testCA.Issue(ca.IssueRequest{
		CommonName:   "127.0.0.1",
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("failed to issue leaf: %v", err)
	}

	serverCert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatalf("failed to parse keypair: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := ProbeEndpoint(ctx, server.Listener.Addr().String(), ProbeOptions{
		InsecureSkipVerify: true,
		ALPNProtocols:      []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("ProbeEndpoint returned unexpected error: %v", err)
	}

	if result.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", result.Host)
	}
	if len(result.Timings) < 3 {
		t.Errorf("expected at least 3 timing stages, got %d", len(result.Timings))
	}
	if len(result.PeerCertificates) == 0 {
		t.Errorf("expected at least 1 peer certificate")
	}
	if result.Cipher.Name == "" {
		t.Errorf("expected cipher suite name")
	}
}

func osMkdirTemp() (string, error) {
	return os.MkdirTemp("", "probe_test")
}
