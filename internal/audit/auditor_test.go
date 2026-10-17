package audit

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

func TestAuditEndpoint(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit_test")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Audit Test CA",
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
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := AuditEndpoint(ctx, server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("AuditEndpoint error: %v", err)
	}

	if result.Score < 80 {
		t.Errorf("expected score >= 80 for modern TLS 1.3 server, got %d (grade: %s)", result.Score, result.Grade)
	}
	if !result.HasTLS13 {
		t.Errorf("expected HasTLS13 to be true")
	}
}
