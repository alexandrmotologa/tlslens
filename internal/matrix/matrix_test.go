package matrix

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

func TestScanMatrix(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "matrix_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Matrix Test CA",
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
		t.Fatalf("failed to parse cert: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := ScanMatrix(ctx, server.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("ScanMatrix failed: %v", err)
	}

	if report.TotalProfiles == 0 {
		t.Fatalf("expected non-zero profiles")
	}

	if report.SuccessfulProfiles == 0 {
		t.Errorf("expected at least one successful profile connection")
	}

	for _, res := range report.Results {
		if res.Success && res.NegotiatedProtocol == "" {
			t.Errorf("profile %s succeeded but has empty protocol", res.Profile.Name)
		}
	}
}
