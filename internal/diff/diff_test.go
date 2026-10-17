package diff

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

func TestCompareTargets(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "diff_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Diff Test Root CA",
		ValidityDays: 1,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	// Server A
	leafA, err := testCA.Issue(ca.IssueRequest{
		CommonName:   "127.0.0.1",
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("failed to issue leaf A: %v", err)
	}
	certA, err := tls.X509KeyPair(leafA.CertPEM, leafA.KeyPEM)
	if err != nil {
		t.Fatalf("failed to parse keypair A: %v", err)
	}

	serverA := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverA.TLS = &tls.Config{
		Certificates: []tls.Certificate{certA},
		NextProtos:   []string{"h2"},
	}
	serverA.StartTLS()
	defer serverA.Close()

	// Server B
	leafB, err := testCA.Issue(ca.IssueRequest{
		CommonName:   "localhost",
		Domains:      []string{"localhost"},
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 60,
	})
	if err != nil {
		t.Fatalf("failed to issue leaf B: %v", err)
	}
	certB, err := tls.X509KeyPair(leafB.CertPEM, leafB.KeyPEM)
	if err != nil {
		t.Fatalf("failed to parse keypair B: %v", err)
	}

	serverB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverB.TLS = &tls.Config{
		Certificates: []tls.Certificate{certB},
		NextProtos:   []string{"http/1.1"},
	}
	serverB.StartTLS()
	defer serverB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	diffResult, err := CompareTargets(ctx, serverA.Listener.Addr().String(), serverB.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("CompareTargets failed: %v", err)
	}

	if diffResult.ProbeA == nil || diffResult.ProbeB == nil {
		t.Fatalf("expected non-nil probes for both targets")
	}

	if len(diffResult.Differences) == 0 {
		t.Errorf("expected differences between server A and B")
	}

	foundALPN := false
	for _, d := range diffResult.Differences {
		if d.Field == "ALPN Negotiated" {
			foundALPN = true
			if !d.IsDifferent {
				t.Errorf("expected ALPN to be different (h2 vs http/1.1)")
			}
		}
	}

	if !foundALPN {
		t.Errorf("expected ALPN Negotiated field diff")
	}
}
