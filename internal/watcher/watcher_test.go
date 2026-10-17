package watcher

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

func TestDomainWatcher(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "watcher_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Watcher Test CA",
		ValidityDays: 1,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	leaf, err := testCA.Issue(ca.IssueRequest{
		CommonName:   "127.0.0.1",
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 30,
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
	}
	server.StartTLS()
	defer server.Close()

	alertTriggered := false
	watcher := NewDomainWatcher(nil, func(domain MonitoredDomain, changeType string) {
		alertTriggered = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watcher.Start(ctx)
	defer watcher.Stop()

	// Add domain
	item, err := watcher.Add(ctx, server.Listener.Addr().String(), 60)
	if err != nil {
		t.Fatalf("failed to add domain to watcher: %v", err)
	}

	if item.Status != StatusHealthy {
		t.Errorf("expected healthy status, got %s", item.Status)
	}

	if item.CommonName != "127.0.0.1" {
		t.Errorf("expected common name 127.0.0.1, got %s", item.CommonName)
	}

	// List
	domains := watcher.List()
	if len(domains) != 1 {
		t.Errorf("expected 1 domain, got %d", len(domains))
	}

	// Check
	refreshed, err := watcher.Check(ctx, item.ID)
	if err != nil {
		t.Fatalf("failed to re-check domain: %v", err)
	}
	if refreshed.Status != StatusHealthy {
		t.Errorf("expected healthy after check, got %s", refreshed.Status)
	}

	// Remove
	removed := watcher.Remove(item.ID)
	if !removed {
		t.Errorf("expected remove to return true")
	}

	if len(watcher.List()) != 0 {
		t.Errorf("expected 0 domains after remove")
	}

	_ = alertTriggered
}
