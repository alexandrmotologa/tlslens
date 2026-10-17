package inspector

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/alexandrmotologa/tlslens/internal/ca"
)

func TestChainHierarchyAndExtensions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "inspector_test")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rootCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Hierarchy Root CA",
		ValidityDays: 10,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create root CA: %v", err)
	}

	leaf, err := rootCA.Issue(ca.IssueRequest{
		CommonName:   "service.local.test",
		Domains:      []string{"service.local.test", "localhost"},
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 5,
	})
	if err != nil {
		t.Fatalf("failed to issue leaf: %v", err)
	}

	certs, err := ParseCertificatesFromPEM(leaf.BundlePEM)
	if err != nil {
		t.Fatalf("failed to parse certificates from bundle: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates in bundle, got %d", len(certs))
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	hierarchy := BuildHierarchy(certs, roots)
	if !hierarchy.IsValid {
		t.Errorf("expected hierarchy to be valid, got validation error: %s", hierarchy.ValidationError)
	}
	if hierarchy.Leaf.CommonName != "service.local.test" {
		t.Errorf("unexpected leaf name: %s", hierarchy.Leaf.CommonName)
	}
	if hierarchy.Root == nil || hierarchy.Root.CommonName != "Hierarchy Root CA" {
		t.Errorf("unexpected root CA: %v", hierarchy.Root)
	}

	// Test revocation info
	rev := CheckRevocation(leaf.Certificate, false)
	if rev.Status != "unconfigured" {
		t.Errorf("expected unconfigured for local cert, got %s", rev.Status)
	}
}
