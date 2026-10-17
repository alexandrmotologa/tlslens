package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCANewAndIssue(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tlslens_ca_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := CAConfig{
		CommonName:   "TLSLens Test Root CA",
		Organization: "TLSLens Testing",
		Country:      "US",
		ValidityDays: 30,
		KeyType:      "ecdsa",
		StorageDir:   tempDir,
	}

	caInstance, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	if !caInstance.Certificate.IsCA {
		t.Errorf("expected IsCA to be true")
	}

	info := caInstance.Inspect()
	if info.CommonName != "TLSLens Test Root CA" {
		t.Errorf("unexpected CommonName: %s", info.CommonName)
	}
	if info.KeyType != "ECDSA" {
		t.Errorf("unexpected key type: %s", info.KeyType)
	}

	// Test reload
	loadedCA, err := LoadCA(tempDir)
	if err != nil {
		t.Fatalf("failed to reload CA from disk: %v", err)
	}
	if loadedCA.Certificate.Subject.CommonName != caInstance.Certificate.Subject.CommonName {
		t.Errorf("reloaded CA name mismatch")
	}

	// Test Leaf Certificate Issuance
	req := IssueRequest{
		CommonName:   "api.local.test",
		Domains:      []string{"api.local.test", "*.local.test", "localhost"},
		IPs:          []string{"127.0.0.1", "::1"},
		ValidityDays: 14,
		KeyType:      "ecdsa",
		Organization: "TLSLens Devs",
		P12Password:  "changeit",
	}

	leaf, err := caInstance.Issue(req)
	if err != nil {
		t.Fatalf("failed to issue leaf certificate: %v", err)
	}

	if leaf.CommonName != "api.local.test" {
		t.Errorf("expected common name api.local.test, got %s", leaf.CommonName)
	}
	if len(leaf.DNSNames) != 3 {
		t.Errorf("expected 3 DNS names, got %d", len(leaf.DNSNames))
	}
	if len(leaf.IPAddresses) != 2 {
		t.Errorf("expected 2 IP addresses, got %d", len(leaf.IPAddresses))
	}
	if len(leaf.P12Bytes) == 0 {
		t.Errorf("expected non-empty P12 bytes")
	}

	// Verify certificate signature against root CA
	roots := x509.NewCertPool()
	roots.AddCert(caInstance.Certificate)

	block, _ := pem.Decode(leaf.CertPEM)
	if block == nil {
		t.Fatalf("failed to decode leaf PEM")
	}
	parsedLeaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: "api.local.test",
	}
	if _, err := parsedLeaf.Verify(opts); err != nil {
		t.Fatalf("leaf verification against root CA failed: %v", err)
	}

	// Test saving to directory
	leafOut := filepath.Join(tempDir, "leaf_out")
	if err := leaf.SaveToDir(leafOut); err != nil {
		t.Fatalf("failed to save leaf certs to disk: %v", err)
	}

	if _, err := os.Stat(filepath.Join(leafOut, "cert.pem")); err != nil {
		t.Errorf("cert.pem was not created")
	}
	if _, err := os.Stat(filepath.Join(leafOut, "key.pem")); err != nil {
		t.Errorf("key.pem was not created")
	}
	if _, err := os.Stat(filepath.Join(leafOut, "bundle.pem")); err != nil {
		t.Errorf("bundle.pem was not created")
	}
	if _, err := os.Stat(filepath.Join(leafOut, "cert.p12")); err != nil {
		t.Errorf("cert.p12 was not created")
	}
}

func TestCARSAKeyGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tlslens_rsa_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := CAConfig{
		CommonName:   "TLSLens RSA Root CA",
		Organization: "TLSLens Testing",
		Country:      "US",
		ValidityDays: 1,
		KeyType:      "rsa2048",
		StorageDir:   tempDir,
	}

	caInstance, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("failed to create RSA CA: %v", err)
	}

	info := caInstance.Inspect()
	if info.KeyType != "RSA" || info.KeyLength != 2048 {
		t.Errorf("expected RSA 2048, got %s %d", info.KeyType, info.KeyLength)
	}
}
