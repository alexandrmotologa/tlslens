package linter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestLintValidCertificate(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   "api.example.com",
			Organization: []string{"Acme Corp"},
		},
		DNSNames:              []string{"api.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // 90 days <= 398 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        []byte{1, 2, 3, 4},
		OCSPServer:            []string{"http://ocsp.example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	result := LintCertificate(cert)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s (errors: %d, warnings: %d)", result.Status, result.ErrorCount, result.WarningCount)
	}
	if result.ErrorCount > 0 {
		t.Errorf("expected 0 errors, got %d", result.ErrorCount)
	}
}

func TestLintViolations(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024) // Weak RSA: 1024 bits
	if err != nil {
		t.Fatalf("failed to generate RSA: %v", err)
	}

	// Violations:
	// 1. Weak RSA key (1024 bits)
	// 2. Validity > 398 days (800 days)
	// 3. No SANs (only CN)
	// 4. Leaf cert with KeyUsageCertSign
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2002),
		Subject: pkix.Name{
			CommonName: "legacy.example.com",
		},
		NotBefore:             time.Now().Add(-10 * time.Hour),
		NotAfter:              time.Now().Add(800 * 24 * time.Hour), // > 398 days
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	result := LintCertificate(cert)
	if result.Status != "fail" {
		t.Errorf("expected fail status, got %s", result.Status)
	}

	foundWeakRSA := false
	foundValidity := false
	foundSANMissing := false
	foundLeafCertSign := false

	for _, f := range result.Findings {
		switch f.Code {
		case "LINT_RSA_KEY_TOO_SHORT":
			foundWeakRSA = true
		case "LINT_VALIDITY_EXCEEDS_398_DAYS":
			foundValidity = true
		case "LINT_SAN_MISSING":
			foundSANMissing = true
		case "LINT_LEAF_HAS_CERTSIGN":
			foundLeafCertSign = true
		}
	}

	if !foundWeakRSA {
		t.Errorf("missing expected LINT_RSA_KEY_TOO_SHORT finding")
	}
	if !foundValidity {
		t.Errorf("missing expected LINT_VALIDITY_EXCEEDS_398_DAYS finding")
	}
	if !foundSANMissing {
		t.Errorf("missing expected LINT_SAN_MISSING finding")
	}
	if !foundLeafCertSign {
		t.Errorf("missing expected LINT_LEAF_HAS_CERTSIGN finding")
	}
}
