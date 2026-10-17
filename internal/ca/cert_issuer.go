package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// IssueRequest defines attributes for issuing an X.509 leaf certificate.
type IssueRequest struct {
	CommonName   string   `json:"commonName"`
	Domains      []string `json:"domains"`
	IPs          []string `json:"ips"`
	ValidityDays int      `json:"validityDays"`
	KeyType      string   `json:"keyType"` // "ecdsa" (default), "rsa2048", "rsa4096", "ed25519"
	Organization string   `json:"organization"`
	P12Password  string   `json:"p12Password"`
}

// IssuedCertificate contains generated certificate assets and raw bytes.
type IssuedCertificate struct {
	CertPEM           []byte            `json:"certPEM"`
	KeyPEM            []byte            `json:"keyPEM"`
	BundlePEM         []byte            `json:"bundlePEM"`
	P12Bytes          []byte            `json:"p12Bytes,omitempty"`
	CommonName        string            `json:"commonName"`
	DNSNames          []string          `json:"dnsNames"`
	IPAddresses       []string          `json:"ipAddresses"`
	SerialNumber      string            `json:"serialNumber"`
	NotBefore         time.Time         `json:"notBefore"`
	NotAfter          time.Time         `json:"notAfter"`
	FingerprintSHA256 string            `json:"fingerprintSHA256"`
	Certificate       *x509.Certificate `json:"-"`
}

// Issue issues a leaf certificate signed by the CA.
func (ca *CA) Issue(req IssueRequest) (*IssuedCertificate, error) {
	if ca == nil || ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, errors.New("ca is not initialized")
	}

	if len(req.Domains) == 0 && len(req.IPs) == 0 && req.CommonName == "" {
		req.Domains = []string{"localhost"}
	}
	if req.CommonName == "" {
		if len(req.Domains) > 0 {
			req.CommonName = req.Domains[0]
		} else if len(req.IPs) > 0 {
			req.CommonName = req.IPs[0]
		}
	}
	if req.Organization == "" {
		req.Organization = "TLSLens Local Development"
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}
	if req.KeyType == "" {
		req.KeyType = "ecdsa"
	}

	privKey, pubKey, err := generateKey(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	var ipAddresses []net.IP
	var ipStrings []string
	for _, ipStr := range req.IPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		parsedIP := net.ParseIP(ipStr)
		if parsedIP != nil {
			ipAddresses = append(ipAddresses, parsedIP)
			ipStrings = append(ipStrings, parsedIP.String())
		}
	}

	var dnsNames []string
	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		// If domain is an IP address string, add to IPs
		if parsedIP := net.ParseIP(domain); parsedIP != nil {
			ipAddresses = append(ipAddresses, parsedIP)
			ipStrings = append(ipStrings, parsedIP.String())
		} else {
			dnsNames = append(dnsNames, domain)
		}
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.AddDate(0, 0, req.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		AuthorityKeyId:        ca.Certificate.SubjectKeyId,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, pubKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign leaf certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	// Bundle is Leaf + Root CA
	bundlePEM := append(certPEM, ca.CertPEM...)

	// Create PKCS#12 if requested
	var p12Bytes []byte
	p12Data, p12Err := pkcs12.Encode(rand.Reader, privKey, cert, []*x509.Certificate{ca.Certificate}, req.P12Password)
	if p12Err == nil {
		p12Bytes = p12Data
	}

	sha256Sum := sha256.Sum256(derBytes)

	return &IssuedCertificate{
		CertPEM:           certPEM,
		KeyPEM:            keyPEM,
		BundlePEM:         bundlePEM,
		P12Bytes:          p12Bytes,
		CommonName:        req.CommonName,
		DNSNames:          dnsNames,
		IPAddresses:       ipStrings,
		SerialNumber:      cert.SerialNumber.Text(16),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		FingerprintSHA256: formatFingerprint(hex.EncodeToString(sha256Sum[:])),
		Certificate:       cert,
	}, nil
}

// SaveToDir saves cert.pem, key.pem, bundle.pem, and optionally cert.p12 into directory.
func (ic *IssuedCertificate) SaveToDir(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outDir, err)
	}

	if err := os.WriteFile(filepath.Join(outDir, "cert.pem"), ic.CertPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "key.pem"), ic.KeyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "bundle.pem"), ic.BundlePEM, 0644); err != nil {
		return err
	}
	if len(ic.P12Bytes) > 0 {
		if err := os.WriteFile(filepath.Join(outDir, "cert.p12"), ic.P12Bytes, 0600); err != nil {
			return err
		}
	}
	return nil
}
