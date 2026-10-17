package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CAConfig defines parameters for creating or loading a Certificate Authority.
type CAConfig struct {
	CommonName   string
	Organization string
	Country      string
	ValidityDays int
	KeyType      string // "ecdsa", "rsa2048", "rsa4096", "ed25519"
	StorageDir   string
}

// CA represents a root Certificate Authority with its certificate and private key.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
	CertPath    string
	KeyPath     string
	StorageDir  string
}

// CACredentialsInfo contains inspectable metadata for the CA.
type CACredentialsInfo struct {
	CommonName           string    `json:"commonName"`
	Organization         string    `json:"organization"`
	Country              string    `json:"country"`
	SerialNumber         string    `json:"serialNumber"`
	NotBefore            time.Time `json:"notBefore"`
	NotAfter             time.Time `json:"notAfter"`
	DaysRemaining        int       `json:"daysRemaining"`
	KeyType              string    `json:"keyType"`
	KeyLength            int       `json:"keyLength"`
	SignatureAlgorithm   string    `json:"signatureAlgorithm"`
	FingerprintSHA256    string    `json:"fingerprintSHA256"`
	FingerprintSHA1      string    `json:"fingerprintSHA1"`
	CertPath             string    `json:"certPath"`
	KeyPath              string    `json:"keyPath"`
	IsTrustedByOS        bool      `json:"isTrustedByOS"`
	StorageDir           string    `json:"storageDir"`
}

// GetDefaultStorageDir returns ~/.tlslens/ca directory.
func GetDefaultStorageDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "certs", "ca"), nil
	}
	return filepath.Join(home, ".tlslens", "ca"), nil
}

// IsCAInitialized checks if root-ca.crt and root-ca.key exist in the directory.
func IsCAInitialized(dir string) bool {
	certPath := filepath.Join(dir, "root-ca.crt")
	keyPath := filepath.Join(dir, "root-ca.key")

	_, err1 := os.Stat(certPath)
	_, err2 := os.Stat(keyPath)
	return err1 == nil && err2 == nil
}

// NewCA creates a fresh root CA and persists it to disk if StorageDir is provided.
func NewCA(cfg CAConfig) (*CA, error) {
	if cfg.CommonName == "" {
		cfg.CommonName = "TLSLens Local Development Root CA"
	}
	if cfg.Organization == "" {
		cfg.Organization = "TLSLens"
	}
	if cfg.Country == "" {
		cfg.Country = "US"
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 3650 // 10 years
	}
	if cfg.KeyType == "" {
		cfg.KeyType = "ecdsa"
	}

	privKey, pubKey, err := generateKey(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	spkiBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	skid := sha1.Sum(spkiBytes)

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
			Country:      []string{cfg.Country},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(0, 0, cfg.ValidityDays),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          skid[:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
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

	instance := &CA{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		StorageDir:  cfg.StorageDir,
	}

	if cfg.StorageDir != "" {
		if err := os.MkdirAll(cfg.StorageDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create storage directory %s: %w", cfg.StorageDir, err)
		}
		instance.CertPath = filepath.Join(cfg.StorageDir, "root-ca.crt")
		instance.KeyPath = filepath.Join(cfg.StorageDir, "root-ca.key")

		if err := os.WriteFile(instance.CertPath, certPEM, 0644); err != nil {
			return nil, fmt.Errorf("failed to write CA certificate to %s: %w", instance.CertPath, err)
		}
		if err := os.WriteFile(instance.KeyPath, keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("failed to write CA key to %s: %w", instance.KeyPath, err)
		}
	}

	return instance, nil
}

// LoadCA loads an existing CA from disk.
func LoadCA(storageDir string) (*CA, error) {
	certPath := filepath.Join(storageDir, "root-ca.crt")
	keyPath := filepath.Join(storageDir, "root-ca.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", certPath, err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key from %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid or missing CERTIFICATE block in root-ca.crt")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid or missing private key block in root-ca.key")
	}

	var privKey crypto.Signer
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err == nil {
		if signer, ok := parsedKey.(crypto.Signer); ok {
			privKey = signer
		}
	}

	if privKey == nil {
		if ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
			privKey = ecKey
		} else if rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
			privKey = rsaKey
		}
	}

	if privKey == nil {
		return nil, errors.New("unsupported or unparseable private key type")
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		CertPath:    certPath,
		KeyPath:     keyPath,
		StorageDir:  storageDir,
	}, nil
}

// Inspect returns metadata and OS trust status for the CA.
func (ca *CA) Inspect() CACredentialsInfo {
	now := time.Now().UTC()
	daysRemaining := int(ca.Certificate.NotAfter.Sub(now).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	sha256Sum := sha256.Sum256(ca.Certificate.Raw)
	sha1Sum := sha1.Sum(ca.Certificate.Raw)

	keyType, keyLen := getKeyInfo(ca.Certificate.PublicKey)
	isTrusted := CheckRootCATrusted(ca.Certificate)

	return CACredentialsInfo{
		CommonName:         ca.Certificate.Subject.CommonName,
		Organization:       strings.Join(ca.Certificate.Subject.Organization, ", "),
		Country:            strings.Join(ca.Certificate.Subject.Country, ", "),
		SerialNumber:       ca.Certificate.SerialNumber.Text(16),
		NotBefore:          ca.Certificate.NotBefore,
		NotAfter:           ca.Certificate.NotAfter,
		DaysRemaining:      daysRemaining,
		KeyType:            keyType,
		KeyLength:          keyLen,
		SignatureAlgorithm: ca.Certificate.SignatureAlgorithm.String(),
		FingerprintSHA256:  formatFingerprint(hex.EncodeToString(sha256Sum[:])),
		FingerprintSHA1:    formatFingerprint(hex.EncodeToString(sha1Sum[:])),
		CertPath:           ca.CertPath,
		KeyPath:            ca.KeyPath,
		IsTrustedByOS:      isTrusted,
		StorageDir:         ca.StorageDir,
	}
}

func generateKey(keyType string) (crypto.Signer, crypto.PublicKey, error) {
	switch strings.ToLower(keyType) {
	case "rsa2048", "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case "rsa4096":
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	case "ecdsa", "p256", "ecdsa-p256":
		fallthrough
	default:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	}
}

func getKeyInfo(pub crypto.PublicKey) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

func formatFingerprint(hexStr string) string {
	hexStr = strings.ToUpper(hexStr)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}
