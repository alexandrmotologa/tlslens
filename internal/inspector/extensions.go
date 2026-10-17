package inspector

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// ParseCertSummary extracts structured metadata and extensions from an x509.Certificate.
func ParseCertSummary(cert *x509.Certificate) handshake.CertSummary {
	if cert == nil {
		return handshake.CertSummary{}
	}

	now := time.Now().UTC()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)
	expiresSoon := !isExpired && daysRemaining <= 30

	sha256Sum := sha256.Sum256(cert.Raw)

	var ipStrings []string
	for _, ip := range cert.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	keyType, keyLen := getKeyInfo(cert.PublicKey)

	return handshake.CertSummary{
		CommonName:         cert.Subject.CommonName,
		Subject:            formatPKIXName(cert.Subject.String()),
		Issuer:             formatPKIXName(cert.Issuer.String()),
		SerialNumber:       cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysRemaining:      daysRemaining,
		IsExpired:          isExpired,
		ExpiresSoon:        expiresSoon,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipStrings,
		KeyType:            keyType,
		KeyLength:          keyLen,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		FingerprintSHA256:  formatFingerprint(hex.EncodeToString(sha256Sum[:])),
		IsCA:               cert.IsCA,
		KeyUsage:           FormatKeyUsage(cert.KeyUsage),
		ExtKeyUsage:        FormatExtKeyUsage(cert.ExtKeyUsage),
		OCSPServers:        cert.OCSPServer,
		CRLDistribution:    cert.CRLDistributionPoints,
	}
}

// FormatKeyUsage converts bitmask into human-readable list.
func FormatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Non-Repudiation")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

// FormatExtKeyUsage converts ExtKeyUsage constants into readable names.
func FormatExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var names []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Authentication (TLS Web Server)")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Authentication (TLS Web Client)")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection (S/MIME)")
		case x509.ExtKeyUsageIPSECEndSystem:
			names = append(names, "IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			names = append(names, "IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			names = append(names, "IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		default:
			names = append(names, fmt.Sprintf("Extended Key Usage (%d)", eku))
		}
	}
	return names
}

func getKeyInfo(pub any) (string, int) {
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

func formatPKIXName(raw string) string {
	raw = strings.TrimSpace(raw)
	return raw
}

// FingerprintSHA1 calculates SHA-1 fingerprint for an X.509 certificate.
func FingerprintSHA1(cert *x509.Certificate) string {
	sha1Sum := sha1.Sum(cert.Raw)
	return formatFingerprint(hex.EncodeToString(sha1Sum[:]))
}
