package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// AuditRiskItem highlights a security weakness or misconfiguration.
type AuditRiskItem struct {
	Severity    string `json:"severity"` // "critical", "warning", "info"
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// ProtocolCheck tracks status of a TLS protocol version.
type ProtocolCheck struct {
	Version string `json:"version"`
	Allowed bool   `json:"allowed"`
	Secure  bool   `json:"secure"`
}

// AuditResult summarizes security posture, score, and grade.
type AuditResult struct {
	Target             string                  `json:"target"`
	Score              int                     `json:"score"`
	Grade              string                  `json:"grade"` // "A+", "A", "B", "C", "F"
	Protocols          []ProtocolCheck         `json:"protocols"`
	SupportedCiphers   []handshake.CipherInfo  `json:"supportedCiphers"`
	HasPFS             bool                    `json:"hasPfs"`
	HasTLS13           bool                    `json:"hasTls13"`
	HasDeprecatedTLS   bool                    `json:"hasDeprecatedTls"`
	HasWeakCiphers     bool                    `json:"hasWeakCiphers"`
	CertificateValid   bool                    `json:"certificateValid"`
	Risks              []AuditRiskItem         `json:"risks"`
	DurationMs         float64                 `json:"durationMs"`
}

// AuditEndpoint audits a target TLS host for protocol versions, ciphers, and security risks.
func AuditEndpoint(ctx context.Context, target string) (*AuditResult, error) {
	start := time.Now()

	probeRes, err := handshake.ProbeEndpoint(ctx, target, handshake.ProbeOptions{
		Timeout: 5 * time.Second,
	})
	if err != nil && probeRes == nil {
		return nil, fmt.Errorf("audit failed to connect to target: %w", err)
	}

	score := 100
	var risks []AuditRiskItem

	// 1. Check TLS 1.3 support
	tls13Check := testProtocolVersion(ctx, target, tls.VersionTLS13, tls.VersionTLS13)
	// 2. Check TLS 1.2 support
	tls12Check := testProtocolVersion(ctx, target, tls.VersionTLS12, tls.VersionTLS12)
	// 3. Check legacy TLS 1.0 support
	tls10Check := testProtocolVersion(ctx, target, tls.VersionTLS10, tls.VersionTLS10)
	// 4. Check legacy TLS 1.1 support
	tls11Check := testProtocolVersion(ctx, target, tls.VersionTLS11, tls.VersionTLS11)

	protocols := []ProtocolCheck{
		{Version: "TLS 1.3", Allowed: tls13Check, Secure: true},
		{Version: "TLS 1.2", Allowed: tls12Check, Secure: true},
		{Version: "TLS 1.1", Allowed: tls11Check, Secure: false},
		{Version: "TLS 1.0", Allowed: tls10Check, Secure: false},
	}

	hasDeprecatedTLS := tls10Check || tls11Check
	if tls10Check {
		score -= 30
		risks = append(risks, AuditRiskItem{
			Severity:    "critical",
			Title:       "Deprecated TLS 1.0 Enabled",
			Description: "Target endpoint permits legacy TLS 1.0 handshakes vulnerable to POODLE and BEAST attacks.",
			Remediation: "Set minimum TLS version to TLS 1.2 or TLS 1.3 in server configuration.",
		})
	}
	if tls11Check {
		score -= 20
		risks = append(risks, AuditRiskItem{
			Severity:    "warning",
			Title:       "Deprecated TLS 1.1 Enabled",
			Description: "Target endpoint permits TLS 1.1 handshakes which are deprecated by RFC 8996.",
			Remediation: "Disable TLS 1.0 and TLS 1.1 protocols in server SSL settings.",
		})
	}
	if !tls13Check {
		score -= 10
		risks = append(risks, AuditRiskItem{
			Severity:    "info",
			Title:       "TLS 1.3 Not Enabled",
			Description: "Server did not negotiate TLS 1.3, missing 1-RTT performance gains and modern cryptographic security.",
			Remediation: "Enable TLS 1.3 on your reverse proxy or web server.",
		})
	}

	// Cipher evaluation
	hasPFS := false
	hasWeakCiphers := false
	var ciphers []handshake.CipherInfo

	if probeRes != nil && probeRes.Cipher.Name != "" {
		ciphers = append(ciphers, probeRes.Cipher)
		if probeRes.Cipher.IsPFS {
			hasPFS = true
		}
		if probeRes.Cipher.SecurityStatus == "weak" || probeRes.Cipher.SecurityStatus == "insecure" {
			hasWeakCiphers = true
			score -= 25
			risks = append(risks, AuditRiskItem{
				Severity:    "warning",
				Title:       fmt.Sprintf("Weak Cipher Suite Selected: %s", probeRes.Cipher.Name),
				Description: "The negotiated cipher suite utilizes CBC mode or lacks authenticated encryption (AEAD).",
				Remediation: "Prioritize AEAD ciphers such as AES-GCM and ChaCha20-Poly1305.",
			})
		}
	}

	// Certificate evaluation
	certValid := true
	if probeRes != nil && len(probeRes.PeerCertificates) > 0 {
		leaf := probeRes.PeerCertificates[0]
		if leaf.IsExpired {
			certValid = false
			score -= 35
			risks = append(risks, AuditRiskItem{
				Severity:    "critical",
				Title:       "Certificate Expired",
				Description: fmt.Sprintf("Certificate expired on %s.", leaf.NotAfter.Format("2006-01-02")),
				Remediation: "Renew and deploy an active certificate immediately.",
			})
		} else if leaf.ExpiresSoon {
			risks = append(risks, AuditRiskItem{
				Severity:    "warning",
				Title:       fmt.Sprintf("Certificate Expiring Soon (%d days)", leaf.DaysRemaining),
				Description: "Certificate expiration is approaching within 30 days.",
				Remediation: "Schedule automated certificate renewal via TLSLens or ACME / Let's Encrypt.",
			})
		}

		if leaf.KeyType == "RSA" && leaf.KeyLength < 2048 {
			score -= 30
			risks = append(risks, AuditRiskItem{
				Severity:    "critical",
				Title:       fmt.Sprintf("Weak RSA Key Length (%d bits)", leaf.KeyLength),
				Description: "RSA keys below 2048 bits do not provide sufficient cryptographic strength.",
				Remediation: "Reissue certificate with RSA 2048, RSA 4096, or ECDSA P-256.",
			})
		}

		if strings.Contains(strings.ToLower(leaf.SignatureAlgorithm), "sha1") {
			score -= 30
			risks = append(risks, AuditRiskItem{
				Severity:    "critical",
				Title:       "Weak SHA-1 Signature Algorithm",
				Description: "SHA-1 signatures are cryptographically broken and rejected by modern browsers.",
				Remediation: "Reissue certificate using SHA-256 (e.g. SHA256-RSA or ECDSA-SHA256).",
			})
		}
	}

	if score < 0 {
		score = 0
	}

	grade := calculateGrade(score)

	return &AuditResult{
		Target:             target,
		Score:              score,
		Grade:              grade,
		Protocols:          protocols,
		SupportedCiphers:   ciphers,
		HasPFS:             hasPFS,
		HasTLS13:           tls13Check,
		HasDeprecatedTLS:   hasDeprecatedTLS,
		HasWeakCiphers:     hasWeakCiphers,
		CertificateValid:   certValid,
		Risks:              risks,
		DurationMs:         float64(time.Since(start).Microseconds()) / 1000.0,
	}, nil
}

func testProtocolVersion(ctx context.Context, target string, minVer, maxVer uint16) bool {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tlsConfig := &tls.Config{
		MinVersion:         minVer,
		MaxVersion:         maxVer,
		InsecureSkipVerify: true,
	}

	host := target
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(target)
		if err == nil {
			host = h
		}
	}
	tlsConfig.ServerName = host

	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

func calculateGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	default:
		return "F"
	}
}
