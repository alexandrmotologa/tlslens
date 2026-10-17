package linter

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// Severity represents finding level: error, warning, info.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// LintFinding describes a specific standard violation or recommendation.
type LintFinding struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	Standard    string   `json:"standard"`
	Remediation string   `json:"remediation"`
}

// LintResult summarizes all findings for an analyzed certificate.
type LintResult struct {
	Subject      string        `json:"subject"`
	CommonName   string        `json:"commonName"`
	IsCA         bool          `json:"isCA"`
	Status       string        `json:"status"` // "pass", "warning", "fail"
	ErrorCount   int           `json:"errorCount"`
	WarningCount int           `json:"warningCount"`
	InfoCount    int           `json:"infoCount"`
	Findings     []LintFinding `json:"findings"`
}

// LintCertificate analyzes a single X.509 certificate against CAB Forum & RFC 5280 rules.
func LintCertificate(cert *x509.Certificate) LintResult {
	if cert == nil {
		return LintResult{Status: "fail", ErrorCount: 1, Findings: []LintFinding{
			{
				Code:        "LINT_NIL_CERT",
				Severity:    SeverityError,
				Title:       "Nil Certificate",
				Message:     "Provided certificate is nil and cannot be analyzed.",
				Standard:    "Internal",
				Remediation: "Provide a valid parsed X.509 certificate.",
			},
		}}
	}

	res := LintResult{
		Subject:    cert.Subject.String(),
		CommonName: cert.Subject.CommonName,
		IsCA:       cert.IsCA,
		Status:     "pass",
		Findings:   make([]LintFinding, 0),
	}

	// 1. Check Signature Algorithm (SHA-1 / MD5)
	lintSignatureAlgorithm(cert, &res)

	// 2. Check Public Key Strength
	lintPublicKey(cert, &res)

	// 3. Check Validity Period (CAB Forum 398 days limit for subscriber certs)
	lintValidityPeriod(cert, &res)

	// 4. Check Subject Alternative Names (RFC 6125 & CAB Forum 7.1.4.2)
	lintSubjectAlternativeNames(cert, &res)

	// 5. Check KeyUsage and ExtendedKeyUsage Coherence (RFC 5280 4.2.1.3 & 4.2.1.12)
	lintKeyUsageCoherence(cert, &res)

	// 6. Check Basic Constraints & Path Length (RFC 5280 4.2.1.9)
	lintBasicConstraints(cert, &res)

	// 7. Check Authority Key Identifier & Subject Key Identifier (RFC 5280 4.2.1.1)
	lintKeyIdentifiers(cert, &res)

	// 8. Check Revocation endpoints (OCSP / CRL)
	lintRevocationPoints(cert, &res)

	// Compute status and totals
	for _, f := range res.Findings {
		switch f.Severity {
		case SeverityError:
			res.ErrorCount++
		case SeverityWarning:
			res.WarningCount++
		case SeverityInfo:
			res.InfoCount++
		}
	}

	if res.ErrorCount > 0 {
		res.Status = "fail"
	} else if res.WarningCount > 0 {
		res.Status = "warning"
	} else {
		res.Status = "pass"
	}

	return res
}

func lintSignatureAlgorithm(cert *x509.Certificate, res *LintResult) {
	sigAlgo := cert.SignatureAlgorithm.String()
	lower := strings.ToLower(sigAlgo)

	if strings.Contains(lower, "md5") {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_SIG_MD5_FORBIDDEN",
			Severity:    SeverityError,
			Title:       "Forbidden MD5 Signature Algorithm",
			Message:     fmt.Sprintf("Certificate is signed using %s, which is cryptographically broken and forbidden.", sigAlgo),
			Standard:    "CAB Forum BR §7.1.3.2 / RFC 6151",
			Remediation: "Reissue the certificate using SHA-256 or better (e.g. SHA256-RSA or ECDSA-SHA256).",
		})
	} else if strings.Contains(lower, "sha1") {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_SIG_SHA1_DEPRECATED",
			Severity:    SeverityError,
			Title:       "Insecure SHA-1 Signature Algorithm",
			Message:     fmt.Sprintf("Certificate is signed using %s. SHA-1 collisions have been demonstrated and major browsers reject it.", sigAlgo),
			Standard:    "CAB Forum BR §7.1.3.2 / RFC 6818",
			Remediation: "Migrate to SHA-256 or SHA-384 signature algorithms.",
		})
	}
}

func lintPublicKey(cert *x509.Certificate, res *LintResult) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bitLen := k.N.BitLen()
		if bitLen < 2048 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_RSA_KEY_TOO_SHORT",
				Severity:    SeverityError,
				Title:       "RSA Key Modulus Below 2048 Bits",
				Message:     fmt.Sprintf("RSA key length is %d bits. CAB Forum requirements mandate at least 2048-bit modulus for RSA.", bitLen),
				Standard:    "CAB Forum BR §6.1.5 / NIST SP 800-57",
				Remediation: "Generate RSA private keys with at least 2048 or 4096 bits.",
			})
		}
		if k.E < 65537 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_RSA_SMALL_EXPONENT",
				Severity:    SeverityWarning,
				Title:       "RSA Small Public Exponent",
				Message:     fmt.Sprintf("RSA public exponent e=%d is below standard F4 (65537). Small exponents can be vulnerable to Coppersmith attacks.", k.E),
				Standard:    "RFC 3447 / CAB Forum BR §6.1.5",
				Remediation: "Use standard public exponent e=65537 for RSA key generation.",
			})
		}
	case *ecdsa.PublicKey:
		bitSize := k.Curve.Params().BitSize
		if bitSize < 256 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_ECDSA_CURVE_WEAK",
				Severity:    SeverityError,
				Title:       "Weak Elliptic Curve (< 256 bits)",
				Message:     fmt.Sprintf("ECDSA curve size is %d bits. Minimum recommended curve size is P-256 (256 bits).", bitSize),
				Standard:    "CAB Forum BR §6.1.5",
				Remediation: "Use standard P-256 (secp256r1) or P-384 curves.",
			})
		}
	}
}

func lintValidityPeriod(cert *x509.Certificate, res *LintResult) {
	if cert.IsCA {
		return // CA certificates typically have longer lifespans (5 - 20 years)
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	days := int(duration.Hours() / 24)

	// Since September 1, 2020, Apple, Google Chrome, and Mozilla enforce max 398 days for TLS server certs
	if days > 398 {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_VALIDITY_EXCEEDS_398_DAYS",
			Severity:    SeverityWarning,
			Title:       "Validity Period Exceeds 398 Days",
			Message:     fmt.Sprintf("Certificate validity is %d days. Modern root stores (Apple, Google, Mozilla) reject server certificates valid for > 398 days.", days),
			Standard:    "CAB Forum Ballot SC22 / Apple TLS Policy",
			Remediation: "Limit server certificate validity period to 397 days or fewer (e.g. 90 or 365 days).",
		})
	}

	if cert.NotBefore.After(cert.NotAfter) {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_NOTBEFORE_AFTER_NOTAFTER",
			Severity:    SeverityError,
			Title:       "NotBefore Date is After NotAfter",
			Message:     "Certificate activation date (NotBefore) occurs chronologically after expiration date (NotAfter).",
			Standard:    "RFC 5280 §4.1.2.5",
			Remediation: "Ensure certificate issuance sets NotBefore prior to NotAfter.",
		})
	}
}

func lintSubjectAlternativeNames(cert *x509.Certificate, res *LintResult) {
	hasSAN := len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0

	if !cert.IsCA {
		if !hasSAN {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_SAN_MISSING",
				Severity:    SeverityError,
				Title:       "Subject Alternative Name (SAN) Missing",
				Message:     "The certificate lacks Subject Alternative Name extension. Browsers no longer evaluate Subject Common Name (CN) for host matching.",
				Standard:    "RFC 6125 §6.4.4 / CAB Forum BR §7.1.4.2",
				Remediation: "Include all target DNS hostnames or IP addresses inside the Subject Alternative Name extension.",
			})
		} else if cert.Subject.CommonName != "" {
			// Check if CN matches at least one SAN entry
			cnMatched := false
			for _, dns := range cert.DNSNames {
				if strings.EqualFold(dns, cert.Subject.CommonName) {
					cnMatched = true
					break
				}
			}
			if !cnMatched && len(cert.DNSNames) > 0 {
				res.Findings = append(res.Findings, LintFinding{
					Code:        "LINT_CN_NOT_IN_SAN",
					Severity:    SeverityInfo,
					Title:       "Subject Common Name Not Present in SAN",
					Message:     fmt.Sprintf("Common Name '%s' is not listed among DNS SAN entries.", cert.Subject.CommonName),
					Standard:    "CAB Forum BR §7.1.4.2.2",
					Remediation: "Ensure Common Name is mirrored as an entry in the Subject Alternative Name extension.",
				})
			}
		}
	}
}

func lintKeyUsageCoherence(cert *x509.Certificate, res *LintResult) {
	// If it's a leaf cert (not CA) but has KeyUsageCertSign or KeyUsageCRLSign
	if !cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_LEAF_HAS_CERTSIGN",
				Severity:    SeverityError,
				Title:       "Leaf Certificate Has CertSign KeyUsage",
				Message:     "End-entity subscriber certificate specifies KeyUsage 'Certificate Sign' without IsCA being true.",
				Standard:    "RFC 5280 §4.2.1.3",
				Remediation: "Remove KeyUsageCertSign from subscriber leaf certificates.",
			})
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_LEAF_HAS_CRLSIGN",
				Severity:    SeverityWarning,
				Title:       "Leaf Certificate Has CRLSign KeyUsage",
				Message:     "End-entity subscriber certificate specifies CRL Sign key usage, but is not configured as a CA.",
				Standard:    "RFC 5280 §4.2.1.3",
				Remediation: "Remove KeyUsageCRLSign unless this entity is a dedicated CRL signer.",
			})
		}
	}

	// For Server Authentication EKU:
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}

	if hasServerAuth && cert.KeyUsage != 0 {
		switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				res.Findings = append(res.Findings, LintFinding{
					Code:        "LINT_ECDSA_SERVERAUTH_NO_DIGITALSIG",
					Severity:    SeverityError,
					Title:       "ECDSA ServerAuth Missing DigitalSignature KeyUsage",
					Message:     "ECDSA certificate with Server Authentication extended key usage requires KeyUsageDigitalSignature for TLS ECDHE handshake authentication.",
					Standard:    "RFC 5280 §4.2.1.3 / CAB Forum BR §7.1.2.3",
					Remediation: "Enable KeyUsageDigitalSignature for ECDSA certificates.",
				})
			}
			if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
				res.Findings = append(res.Findings, LintFinding{
					Code:        "LINT_ECDSA_HAS_KEYENCIPHERMENT",
					Severity:    SeverityWarning,
					Title:       "ECDSA Certificate Contains KeyEncipherment",
					Message:     "KeyUsageKeyEncipherment is only valid for RSA key transport. ECDSA does not support RSA key encipherment.",
					Standard:    "RFC 5280 §4.2.1.3",
					Remediation: "Remove KeyUsageKeyEncipherment from ECDSA certificates.",
				})
			}
		case *rsa.PublicKey:
			if cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
				res.Findings = append(res.Findings, LintFinding{
					Code:        "LINT_RSA_SERVERAUTH_NO_VALID_USAGE",
					Severity:    SeverityError,
					Title:       "RSA ServerAuth Missing DigitalSignature or KeyEncipherment",
					Message:     "RSA certificate configured for ServerAuth must contain DigitalSignature (for DHE/ECDHE) or KeyEncipherment (for RSA key exchange).",
					Standard:    "RFC 5280 §4.2.1.3",
					Remediation: "Add KeyUsageDigitalSignature and KeyUsageKeyEncipherment to RSA TLS server certificates.",
				})
			}
		}
	}
}

func lintBasicConstraints(cert *x509.Certificate, res *LintResult) {
	if cert.IsCA {
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			res.Findings = append(res.Findings, LintFinding{
				Code:        "LINT_CA_MISSING_CERTSIGN",
				Severity:    SeverityError,
				Title:       "CA Certificate Missing CertSign KeyUsage",
				Message:     "BasicConstraints IsCA is true, but KeyUsage does not assert Certificate Sign.",
				Standard:    "RFC 5280 §4.2.1.9 / §4.2.1.3",
				Remediation: "Add KeyUsageCertSign to CA certificates.",
			})
		}
	}
}

func lintKeyIdentifiers(cert *x509.Certificate, res *LintResult) {
	if !cert.IsCA && len(cert.AuthorityKeyId) == 0 {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_MISSING_AUTHORITY_KEY_ID",
			Severity:    SeverityInfo,
			Title:       "Missing Authority Key Identifier (AKID)",
			Message:     "End-entity certificate does not contain Authority Key Identifier extension, which assists TLS clients with chain building.",
			Standard:    "RFC 5280 §4.2.1.1",
			Remediation: "Configure CA to include Authority Key Identifier pointing to issuer Subject Key Identifier.",
		})
	}
}

func lintRevocationPoints(cert *x509.Certificate, res *LintResult) {
	if !cert.IsCA && len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		res.Findings = append(res.Findings, LintFinding{
			Code:        "LINT_NO_REVOCATION_INFO",
			Severity:    SeverityInfo,
			Title:       "No OCSP or CRL Distribution Points",
			Message:     "Certificate contains neither OCSP responder URLs nor CRL distribution points. Clients cannot verify real-time revocation status.",
			Standard:    "CAB Forum BR §7.1.2.2.4",
			Remediation: "Specify an OCSP responder URI or CRL distribution URL if issuing production certificates.",
		})
	}
}
