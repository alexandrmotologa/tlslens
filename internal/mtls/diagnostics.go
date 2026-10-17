package mtls

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AlertDefinition defines root causes and remediation guidance for a TLS alert.
type AlertDefinition struct {
	Code             int      `json:"code"`
	Name             string   `json:"name"`
	Summary          string   `json:"summary"`
	ProbableCause    string   `json:"probableCause"`
	RemediationSteps []string `json:"remediationSteps"`
	VerificationTip  string   `json:"verificationTip"`
}

// KnownAlerts maps standard TLS alert codes to diagnostics.
var KnownAlerts = map[int]AlertDefinition{
	40: {
		Code:          40,
		Name:          "handshake_failure",
		Summary:       "Server and client could not negotiate a mutually acceptable set of security parameters",
		ProbableCause: "No shared cipher suites, incompatible TLS protocol version, or mismatched signature algorithms between client and server.",
		RemediationSteps: []string{
			"Verify that client supports at least one cipher suite configured on the server.",
			"Check minimum and maximum TLS version constraints on both sides (e.g. server requires TLS 1.3 while client only supports TLS 1.2).",
			"If using ECDSA client certificates, ensure server supports the EC curve used (such as secp256r1).",
		},
		VerificationTip: "Run `tlslens audit <target>` to review supported cipher suites and protocol versions.",
	},
	41: {
		Code:          41,
		Name:          "no_certificate",
		Summary:       "Server requested a client certificate during handshake, but none was provided",
		ProbableCause: "Client configuration did not attach a client certificate to the TLS connection.",
		RemediationSteps: []string{
			"Attach a valid client certificate and private key in your client's TLS configuration.",
			"If testing with curl, supply `--cert client.crt --key client.key`.",
		},
		VerificationTip: "Check that your HTTP client or proxy has a non-empty `tls.Certificate` slice.",
	},
	42: {
		Code:          42,
		Name:          "bad_certificate",
		Summary:       "The presented client certificate was corrupt, has an invalid signature, or lacks required extensions",
		ProbableCause: "Certificate signature could not be verified, ASN.1 is malformed, or certificate lacks KeyUsageDigitalSignature / ExtKeyUsageClientAuth.",
		RemediationSteps: []string{
			"Verify that the certificate includes `ExtKeyUsageClientAuth` (TLS Web Client Authentication).",
			"Verify that Key Usage includes `Digital Signature`.",
			"Re-generate the client certificate using `tlslens cert issue` to ensure compliant X.509 v3 extensions.",
		},
		VerificationTip: "Inspect certificate extensions with `tlslens inspect` or view the Certificate Hierarchy tab.",
	},
	45: {
		Code:          45,
		Name:          "certificate_expired",
		Summary:       "The client certificate validity period is outside the current system time window",
		ProbableCause: "Certificate NotAfter date has expired, or NotBefore date is in the future due to clock skew.",
		RemediationSteps: []string{
			"Re-issue the client certificate with a fresh validity window.",
			"Verify system time and NTP synchronization across both client and server machines.",
		},
		VerificationTip: "Compare system clock `time.Now()` with certificate NotBefore / NotAfter timestamps.",
	},
	46: {
		Code:          46,
		Name:          "certificate_unknown",
		Summary:       "Client certificate was rejected by server trust evaluation",
		ProbableCause: "The issuer CA of the client certificate is not included in the server's trusted client CA bundle (`ClientCAs` pool).",
		RemediationSteps: []string{
			"Add the root or intermediate CA that signed the client certificate to the server's `ClientCAs` pool.",
			"Ensure the client certificate chain sends required intermediate certificates along with the leaf certificate.",
			"Check that the certificate issuer Subject Key ID matches the CA Authority Key ID.",
		},
		VerificationTip: "Use `tlslens ca trust` or configure `tls.Config.ClientCAs` with the issuer CA certificate.",
	},
	48: {
		Code:          48,
		Name:          "unknown_ca",
		Summary:       "A valid certificate chain was received, but could not be verified to a trusted root CA",
		ProbableCause: "Missing intermediate CA in the bundle or untrusted root authority.",
		RemediationSteps: []string{
			"Ensure bundle.pem contains both the leaf certificate and all intermediate certificates.",
			"Install the root CA into the server's system trust store or pass explicitly via CA pool.",
		},
		VerificationTip: "Inspect the full chain in TLSLens to see where the trust path terminates.",
	},
	112: {
		Code:          112,
		Name:          "unrecognized_name",
		Summary:       "The server does not recognize the Server Name Indication (SNI) sent by client",
		ProbableCause: "Client sent an SNI hostname that does not match any virtual host or certificate configured on the server.",
		RemediationSteps: []string{
			"Verify that client SNI matches one of the Subject Alternative Names (SANs) on the server certificate.",
			"If connecting to an IP address, configure `InsecureSkipVerify` or add the IP to SAN IPAddresses.",
		},
		VerificationTip: "Review SAN DNS and IP entries on the server certificate.",
	},
	116: {
		Code:          116,
		Name:          "certificate_required",
		Summary:       "TLS 1.3 server requires client authentication and none was provided",
		ProbableCause: "Server policy enforces mutual TLS (`RequireAndVerifyClientCert`), but client sent an empty certificate response.",
		RemediationSteps: []string{
			"Configure client with a valid client certificate and matching private key.",
			"Ensure client TLS configuration allows presenting certificates for the target host.",
		},
		VerificationTip: "Check server client authentication policy setting.",
	},
}

// DiagnosticReport is the structured output of an mTLS handshake error analysis.
type DiagnosticReport struct {
	OriginalError    string          `json:"originalError"`
	AlertCode        int             `json:"alertCode,omitempty"`
	AlertName        string          `json:"alertName,omitempty"`
	Summary          string          `json:"summary"`
	ProbableCause    string          `json:"probableCause"`
	RemediationSteps []string        `json:"remediationSteps"`
	VerificationTip  string          `json:"verificationTip"`
	CertificateAudit *CertAuditCheck `json:"certificateAudit,omitempty"`
}

// CertAuditCheck details client certificate validity against server expectations.
type CertAuditCheck struct {
	HasClientCert     bool     `json:"hasClientCert"`
	CommonName        string   `json:"commonName"`
	IsExpired         bool     `json:"isExpired"`
	NotBefore         string   `json:"notBefore"`
	NotAfter          string   `json:"notAfter"`
	HasClientAuthExt  bool     `json:"hasClientAuthExt"`
	HasDigitalSig     bool     `json:"hasDigitalSig"`
	IssuerMatchesCA   bool     `json:"issuerMatchesCa"`
	AuditFindings     []string `json:"auditFindings"`
}

var alertRegex = regexp.MustCompile(`(?:alert\((\d+)\)|tls:\s*(?:remote error:\s*)?tls:\s*(?:alert:\s*)?([a-z_]+))`)

// DiagnoseError analyzes an error returned during an mTLS handshake.
func DiagnoseError(err error, clientCert *x509.Certificate, serverCA *x509.Certificate) DiagnosticReport {
	if err == nil {
		return DiagnosticReport{
			Summary: "Handshake succeeded. Mutual TLS connection established successfully.",
		}
	}

	errStr := err.Error()
	report := DiagnosticReport{
		OriginalError: errStr,
	}

	// 1. Audit client certificate directly if provided
	if clientCert != nil {
		audit := auditClientCert(clientCert, serverCA)
		report.CertificateAudit = &audit
	}

	// 2. Identify alert code from error message
	code := extractAlertCode(errStr)
	if def, ok := KnownAlerts[code]; ok {
		report.AlertCode = def.Code
		report.AlertName = def.Name
		report.Summary = def.Summary
		report.ProbableCause = def.ProbableCause
		report.RemediationSteps = def.RemediationSteps
		report.VerificationTip = def.VerificationTip
		return report
	}

	// 3. Match known string patterns
	lower := strings.ToLower(errStr)
	switch {
	case strings.Contains(lower, "bad certificate"):
		def := KnownAlerts[42]
		fillReport(&report, def)
	case strings.Contains(lower, "certificate unknown"):
		def := KnownAlerts[46]
		fillReport(&report, def)
	case strings.Contains(lower, "expired") || strings.Contains(lower, "not yet valid"):
		def := KnownAlerts[45]
		fillReport(&report, def)
	case strings.Contains(lower, "handshake failure"):
		def := KnownAlerts[40]
		fillReport(&report, def)
	case strings.Contains(lower, "unknown authority") || strings.Contains(lower, "unknown ca"):
		def := KnownAlerts[48]
		fillReport(&report, def)
	case strings.Contains(lower, "unrecognized name"):
		def := KnownAlerts[112]
		fillReport(&report, def)
	case strings.Contains(lower, "certificate required"):
		def := KnownAlerts[116]
		fillReport(&report, def)
	default:
		report.Summary = "TLS connection failed during handshake"
		report.ProbableCause = "Network reset, rejected certificate, or incompatible configuration."
		report.RemediationSteps = []string{
			"Verify target host and port are reachable.",
			"Inspect client certificate and key matching.",
			"Check server logs for corresponding connection drops.",
		}
		report.VerificationTip = "Test connectivity with `tlslens inspect <host:port>`."
	}

	return report
}

func fillReport(r *DiagnosticReport, def AlertDefinition) {
	r.AlertCode = def.Code
	r.AlertName = def.Name
	r.Summary = def.Summary
	r.ProbableCause = def.ProbableCause
	r.RemediationSteps = def.RemediationSteps
	r.VerificationTip = def.VerificationTip
}

func extractAlertCode(errStr string) int {
	matches := alertRegex.FindStringSubmatch(errStr)
	if len(matches) > 1 && matches[1] != "" {
		code, _ := strconv.Atoi(matches[1])
		return code
	}

	// Search for numeric alert in text like "alert(46)" or "alert 46"
	reNum := regexp.MustCompile(`alert\s*\(?(\d+)\)?`)
	numMatch := reNum.FindStringSubmatch(errStr)
	if len(numMatch) > 1 {
		code, _ := strconv.Atoi(numMatch[1])
		return code
	}

	return 0
}

func auditClientCert(cert *x509.Certificate, trustedCA *x509.Certificate) CertAuditCheck {
	now := time.Now().UTC()
	isExpired := now.After(cert.NotAfter) || now.Before(cert.NotBefore)

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}

	hasDigitalSig := (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0

	issuerMatches := false
	var findings []string

	if isExpired {
		findings = append(findings, fmt.Sprintf("Certificate is expired or not yet valid (valid: %s to %s)", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
	}
	if !hasClientAuth {
		findings = append(findings, "Missing ExtKeyUsageClientAuth (TLS Web Client Authentication) extension")
	}
	if !hasDigitalSig {
		findings = append(findings, "Missing KeyUsageDigitalSignature in Key Usage extension")
	}

	if trustedCA != nil {
		if err := cert.CheckSignatureFrom(trustedCA); err == nil {
			issuerMatches = true
		} else {
			findings = append(findings, fmt.Sprintf("Certificate was not signed by server's trusted CA (%s)", trustedCA.Subject.CommonName))
		}
	}

	if len(findings) == 0 {
		findings = append(findings, "Client certificate passes all structural and cryptographic checks")
	}

	return CertAuditCheck{
		HasClientCert:    true,
		CommonName:       cert.Subject.CommonName,
		IsExpired:        isExpired,
		NotBefore:        cert.NotBefore.Format(time.RFC3339),
		NotAfter:         cert.NotAfter.Format(time.RFC3339),
		HasClientAuthExt: hasClientAuth,
		HasDigitalSig:    hasDigitalSig,
		IssuerMatchesCA:  issuerMatches,
		AuditFindings:    findings,
	}
}
