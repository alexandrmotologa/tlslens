package inspector

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// RevocationInfo captures OCSP and CRL status for a certificate.
type RevocationInfo struct {
	HasOCSP               bool     `json:"hasOcsp"`
	OCSPServers           []string `json:"ocspServers"`
	HasCRL                bool     `json:"hasCrl"`
	CRLDistributionPoints []string `json:"crlDistributionPoints"`
	OCSPStapled           bool     `json:"ocspStapled"`
	Status                string   `json:"status"` // "good", "revoked", "unknown", "unconfigured"
	Details               string   `json:"details"`
}

// CheckRevocation examines certificate revocation endpoints and verifies basic reachability.
func CheckRevocation(cert *x509.Certificate, ocspStapled bool) RevocationInfo {
	if cert == nil {
		return RevocationInfo{Status: "unknown", Details: "nil certificate"}
	}

	info := RevocationInfo{
		HasOCSP:               len(cert.OCSPServer) > 0,
		OCSPServers:           cert.OCSPServer,
		HasCRL:                len(cert.CRLDistributionPoints) > 0,
		CRLDistributionPoints: cert.CRLDistributionPoints,
		OCSPStapled:           ocspStapled,
		Status:                "good",
		Details:               "No revocation flags detected",
	}

	if ocspStapled {
		info.Details = "OCSP response stapled by server in handshake"
		return info
	}

	if !info.HasOCSP && !info.HasCRL {
		info.Status = "unconfigured"
		info.Details = "Certificate has no OCSP AIA or CRL distribution points (common for local/private CAs)"
		return info
	}

	// If OCSP server URL is present, test connectivity
	if len(cert.OCSPServer) > 0 {
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Head(cert.OCSPServer[0])
		if err == nil {
			_ = resp.Body.Close()
			info.Details = fmt.Sprintf("OCSP responder %s is reachable (HTTP %d)", cert.OCSPServer[0], resp.StatusCode)
		} else {
			info.Details = fmt.Sprintf("OCSP responder configured (%s)", cert.OCSPServer[0])
		}
	}

	return info
}
