package handshake

import (
	"time"
)

// TimingStage represents a distinct phase of the network & TLS handshake.
type TimingStage struct {
	Name          string  `json:"name"`
	Category      string  `json:"category"` // "dns", "tcp", "tls_hello", "tls_cert", "tls_finish"
	StartOffsetMs float64 `json:"startOffsetMs"`
	DurationMs    float64 `json:"durationMs"`
	Description   string  `json:"description"`
}

// CertSummary captures certificate details for the visual chain.
type CertSummary struct {
	CommonName         string    `json:"commonName"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DaysRemaining      int       `json:"daysRemaining"`
	IsExpired          bool      `json:"isExpired"`
	ExpiresSoon        bool      `json:"expiresSoon"`
	DNSNames           []string  `json:"dnsNames"`
	IPAddresses        []string  `json:"ipAddresses"`
	KeyType            string    `json:"keyType"`
	KeyLength          int       `json:"keyLength"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	FingerprintSHA256  string    `json:"fingerprintSHA256"`
	IsCA               bool      `json:"isCA"`
	KeyUsage           []string  `json:"keyUsage"`
	ExtKeyUsage        []string  `json:"extKeyUsage"`
	OCSPServers        []string  `json:"ocspServers"`
	CRLDistribution    []string  `json:"crlDistribution"`
}

// ProbeResult aggregates all timing, protocol, and certificate metrics.
type ProbeResult struct {
	Target             string        `json:"target"`
	Host               string        `json:"host"`
	Port               string        `json:"port"`
	ResolvedIP         string        `json:"resolvedIp"`
	TLSVersion         string        `json:"tlsVersion"`
	TLSVersionID       uint16        `json:"tlsVersionId"`
	Cipher             CipherInfo    `json:"cipher"`
	ALPN               string        `json:"alpn"`
	ServerName         string        `json:"serverName"`
	DidResume          bool          `json:"didResume"`
	OCSPStapled        bool          `json:"ocspStapled"`
	Timings            []TimingStage `json:"timings"`
	TotalDurationMs    float64       `json:"totalDurationMs"`
	PeerCertificates   []CertSummary `json:"peerCertificates"`
	VerifiedChainCount int           `json:"verifiedChainCount"`
	Error              string        `json:"error,omitempty"`
}
