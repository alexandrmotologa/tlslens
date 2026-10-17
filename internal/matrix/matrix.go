package matrix

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// ClientProfile defines a simulated TLS client configuration.
type ClientProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"` // "Browser", "Mobile", "Enterprise", "CLI"
	Description string   `json:"description"`
	MinVersion  uint16   `json:"minVersion"`
	MaxVersion  uint16   `json:"maxVersion"`
	Ciphers     []uint16 `json:"ciphers"`
	ALPN        []string `json:"alpn"`
}

// ClientProbeResult stores the simulation outcome for a single profile.
type ClientProbeResult struct {
	Profile            ClientProfile `json:"profile"`
	Success            bool          `json:"success"`
	NegotiatedProtocol string        `json:"negotiatedProtocol"`
	NegotiatedCipher   string        `json:"negotiatedCipher"`
	IsPFS              bool          `json:"isPfs"`
	ALPN               string        `json:"alpn"`
	LatencyMs          float64       `json:"latencyMs"`
	Error              string        `json:"error,omitempty"`
}

// MatrixReport aggregates all profile probe outcomes for a target.
type MatrixReport struct {
	Target             string              `json:"target"`
	Host               string              `json:"host"`
	Port               string              `json:"port"`
	Timestamp          time.Time           `json:"timestamp"`
	TotalProfiles      int                 `json:"totalProfiles"`
	SuccessfulProfiles int                 `json:"successfulProfiles"`
	FailedProfiles     int                 `json:"failedProfiles"`
	Results            []ClientProbeResult `json:"results"`
}

// StandardProfiles returns the matrix of simulated real-world clients.
func StandardProfiles() []ClientProfile {
	return []ClientProfile{
		{
			ID:          "chrome-modern",
			Name:        "Chrome 130+ / Chromium",
			Category:    "Browser",
			Description: "Modern desktop Google Chrome with TLS 1.3 and ChaCha20 preference",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			ID:          "firefox-modern",
			Name:        "Firefox 130+",
			Category:    "Browser",
			Description: "Modern desktop Mozilla Firefox",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			ID:          "safari-ios17",
			Name:        "iOS 17+ / macOS Sonoma Safari",
			Category:    "Mobile",
			Description: "Apple WebKit engine with strict modern cipher requirements",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			ID:          "android-14",
			Name:        "Android 14 (Conscrypt)",
			Category:    "Mobile",
			Description: "Modern Android OS TLS client stack",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			ID:          "android-7",
			Name:        "Android 7.0 (Legacy)",
			Category:    "Mobile",
			Description: "Legacy Android device with TLS 1.2 maximum and older cipher suite priorities",
			MinVersion:  tls.VersionTLS10,
			MaxVersion:  tls.VersionTLS12,
			Ciphers: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
			ALPN: []string{"http/1.1"},
		},
		{
			ID:          "java-8",
			Name:        "Java 8u121 (Legacy Enterprise)",
			Category:    "Enterprise",
			Description: "Legacy Java JVM without TLS 1.3 support",
			MinVersion:  tls.VersionTLS10,
			MaxVersion:  tls.VersionTLS12,
			Ciphers: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			},
			ALPN: []string{"http/1.1"},
		},
		{
			ID:          "java-17",
			Name:        "Java 17 / 21 LTS",
			Category:    "Enterprise",
			Description: "Modern Java LTS runtime supporting TLS 1.3 and ALPN",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		{
			ID:          "openssl-102",
			Name:        "OpenSSL 1.0.2 (Legacy Linux)",
			Category:    "CLI",
			Description: "Legacy Linux server / curl stack (RHEL 7 / Ubuntu 14.04)",
			MinVersion:  tls.VersionTLS10,
			MaxVersion:  tls.VersionTLS12,
			Ciphers: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
			ALPN: []string{"http/1.1"},
		},
		{
			ID:          "openssl-30",
			Name:        "OpenSSL 3.0+ / Modern curl",
			Category:    "CLI",
			Description: "Standard modern Linux / Unix CLI and microservice client",
			MinVersion:  tls.VersionTLS12,
			MaxVersion:  tls.VersionTLS13,
			Ciphers: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			ALPN: []string{"h2", "http/1.1"},
		},
	}
}

// ScanMatrix probes a host with each simulated profile concurrently.
func ScanMatrix(ctx context.Context, target string, rootPool *x509.CertPool) (*MatrixReport, error) {
	profiles := StandardProfiles()

	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host := target
	port := "443"
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			host = h
			port = p
		}
	}
	connectAddr := net.JoinHostPort(host, port)

	report := &MatrixReport{
		Target:        target,
		Host:          host,
		Port:          port,
		Timestamp:     time.Now().UTC(),
		TotalProfiles: len(profiles),
		Results:       make([]ClientProbeResult, len(profiles)),
	}

	var wg sync.WaitGroup
	wg.Add(len(profiles))

	for i, prof := range profiles {
		go func(idx int, p ClientProfile) {
			defer wg.Done()
			report.Results[idx] = probeWithProfile(ctx, connectAddr, host, p, rootPool)
		}(i, prof)
	}

	wg.Wait()

	for _, res := range report.Results {
		if res.Success {
			report.SuccessfulProfiles++
		} else {
			report.FailedProfiles++
		}
	}

	return report, nil
}

func probeWithProfile(ctx context.Context, connectAddr, serverName string, prof ClientProfile, rootPool *x509.CertPool) ClientProbeResult {
	start := time.Now()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", connectAddr)
	if err != nil {
		return ClientProbeResult{
			Profile:   prof,
			Success:   false,
			LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
			Error:     fmt.Sprintf("TCP connect failed: %v", err),
		}
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		MinVersion:         prof.MinVersion,
		MaxVersion:         prof.MaxVersion,
		CipherSuites:       prof.Ciphers,
		NextProtos:         prof.ALPN,
		InsecureSkipVerify: true,
	}
	if rootPool != nil {
		tlsConfig.RootCAs = rootPool
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	err = tlsConn.HandshakeContext(ctx)
	latency := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		return ClientProbeResult{
			Profile:   prof,
			Success:   false,
			LatencyMs: latency,
			Error:     err.Error(),
		}
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	protoStr := "TLS 1.2"
	if state.Version == tls.VersionTLS13 {
		protoStr = "TLS 1.3"
	} else if state.Version == tls.VersionTLS11 {
		protoStr = "TLS 1.1"
	} else if state.Version == tls.VersionTLS10 {
		protoStr = "TLS 1.0"
	}

	cipherInfo, exists := handshake.CipherSuiteMap[state.CipherSuite]
	cipherName := fmt.Sprintf("0x%04X", state.CipherSuite)
	isPFS := false
	if exists {
		cipherName = cipherInfo.Name
		isPFS = cipherInfo.IsPFS
	}

	return ClientProbeResult{
		Profile:            prof,
		Success:            true,
		NegotiatedProtocol: protoStr,
		NegotiatedCipher:   cipherName,
		IsPFS:              isPFS,
		ALPN:               state.NegotiatedProtocol,
		LatencyMs:          latency,
	}
}
