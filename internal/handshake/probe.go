package handshake

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProbeOptions configures the probe parameters.
type ProbeOptions struct {
	ServerName         string
	RootCAs            *x509.CertPool
	ClientCertificate  *tls.Certificate
	InsecureSkipVerify bool
	MinVersion         uint16
	MaxVersion         uint16
	CipherSuites       []uint16
	ALPNProtocols      []string
	Timeout            time.Duration
}

// timedConn instruments net.Conn to record ClientHello and ServerHello packet timings.
type timedConn struct {
	net.Conn
	mu               sync.Mutex
	firstWriteTime   time.Time
	firstReadTime    time.Time
	clientHelloSent  bool
	serverHelloRcvd  bool
}

func (tc *timedConn) Write(b []byte) (n int, err error) {
	tc.mu.Lock()
	if !tc.clientHelloSent {
		tc.firstWriteTime = time.Now()
		tc.clientHelloSent = true
	}
	tc.mu.Unlock()
	return tc.Conn.Write(b)
}

func (tc *timedConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	tc.mu.Lock()
	if !tc.serverHelloRcvd && n > 0 {
		tc.firstReadTime = time.Now()
		tc.serverHelloRcvd = true
	}
	tc.mu.Unlock()
	return n, err
}

// ProbeEndpoint executes a high-precision DNS, TCP, and TLS connection probe.
func ProbeEndpoint(ctx context.Context, target string, opts ProbeOptions) (*ProbeResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if len(opts.ALPNProtocols) == 0 {
		opts.ALPNProtocols = []string{"h2", "http/1.1"}
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %s: %w", target, err)
	}

	result := &ProbeResult{
		Target: target,
		Host:   host,
		Port:   port,
	}

	overallStart := time.Now()
	var timings []TimingStage

	// 1. DNS Resolution
	dnsStart := time.Now()
	var resolvedIP string
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	dnsDuration := time.Since(dnsStart)

	if err != nil {
		// If host is already an IP, treat as 0ms DNS
		if parsed := net.ParseIP(host); parsed != nil {
			resolvedIP = parsed.String()
			dnsDuration = 0
		} else {
			result.Error = fmt.Sprintf("DNS lookup failed: %v", err)
			return result, err
		}
	} else if len(ips) > 0 {
		resolvedIP = ips[0].String()
	}

	result.ResolvedIP = resolvedIP
	timings = append(timings, TimingStage{
		Name:          "DNS Resolution",
		Category:      "dns",
		StartOffsetMs: 0,
		DurationMs:    toMs(dnsDuration),
		Description:   fmt.Sprintf("Resolved %s to %s", host, resolvedIP),
	})

	// 2. TCP 3-Way Handshake
	tcpTarget := net.JoinHostPort(resolvedIP, port)
	tcpStart := time.Now()
	dialer := &net.Dialer{
		Timeout: opts.Timeout,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", tcpTarget)
	tcpDuration := time.Since(tcpStart)

	if err != nil {
		result.Error = fmt.Sprintf("TCP connect to %s failed: %v", tcpTarget, err)
		result.Timings = timings
		result.TotalDurationMs = toMs(time.Since(overallStart))
		return result, err
	}
	defer rawConn.Close()

	timings = append(timings, TimingStage{
		Name:          "TCP 3-Way Handshake",
		Category:      "tcp",
		StartOffsetMs: toMs(tcpStart.Sub(overallStart)),
		DurationMs:    toMs(tcpDuration),
		Description:   fmt.Sprintf("SYN/ACK round-trip with %s", tcpTarget),
	})

	// 3. TLS Handshake Instrumentation
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}
	result.ServerName = serverName

	var capturedRawCerts []*x509.Certificate
	var verifyErr error

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		RootCAs:            opts.RootCAs,
		InsecureSkipVerify: true, // we handle verification in callback to preserve certs on error
		NextProtos:         opts.ALPNProtocols,
		MinVersion:         opts.MinVersion,
		MaxVersion:         opts.MaxVersion,
		CipherSuites:       opts.CipherSuites,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err == nil {
					capturedRawCerts = append(capturedRawCerts, c)
				}
			}

			if !opts.InsecureSkipVerify && len(capturedRawCerts) > 0 {
				optsVerify := x509.VerifyOptions{
					DNSName:       serverName,
					Roots:         opts.RootCAs,
					Intermediates: x509.NewCertPool(),
				}
				for i := 1; i < len(capturedRawCerts); i++ {
					optsVerify.Intermediates.AddCert(capturedRawCerts[i])
				}
				_, verifyErr = capturedRawCerts[0].Verify(optsVerify)
			}
			return nil
		},
	}

	if opts.ClientCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*opts.ClientCertificate}
	}

	tc := &timedConn{Conn: rawConn}
	tlsConn := tls.Client(tc, tlsConfig)

	tlsHandshakeStart := time.Now()
	handshakeErr := tlsConn.HandshakeContext(ctx)
	tlsHandshakeDuration := time.Since(tlsHandshakeStart)

	// Timeline breakdown of TLS stages
	var clientHelloToFirstByte time.Duration
	if !tc.firstReadTime.IsZero() && !tc.firstWriteTime.IsZero() {
		clientHelloToFirstByte = tc.firstReadTime.Sub(tc.firstWriteTime)
	} else {
		clientHelloToFirstByte = tlsHandshakeDuration / 2
	}

	timings = append(timings, TimingStage{
		Name:          "TLS ClientHello -> ServerHello",
		Category:      "tls_hello",
		StartOffsetMs: toMs(tlsHandshakeStart.Sub(overallStart)),
		DurationMs:    toMs(clientHelloToFirstByte),
		Description:   "ClientHello dispatch and initial ServerHello receipt",
	})

	certTransferValidationTime := tlsHandshakeDuration - clientHelloToFirstByte
	if certTransferValidationTime < 0 {
		certTransferValidationTime = 0
	}

	timings = append(timings, TimingStage{
		Name:          "Certificate Transfer & Key Exchange",
		Category:      "tls_cert",
		StartOffsetMs: toMs(tlsHandshakeStart.Sub(overallStart)) + toMs(clientHelloToFirstByte),
		DurationMs:    toMs(certTransferValidationTime),
		Description:   "Certificate chain transmission, verification, and key agreement",
	})

	cs := tlsConn.ConnectionState()
	result.TLSVersion = GetTLSVersionName(cs.Version)
	result.TLSVersionID = cs.Version
	result.Cipher = GetCipherInfo(cs.CipherSuite)
	result.ALPN = cs.NegotiatedProtocol
	result.DidResume = cs.DidResume
	result.OCSPStapled = len(cs.OCSPResponse) > 0
	result.Timings = timings
	result.TotalDurationMs = toMs(time.Since(overallStart))

	// Extract certificate details
	var certSummaries []CertSummary
	for _, cert := range capturedRawCerts {
		certSummaries = append(certSummaries, parseSummaryDirect(cert))
	}
	result.PeerCertificates = certSummaries
	result.VerifiedChainCount = len(cs.VerifiedChains)

	if handshakeErr != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", handshakeErr)
	} else if verifyErr != nil && !opts.InsecureSkipVerify {
		result.Error = fmt.Sprintf("Certificate verification failed: %v", verifyErr)
	}

	return result, nil
}

func splitHostPort(target string) (string, string, error) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	if strings.Contains(target, "/") {
		parts := strings.SplitN(target, "/", 2)
		target = parts[0]
	}

	if !strings.Contains(target, ":") {
		return target, "443", nil
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", err
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return "", "", fmt.Errorf("invalid port %s", portStr)
	}
	return host, portStr, nil
}

func toMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func parseSummaryDirect(cert *x509.Certificate) CertSummary {
	now := time.Now().UTC()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	keyType, keyLen := getKeyInfo(cert.PublicKey)

	return CertSummary{
		CommonName:         cert.Subject.CommonName,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysRemaining:      daysRemaining,
		IsExpired:          isExpired,
		ExpiresSoon:        !isExpired && daysRemaining <= 30,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ips,
		KeyType:            keyType,
		KeyLength:          keyLen,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		OCSPServers:        cert.OCSPServer,
		CRLDistribution:    cert.CRLDistributionPoints,
	}
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

