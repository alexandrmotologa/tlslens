package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// ServerConfig configures the test mTLS server.
type ServerConfig struct {
	Port          int    `json:"port"`
	ClientAuth    string `json:"clientAuth"` // "require_and_verify", "verify_if_given", "require_any", "request", "none"
	ServerCertPEM []byte `json:"serverCertPem"`
	ServerKeyPEM  []byte `json:"serverKeyPem"`
	ClientCAPEM   []byte `json:"clientCaPem"`
}

// ConnectionEvent logs each handshake attempt.
type ConnectionEvent struct {
	ID                    string    `json:"id"`
	Timestamp             time.Time `json:"timestamp"`
	RemoteAddr            string    `json:"remoteAddr"`
	ClientCertPresented   bool      `json:"clientCertPresented"`
	ClientCommonName      string    `json:"clientCommonName"`
	ClientIssuer          string    `json:"clientIssuer"`
	ClientSerialNumber    string    `json:"clientSerialNumber"`
	TLSVersion            string    `json:"tlsVersion"`
	CipherSuite           string    `json:"cipherSuite"`
	Success               bool      `json:"success"`
	Error                 string    `json:"error,omitempty"`
	Diagnosis             string    `json:"diagnosis,omitempty"`
}

// MockServer represents the embedded test server.
type MockServer struct {
	mu         sync.RWMutex
	cfg        ServerConfig
	listener   net.Listener
	httpServer *http.Server
	running    bool
	actualPort int
	events     []ConnectionEvent
	eventSub   []chan ConnectionEvent
}

// NewMockServer creates an unstarted test server instance.
func NewMockServer(cfg ServerConfig) *MockServer {
	if cfg.Port <= 0 {
		cfg.Port = 9443
	}
	if cfg.ClientAuth == "" {
		cfg.ClientAuth = "require_and_verify"
	}
	return &MockServer{
		cfg:    cfg,
		events: make([]ConnectionEvent, 0),
	}
}

// Start boots the HTTPS mTLS server.
func (s *MockServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("server is already running")
	}

	serverCert, err := tls.X509KeyPair(s.cfg.ServerCertPEM, s.cfg.ServerKeyPEM)
	if err != nil {
		return fmt.Errorf("invalid server certificate/key pair: %w", err)
	}

	clientAuthType := parseClientAuth(s.cfg.ClientAuth)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   clientAuthType,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if len(s.cfg.ClientCAPEM) > 0 {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(s.cfg.ClientCAPEM); ok {
			tlsConfig.ClientCAs = pool
		}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// Fallback to random free port if preferred port is occupied
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind listener: %w", err)
		}
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)
	s.actualPort = tcpAddr.Port

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		event := ConnectionEvent{
			ID:         fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			Timestamp:  time.Now().UTC(),
			RemoteAddr: r.RemoteAddr,
			Success:    true,
		}

		if r.TLS != nil {
			event.TLSVersion = handshake.GetTLSVersionName(r.TLS.Version)
			event.CipherSuite = handshake.GetCipherInfo(r.TLS.CipherSuite).Name

			if len(r.TLS.PeerCertificates) > 0 {
				clientCert := r.TLS.PeerCertificates[0]
				event.ClientCertPresented = true
				event.ClientCommonName = clientCert.Subject.CommonName
				event.ClientIssuer = clientCert.Issuer.CommonName
				event.ClientSerialNumber = clientCert.SerialNumber.Text(16)
			}
		}

		s.recordEvent(event)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"connected","message":"mTLS connection accepted"}`))
	})

	tlsListener := tls.NewListener(listener, tlsConfig)
	s.listener = tlsListener
	s.httpServer = &http.Server{
		Handler: mux,
	}

	s.running = true

	go func() {
		_ = s.httpServer.Serve(tlsListener)
	}()

	return nil
}

// Stop shuts down the server.
func (s *MockServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.running = false
	return nil
}

// IsRunning reports whether server is actively listening.
func (s *MockServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Port returns actual listening port.
func (s *MockServer) Port() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.actualPort
}

// GetEvents returns recent connection log.
func (s *MockServer) GetEvents() []ConnectionEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]ConnectionEvent, len(s.events))
	copy(res, s.events)
	return res
}

func (s *MockServer) recordEvent(evt ConnectionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, evt)
	if len(s.events) > 100 {
		s.events = s.events[len(s.events)-100:]
	}

	for _, ch := range s.eventSub {
		select {
		case ch <- evt:
		default:
		}
	}
}

// Subscribe returns a channel receiving connection events.
func (s *MockServer) Subscribe() chan ConnectionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan ConnectionEvent, 10)
	s.eventSub = append(s.eventSub, ch)
	return ch
}

func parseClientAuth(auth string) tls.ClientAuthType {
	switch auth {
	case "verify_if_given":
		return tls.VerifyClientCertIfGiven
	case "require_any":
		return tls.RequireAnyClientCert
	case "request":
		return tls.RequestClientCert
	case "none":
		return tls.NoClientCert
	case "require_and_verify":
		fallthrough
	default:
		return tls.RequireAndVerifyClientCert
	}
}

// ParseCertificateFromPEMBytes parses first certificate from raw PEM bytes.
func ParseCertificateFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
