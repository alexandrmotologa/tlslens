package mtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// AlertSimulationConfig configures an interactive TLS alert simulator.
type AlertSimulationConfig struct {
	Port      int `json:"port"`
	AlertCode int `json:"alertCode"` // e.g. 40, 42, 45, 46, 48, 112, 116
}

// AlertSimulator runs an ephemeral TCP listener that responds to incoming ClientHello with a fatal TLS alert.
type AlertSimulator struct {
	mu         sync.Mutex
	alertCode  int
	listener   net.Listener
	actualPort int
	running    bool
	stopChan   chan struct{}
}

// NewAlertSimulator creates a simulator instance.
func NewAlertSimulator(alertCode int) *AlertSimulator {
	if alertCode <= 0 {
		alertCode = 48 // Default: unknown_ca
	}
	return &AlertSimulator{
		alertCode: alertCode,
		stopChan:  make(chan struct{}),
	}
}

// Start binds to an available local port and starts intercepting handshakes.
func (s *AlertSimulator) Start(preferredPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("alert simulator is already running")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", preferredPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind simulator listener: %w", err)
		}
	}

	s.listener = listener
	s.actualPort = listener.Addr().(*net.TCPAddr).Port
	s.running = true
	s.stopChan = make(chan struct{})

	go s.serve()
	return nil
}

// Port returns actual listening port.
func (s *AlertSimulator) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actualPort
}

// Stop terminates the simulator listener.
func (s *AlertSimulator) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	close(s.stopChan)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *AlertSimulator) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				return
			}
		}

		go s.handleConn(conn)
	}
}

func (s *AlertSimulator) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Read initial ClientHello record (header: 5 bytes + body)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return
	}

	// Build raw RFC 5246 / RFC 8446 TLS Alert Record:
	// Content Type: 0x15 (21 = alert)
	// Version: 0x03, 0x03 (TLS 1.2 / TLS 1.3 compat)
	// Length: 0x00, 0x02
	// Level: 0x02 (Fatal)
	// Description: AlertCode (byte)
	alertRecord := []byte{
		0x15,              // Content Type: Alert
		0x03, 0x03,        // Protocol Version: TLS 1.2 / 1.3
		0x00, 0x02,        // Length: 2 bytes
		0x02,              // Alert Level: 2 (Fatal)
		byte(s.alertCode), // Alert Description Code
	}

	_, _ = conn.Write(alertRecord)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	// Small pause so Windows Winsock sends the alert packet before RST on close
	time.Sleep(25 * time.Millisecond)
}

// SimulationProbeResult details the client side test against the simulated alert.
type SimulationProbeResult struct {
	AlertCode     int              `json:"alertCode"`
	AlertName     string           `json:"alertName"`
	ClientError   string           `json:"clientError"`
	DetectedAlert int              `json:"detectedAlert"`
	Diagnostics   DiagnosticReport `json:"diagnostics"`
	RawHex        string           `json:"rawHex"`
}

// TestAlertSimulation triggers a live client probe against an alert simulator to observe client error behavior.
func TestAlertSimulation(ctx context.Context, alertCode int) (*SimulationProbeResult, error) {
	sim := NewAlertSimulator(alertCode)
	if err := sim.Start(0); err != nil {
		return nil, fmt.Errorf("failed to start simulator: %w", err)
	}
	defer sim.Stop()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", sim.Port())

	// Client attempt
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to simulator: %w", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))

	handshakeErr := tlsConn.HandshakeContext(ctx)
	errStr := ""
	if handshakeErr != nil {
		errStr = handshakeErr.Error()
	}

	detected := extractAlertCode(errStr)
	diag := DiagnoseError(handshakeErr, nil, nil)

	alertDef, ok := KnownAlerts[alertCode]
	alertName := "unknown"
	if ok {
		alertName = alertDef.Name
	}

	rawHex := fmt.Sprintf("15 03 03 00 02 02 %02X", alertCode)

	return &SimulationProbeResult{
		AlertCode:     alertCode,
		AlertName:     alertName,
		ClientError:   errStr,
		DetectedAlert: detected,
		Diagnostics:   diag,
		RawHex:        rawHex,
	}, nil
}
