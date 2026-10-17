package server

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/acme"
	"github.com/alexandrmotologa/tlslens/internal/ca"
	"github.com/alexandrmotologa/tlslens/internal/mtls"
	"github.com/alexandrmotologa/tlslens/internal/watcher"
)

// ServerOptions configures the TLSLens API and web server.
type ServerOptions struct {
	Port         int
	StorageDir   string
	StaticFS     fs.FS
	StaticDir    string
	AllowOrigins []string
}

// Server holds the HTTP server state and subsystems.
type Server struct {
	mu            sync.RWMutex
	opts          ServerOptions
	caInstance    *ca.CA
	mockServer    *mtls.MockServer
	wsHub         *Hub
	caStorageDir  string
	domainWatcher *watcher.DomainWatcher
	acmeServer    *acme.Server
	listener      net.Listener
	httpServer    *http.Server
	actualPort    int
}

// NewServer initializes the server with loaded or default CA.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Port <= 0 {
		opts.Port = 8080
	}
	if opts.StorageDir == "" {
		defDir, err := ca.GetDefaultStorageDir()
		if err != nil {
			opts.StorageDir = filepath.Join(".", "certs", "ca")
		} else {
			opts.StorageDir = defDir
		}
	}

	var caInst *ca.CA
	if ca.IsCAInitialized(opts.StorageDir) {
		loaded, err := ca.LoadCA(opts.StorageDir)
		if err == nil {
			caInst = loaded
		}
	}

	hub := NewHub()
	go hub.Run()

	var rootPool *x509.CertPool
	if caInst != nil {
		rootPool = x509.NewCertPool()
		rootPool.AddCert(caInst.Certificate)
	}

	dmWatcher := watcher.NewDomainWatcher(rootPool, func(domain watcher.MonitoredDomain, changeType string) {
		hub.Broadcast("watcher_alert", map[string]any{
			"domain":     domain,
			"changeType": changeType,
		})
	})

	acmeSrv := acme.NewServer(fmt.Sprintf("http://localhost:%d/acme", opts.Port), caInst)

	s := &Server{
		opts:          opts,
		caInstance:    caInst,
		wsHub:         hub,
		caStorageDir:  opts.StorageDir,
		domainWatcher: dmWatcher,
		acmeServer:    acmeSrv,
	}

	return s, nil
}

// Start launches the HTTP server.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.opts.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind server port %d: %w", s.opts.Port, err)
	}

	s.listener = listener
	s.actualPort = listener.Addr().(*net.TCPAddr).Port

	s.acmeServer.SetBaseURL(fmt.Sprintf("http://localhost:%d/acme", s.actualPort))

	mux := http.NewServeMux()

	// Core API Endpoints
	mux.HandleFunc("/api/ca/status", s.handleCAStatus)
	mux.HandleFunc("/api/ca/init", s.handleCAInit)
	mux.HandleFunc("/api/ca/trust", s.handleCATrust)
	mux.HandleFunc("/api/ca/untrust", s.handleCAUntrust)
	mux.HandleFunc("/api/ca/issue", s.handleCAIssue)
	mux.HandleFunc("/api/ca/download", s.handleCADownload)
	mux.HandleFunc("/api/probe", s.handleProbe)
	mux.HandleFunc("/api/inspect/chain", s.handleInspectChain)
	mux.HandleFunc("/api/mtls/status", s.handleMTLSStatus)
	mux.HandleFunc("/api/mtls/server/start", s.handleMTLSServerStart)
	mux.HandleFunc("/api/mtls/server/stop", s.handleMTLSServerStop)
	mux.HandleFunc("/api/mtls/test", s.handleMTLSTest)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/configs", s.handleConfigs)

	// New Expanded API Endpoints
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.HandleFunc("/api/matrix", s.handleMatrix)
	mux.HandleFunc("/api/linter", s.handleLinter)
	mux.HandleFunc("/api/k8s/generate", s.handleK8sGenerate)
	mux.HandleFunc("/api/mtls/simulate", s.handleMTLSSimulate)
	mux.HandleFunc("/api/watcher", s.handleWatcher)
	mux.HandleFunc("/api/watcher/", s.handleWatcherItem)
	mux.HandleFunc("/api/acme/status", s.handleACMEStatus)

	// Register RFC 8555 ACME Directory Routes
	s.acmeServer.RegisterRoutes(mux)

	// Start Domain Watcher background loop
	s.domainWatcher.Start(context.Background())

	// WebSocket stream
	mux.HandleFunc("/ws/events", s.wsHub.HandleWebSocket)

	// Static SPA Files
	s.registerStaticHandlers(mux)

	// Wrap in CORS & logging middleware
	handler := s.corsMiddleware(mux)

	s.httpServer = &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		_ = s.httpServer.Serve(listener)
	}()

	return nil
}

// Stop shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.mockServer != nil {
		_ = s.mockServer.Stop()
	}
	if s.domainWatcher != nil {
		s.domainWatcher.Stop()
	}
	s.mu.Unlock()

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Port returns actual listening port.
func (s *Server) Port() int {
	return s.actualPort
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerStaticHandlers(mux *http.ServeMux) {
	if s.opts.StaticFS != nil {
		fileServer := http.FileServer(http.FS(s.opts.StaticFS))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
				http.NotFound(w, r)
				return
			}
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			f, err := s.opts.StaticFS.Open(path)
			if err != nil {
				// Fallback to index.html for SPA routing
				r.URL.Path = "/"
			} else {
				_ = f.Close()
			}
			fileServer.ServeHTTP(w, r)
		})
		return
	}

	if s.opts.StaticDir != "" {
		if _, err := os.Stat(s.opts.StaticDir); err == nil {
			fileServer := http.FileServer(http.Dir(s.opts.StaticDir))
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
					http.NotFound(w, r)
					return
				}
				fullPath := filepath.Join(s.opts.StaticDir, filepath.Clean(r.URL.Path))
				if _, err := os.Stat(fullPath); os.IsNotExist(err) {
					// Fallback to index.html
					r.URL.Path = "/"
				}
				fileServer.ServeHTTP(w, r)
			})
			return
		}
	}

	// Minimal fallback if no static files provided
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>TLSLens API</title></head><body style="background:#090d16;color:#e2e8f0;font-family:monospace;padding:2rem;"><h1>TLSLens Backend Active</h1><p>API endpoints running on /api/ca/status, /api/probe, /api/mtls/status, /api/audit, etc.</p></body></html>`))
	})
}
