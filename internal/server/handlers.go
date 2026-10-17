package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/alexandrmotologa/tlslens/internal/audit"
	"github.com/alexandrmotologa/tlslens/internal/ca"
	"github.com/alexandrmotologa/tlslens/internal/configs"
	"github.com/alexandrmotologa/tlslens/internal/diff"
	"github.com/alexandrmotologa/tlslens/internal/handshake"
	"github.com/alexandrmotologa/tlslens/internal/inspector"
	"github.com/alexandrmotologa/tlslens/internal/k8s"
	"github.com/alexandrmotologa/tlslens/internal/linter"
	"github.com/alexandrmotologa/tlslens/internal/matrix"
	"github.com/alexandrmotologa/tlslens/internal/mtls"
	"strings"
)

type jsonMap map[string]any

func (s *Server) handleCAStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if caInst == nil {
		s.jsonResponse(w, http.StatusOK, jsonMap{
			"initialized": false,
			"storageDir":  s.caStorageDir,
		})
		return
	}

	info := caInst.Inspect()
	s.jsonResponse(w, http.StatusOK, jsonMap{
		"initialized": true,
		"ca":          info,
	})
}

type caInitRequest struct {
	CommonName   string `json:"commonName"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	ValidityDays int    `json:"validityDays"`
	KeyType      string `json:"keyType"`
}

func (s *Server) handleCAInit(w http.ResponseWriter, r *http.Request) {
	var req caInitRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()

	newCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   req.CommonName,
		Organization: req.Organization,
		Country:      req.Country,
		ValidityDays: req.ValidityDays,
		KeyType:      req.KeyType,
		StorageDir:   s.caStorageDir,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.caInstance = newCA
	info := newCA.Inspect()
	s.wsHub.Broadcast("ca_update", info)

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success": true,
		"ca":      info,
	})
}

func (s *Server) handleCATrust(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if caInst == nil || caInst.CertPath == "" {
		s.jsonError(w, http.StatusBadRequest, "CA is not initialized")
		return
	}

	if err := ca.InstallRootCA(caInst.CertPath); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to install CA into OS trust store: %v", err))
		return
	}

	info := caInst.Inspect()
	s.wsHub.Broadcast("ca_update", info)

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success":   true,
		"isTrusted": true,
		"message":   "Root CA installed into OS trust store successfully",
	})
}

func (s *Server) handleCAUntrust(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if caInst == nil {
		s.jsonError(w, http.StatusBadRequest, "CA is not initialized")
		return
	}

	identifier := caInst.Certificate.Subject.CommonName
	if err := ca.UninstallRootCA(identifier); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove CA from OS trust store: %v", err))
		return
	}

	info := caInst.Inspect()
	s.wsHub.Broadcast("ca_update", info)

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success":   true,
		"isTrusted": false,
		"message":   "Root CA removed from OS trust store",
	})
}

func (s *Server) handleCAIssue(w http.ResponseWriter, r *http.Request) {
	var req ca.IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if caInst == nil {
		s.jsonError(w, http.StatusBadRequest, "CA is not initialized; please initialize Root CA first")
		return
	}

	issued, err := caInst.Issue(req)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var p12Base64 string
	if len(issued.P12Bytes) > 0 {
		p12Base64 = base64.StdEncoding.EncodeToString(issued.P12Bytes)
	}

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success":           true,
		"commonName":        issued.CommonName,
		"dnsNames":          issued.DNSNames,
		"ipAddresses":       issued.IPAddresses,
		"serialNumber":      issued.SerialNumber,
		"notBefore":         issued.NotBefore,
		"notAfter":          issued.NotAfter,
		"fingerprintSHA256": issued.FingerprintSHA256,
		"certPEM":           string(issued.CertPEM),
		"keyPEM":            string(issued.KeyPEM),
		"bundlePEM":         string(issued.BundlePEM),
		"p12Base64":         p12Base64,
	})
}

func (s *Server) handleCADownload(w http.ResponseWriter, r *http.Request) {
	downloadType := r.URL.Query().Get("type")
	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if caInst == nil {
		http.Error(w, "CA is not initialized", http.StatusBadRequest)
		return
	}

	switch downloadType {
	case "cert":
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=\"root-ca.crt\"")
		_, _ = w.Write(caInst.CertPEM)
	case "key":
		w.Header().Set("Content-Type", "application/pkcs8")
		w.Header().Set("Content-Disposition", "attachment; filename=\"root-ca.key\"")
		_, _ = w.Write(caInst.KeyPEM)
	default:
		http.Error(w, "invalid download type: expected 'cert' or 'key'", http.StatusBadRequest)
	}
}

type probeRequest struct {
	Target             string   `json:"target"`
	ServerName         string   `json:"serverName"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
	ALPN               []string `json:"alpn"`
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid probe request")
		return
	}

	if req.Target == "" {
		s.jsonError(w, http.StatusBadRequest, "Target is required (e.g. google.com:443)")
		return
	}

	opts := handshake.ProbeOptions{
		ServerName:         req.ServerName,
		InsecureSkipVerify: req.InsecureSkipVerify,
		ALPNProtocols:      req.ALPN,
	}

	// Add local CA to probe roots if initialized
	s.mu.RLock()
	if s.caInstance != nil {
		pool := x509.NewCertPool()
		pool.AddCert(s.caInstance.Certificate)
		opts.RootCAs = pool
	}
	s.mu.RUnlock()

	result, err := handshake.ProbeEndpoint(r.Context(), req.Target, opts)
	if err != nil && result == nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast("probe_event", result)
	s.jsonResponse(w, http.StatusOK, result)
}

type inspectChainRequest struct {
	PEMData string `json:"pemData"`
	Target  string `json:"target"`
}

func (s *Server) handleInspectChain(w http.ResponseWriter, r *http.Request) {
	var req inspectChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var rootPool *x509.CertPool
	s.mu.RLock()
	if s.caInstance != nil {
		rootPool = x509.NewCertPool()
		rootPool.AddCert(s.caInstance.Certificate)
	}
	s.mu.RUnlock()

	if req.PEMData != "" {
		certs, err := inspector.ParseCertificatesFromPEM([]byte(req.PEMData))
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, fmt.Sprintf("Failed to parse certificates: %v", err))
			return
		}
		hierarchy := inspector.BuildHierarchy(certs, rootPool)
		s.jsonResponse(w, http.StatusOK, hierarchy)
		return
	}

	if req.Target != "" {
		probeRes, err := handshake.ProbeEndpoint(r.Context(), req.Target, handshake.ProbeOptions{
			InsecureSkipVerify: true,
		})
		if err != nil && probeRes == nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.jsonResponse(w, http.StatusOK, jsonMap{
			"target":           req.Target,
			"peerCertificates": probeRes.PeerCertificates,
			"tlsVersion":       probeRes.TLSVersion,
			"cipher":           probeRes.Cipher,
		})
		return
	}

	s.jsonError(w, http.StatusBadRequest, "Either pemData or target is required")
}

func (s *Server) handleMTLSStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	server := s.mockServer
	s.mu.RUnlock()

	if server == nil {
		s.jsonResponse(w, http.StatusOK, jsonMap{
			"running": false,
			"events":  []any{},
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"running": server.IsRunning(),
		"port":    server.Port(),
		"events":  server.GetEvents(),
	})
}

type mtlsStartRequest struct {
	Port          int    `json:"port"`
	ClientAuth    string `json:"clientAuth"`
	ServerCertPEM string `json:"serverCertPem"`
	ServerKeyPEM  string `json:"serverKeyPem"`
	ClientCAPEM   string `json:"clientCaPem"`
}

func (s *Server) handleMTLSServerStart(w http.ResponseWriter, r *http.Request) {
	var req mtlsStartRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mockServer != nil && s.mockServer.IsRunning() {
		_ = s.mockServer.Stop()
	}

	var serverCertBytes = []byte(req.ServerCertPEM)
	var serverKeyBytes = []byte(req.ServerKeyPEM)
	var clientCABytes = []byte(req.ClientCAPEM)

	// If no server cert supplied, auto-issue from CA
	if len(serverCertBytes) == 0 && s.caInstance != nil {
		issued, err := s.caInstance.Issue(ca.IssueRequest{
			CommonName:   "127.0.0.1",
			IPs:          []string{"127.0.0.1"},
			Domains:      []string{"localhost"},
			ValidityDays: 30,
		})
		if err == nil {
			serverCertBytes = issued.CertPEM
			serverKeyBytes = issued.KeyPEM
			clientCABytes = s.caInstance.CertPEM
		}
	}

	if len(serverCertBytes) == 0 {
		s.jsonError(w, http.StatusBadRequest, "No server certificates provided and local CA is not initialized")
		return
	}

	newMock := mtls.NewMockServer(mtls.ServerConfig{
		Port:          req.Port,
		ClientAuth:    req.ClientAuth,
		ServerCertPEM: serverCertBytes,
		ServerKeyPEM:  serverKeyBytes,
		ClientCAPEM:   clientCABytes,
	})

	if err := newMock.Start(); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to start mTLS server: %v", err))
		return
	}

	s.mockServer = newMock

	// Forward mock server events to WebSocket clients
	eventCh := newMock.Subscribe()
	go func() {
		for evt := range eventCh {
			s.wsHub.Broadcast("mtls_event", evt)
		}
	}()

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success": true,
		"running": true,
		"port":    newMock.Port(),
		"message": fmt.Sprintf("mTLS server listening on 127.0.0.1:%d", newMock.Port()),
	})
}

func (s *Server) handleMTLSServerStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mockServer != nil {
		_ = s.mockServer.Stop()
	}

	s.jsonResponse(w, http.StatusOK, jsonMap{
		"success": true,
		"running": false,
		"message": "mTLS server stopped",
	})
}

type clientTestBody struct {
	TargetURL          string `json:"targetUrl"`
	RootCAPEM          string `json:"rootCaPem"`
	ClientCertPEM      string `json:"clientCertPem"`
	ClientKeyPEM       string `json:"clientKeyPem"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	ServerName         string `json:"serverName"`
}

func (s *Server) handleMTLSTest(w http.ResponseWriter, r *http.Request) {
	var body clientTestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	var rootBytes []byte
	if body.RootCAPEM != "" {
		rootBytes = []byte(body.RootCAPEM)
	} else if caInst != nil {
		rootBytes = caInst.CertPEM
	}

	result, err := mtls.RunClientTest(r.Context(), mtls.ClientTestRequest{
		TargetURL:          body.TargetURL,
		RootCAPEM:          rootBytes,
		ClientCertPEM:      []byte(body.ClientCertPEM),
		ClientKeyPEM:       []byte(body.ClientKeyPEM),
		InsecureSkipVerify: body.InsecureSkipVerify,
		ServerName:         body.ServerName,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, result)
}

type auditRequest struct {
	Target string `json:"target"`
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	var req auditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Target == "" {
		s.jsonError(w, http.StatusBadRequest, "Target is required")
		return
	}

	res, err := audit.AuditEndpoint(r.Context(), req.Target)
	if err != nil && res == nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleConfigs(w http.ResponseWriter, r *http.Request) {
	var params configs.ConfigParameters
	_ = json.NewDecoder(r.Body).Decode(&params)

	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	if params.CAPath == "" && caInst != nil && caInst.CertPath != "" {
		params.CAPath = caInst.CertPath
	}
	if params.CertPath == "" && caInst != nil {
		params.CertPath = filepath.Join(s.caStorageDir, "cert.pem")
	}
	if params.KeyPath == "" && caInst != nil {
		params.KeyPath = filepath.Join(s.caStorageDir, "key.pem")
	}

	snippets := configs.GenerateSnippets(params)
	s.jsonResponse(w, http.StatusOK, jsonMap{
		"snippets": snippets,
	})
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	s.jsonResponse(w, status, jsonMap{
		"error":   msg,
		"success": false,
	})
}

// ---------------- Expanded Handlers ----------------

type diffRequest struct {
	TargetA string `json:"targetA"`
	TargetB string `json:"targetB"`
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	var req diffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.TargetA == "" || req.TargetB == "" {
		s.jsonError(w, http.StatusBadRequest, "Both targetA and targetB are required")
		return
	}

	s.mu.RLock()
	var rootPool *x509.CertPool
	if s.caInstance != nil {
		rootPool = x509.NewCertPool()
		rootPool.AddCert(s.caInstance.Certificate)
	}
	s.mu.RUnlock()

	res, err := diff.CompareTargets(r.Context(), req.TargetA, req.TargetB, rootPool)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, res)
}

type matrixRequest struct {
	Target string `json:"target"`
}

func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	var req matrixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Target == "" {
		s.jsonError(w, http.StatusBadRequest, "Target is required")
		return
	}

	s.mu.RLock()
	var rootPool *x509.CertPool
	if s.caInstance != nil {
		rootPool = x509.NewCertPool()
		rootPool.AddCert(s.caInstance.Certificate)
	}
	s.mu.RUnlock()

	res, err := matrix.ScanMatrix(r.Context(), req.Target, rootPool)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, res)
}

type lintRequest struct {
	Target  string `json:"target"`
	PEMData string `json:"pemData"`
}

func (s *Server) handleLinter(w http.ResponseWriter, r *http.Request) {
	var req lintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var certToLint *x509.Certificate

	if strings.TrimSpace(req.PEMData) != "" {
		certs, err := inspector.ParseCertificatesFromPEM([]byte(req.PEMData))
		if err != nil || len(certs) == 0 {
			s.jsonError(w, http.StatusBadRequest, "Failed to parse PEM certificate")
			return
		}
		certToLint = certs[0]
	} else if strings.TrimSpace(req.Target) != "" {
		opts := handshake.ProbeOptions{InsecureSkipVerify: true}
		res, err := handshake.ProbeEndpoint(r.Context(), req.Target, opts)
		if err != nil || res == nil || len(res.PeerCertificates) == 0 {
			s.jsonError(w, http.StatusInternalServerError, "Failed to probe target certificate")
			return
		}
		if res.PeerCertificates[0].Lint != nil {
			s.jsonResponse(w, http.StatusOK, res.PeerCertificates[0].Lint)
			return
		}
	} else {
		s.jsonError(w, http.StatusBadRequest, "Either target or pemData is required")
		return
	}

	if certToLint != nil {
		lintRes := linter.LintCertificate(certToLint)
		s.jsonResponse(w, http.StatusOK, lintRes)
		return
	}

	s.jsonError(w, http.StatusBadRequest, "No certificate found to lint")
}

type k8sGenRequest struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	CertPEM     string   `json:"certPem"`
	KeyPEM      string   `json:"keyPem"`
	CAPEM       string   `json:"caPem"`
	Domains     []string `json:"domains"`
	ServiceName string   `json:"serviceName"`
	ServicePort int      `json:"servicePort"`
}

func (s *Server) handleK8sGenerate(w http.ResponseWriter, r *http.Request) {
	var req k8sGenRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.RLock()
	caInst := s.caInstance
	s.mu.RUnlock()

	opts := k8s.ManifestOptions{
		Name:        req.Name,
		Namespace:   req.Namespace,
		CertPEM:     []byte(req.CertPEM),
		KeyPEM:      []byte(req.KeyPEM),
		CAPEM:       []byte(req.CAPEM),
		Domains:     req.Domains,
		ServiceName: req.ServiceName,
		ServicePort: req.ServicePort,
	}

	if len(opts.CAPEM) == 0 && caInst != nil {
		opts.CAPEM = caInst.CertPEM
	}
	if len(opts.CertPEM) == 0 && caInst != nil && len(opts.Domains) > 0 {
		leaf, err := caInst.Issue(ca.IssueRequest{
			CommonName:   opts.Domains[0],
			Domains:      opts.Domains,
			ValidityDays: 365,
			KeyType:      "ecdsa",
		})
		if err == nil && leaf != nil {
			opts.CertPEM = leaf.CertPEM
			opts.KeyPEM = leaf.KeyPEM
		}
	}

	bundle := k8s.GenerateManifests(opts)
	s.jsonResponse(w, http.StatusOK, bundle)
}

type alertSimulateRequest struct {
	AlertCode int `json:"alertCode"`
}

func (s *Server) handleMTLSSimulate(w http.ResponseWriter, r *http.Request) {
	var req alertSimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	res, err := mtls.TestAlertSimulation(r.Context(), req.AlertCode)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, res)
}

type addWatchRequest struct {
	Target          string `json:"target"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

func (s *Server) handleWatcher(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := s.domainWatcher.List()
		s.jsonResponse(w, http.StatusOK, items)
	case http.MethodPost:
		var req addWatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}
		item, err := s.domainWatcher.Add(r.Context(), req.Target, req.IntervalSeconds)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.jsonResponse(w, http.StatusCreated, item)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWatcherItem(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/watcher/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	id := parts[0]
	if len(parts) == 2 && parts[1] == "check" && r.Method == http.MethodPost {
		updated, err := s.domainWatcher.Check(r.Context(), id)
		if err != nil {
			s.jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, updated)
		return
	}

	if r.Method == http.MethodDelete {
		ok := s.domainWatcher.Remove(id)
		s.jsonResponse(w, http.StatusOK, jsonMap{"success": ok, "id": id})
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleACMEStatus(w http.ResponseWriter, r *http.Request) {
	status := s.acmeServer.GetStatus()
	s.jsonResponse(w, http.StatusOK, status)
}

