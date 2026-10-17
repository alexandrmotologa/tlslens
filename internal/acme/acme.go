package acme

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/ca"
)

// Identifier represents an ACME domain identifier.
type Identifier struct {
	Type  string `json:"type"` // "dns" or "ip"
	Value string `json:"value"`
}

// Challenge represents an HTTP-01 or TLS-ALPN-01 challenge.
type Challenge struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	Status    string `json:"status"` // "pending", "processing", "valid", "invalid"
	Validated string `json:"validated,omitempty"`
}

// Authorization represents a per-domain ACME authorization.
type Authorization struct {
	ID         string       `json:"id"`
	Identifier Identifier   `json:"identifier"`
	Status     string       `json:"status"` // "pending", "valid", "invalid"
	Expires    string       `json:"expires"`
	Challenges []Challenge  `json:"challenges"`
	Wildcard   bool         `json:"wildcard,omitempty"`
}

// Order represents an RFC 8555 order object.
type Order struct {
	ID             string       `json:"id"`
	Status         string       `json:"status"` // "pending", "ready", "processing", "valid", "invalid"
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	FinalizeURL    string       `json:"finalize"`
	CertificateURL string       `json:"certificate,omitempty"`
	CreatedAt      time.Time    `json:"createdAt"`
	Domains        []string     `json:"domains"`
}

// Account represents a registered ACME client account.
type Account struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // "valid", "deactivated", "revoked"
	Contact   []string  `json:"contact,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Server implements a lightweight, local RFC 8555 ACME Directory.
type Server struct {
	mu           sync.RWMutex
	baseURL      string
	caInstance   *ca.CA
	accounts     map[string]*Account
	orders       map[string]*Order
	authzs       map[string]*Authorization
	certificates map[string][]byte
}

// NewServer initializes the ACME server.
func NewServer(baseURL string, caInstance *ca.CA) *Server {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &Server{
		baseURL:      baseURL,
		caInstance:   caInstance,
		accounts:     make(map[string]*Account),
		orders:       make(map[string]*Order),
		authzs:       make(map[string]*Authorization),
		certificates: make(map[string][]byte),
	}
}

// SetCA updates the CA instance used for signing.
func (s *Server) SetCA(caInstance *ca.CA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caInstance = caInstance
}

// SetBaseURL updates base URL.
func (s *Server) SetBaseURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseURL = strings.TrimSuffix(url, "/")
}

// StatusReport provides metrics for the TLSLens Web UI.
type StatusReport struct {
	DirectoryURL      string   `json:"directoryUrl"`
	TotalAccounts     int      `json:"totalAccounts"`
	TotalOrders       int      `json:"totalOrders"`
	TotalCertificates int      `json:"totalCertificates"`
	RecentOrders      []Order  `json:"recentOrders"`
}

// GetStatus returns real-time metrics for ACME Studio.
func (s *Server) GetStatus() StatusReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	orders := make([]Order, 0, len(s.orders))
	for _, o := range s.orders {
		orders = append(orders, *o)
	}

	return StatusReport{
		DirectoryURL:      s.baseURL + "/directory",
		TotalAccounts:     len(s.accounts),
		TotalOrders:       len(s.orders),
		TotalCertificates: len(s.certificates),
		RecentOrders:      orders,
	}
}

// RegisterRoutes hooks RFC 8555 paths onto a ServeMux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/acme/directory", s.handleDirectory)
	mux.HandleFunc("/acme/new-nonce", s.handleNewNonce)
	mux.HandleFunc("/acme/new-account", s.handleNewAccount)
	mux.HandleFunc("/acme/new-order", s.handleNewOrder)
	mux.HandleFunc("/acme/acct/", s.handleAccount)
	mux.HandleFunc("/acme/order/", s.handleOrderRouter)
	mux.HandleFunc("/acme/authz/", s.handleAuthz)
	mux.HandleFunc("/acme/chall/", s.handleChallenge)
	mux.HandleFunc("/acme/cert/", s.handleCertificate)
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	base := s.baseURL
	s.mu.RUnlock()

	dir := map[string]any{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		"newOrder":   base + "/new-order",
		"revokeCert": base + "/revoke-cert",
		"keyChange":  base + "/key-change",
		"meta": map[string]any{
			"website": "https://github.com/alexandrmotologa/tlslens",
			"author":  "Alexandr Motologa",
		},
	}

	s.jsonResponse(w, http.StatusOK, dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce := randomString(24)
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

type newAccountPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))

	s.mu.Lock()
	defer s.mu.Unlock()

	acctID := fmt.Sprintf("acct_%d", time.Now().UnixNano())
	acct := &Account{
		ID:        acctID,
		Status:    "valid",
		CreatedAt: time.Now().UTC(),
	}
	s.accounts[acctID] = acct

	loc := fmt.Sprintf("%s/acct/%s", s.baseURL, acctID)
	w.Header().Set("Location", loc)
	s.jsonResponse(w, http.StatusCreated, map[string]any{
		"status":  "valid",
		"contact": []string{"mailto:dev@localhost"},
		"orders":  fmt.Sprintf("%s/acct/%s/orders", s.baseURL, acctID),
	})
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"status": "valid",
	})
}

type newOrderPayload struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))

	var req newOrderPayload
	// Support both plain JSON and JWS envelope payload
	bodyBytes := extractPayloadBytes(r)
	_ = json.Unmarshal(bodyBytes, &req)

	if len(req.Identifiers) == 0 {
		req.Identifiers = []Identifier{{Type: "dns", Value: "localhost"}}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	orderID := fmt.Sprintf("ord_%d", time.Now().UnixNano())
	var authzURLs []string
	var domains []string

	for _, id := range req.Identifiers {
		authzID := fmt.Sprintf("authz_%s_%d", sanitizeID(id.Value), time.Now().UnixNano())
		authzURL := fmt.Sprintf("%s/authz/%s", s.baseURL, authzID)
		challID := fmt.Sprintf("chall_%d", time.Now().UnixNano())
		challURL := fmt.Sprintf("%s/chall/%s", s.baseURL, challID)

		authz := &Authorization{
			ID:         authzID,
			Identifier: id,
			Status:     "valid", // In local dev mode, auto-validate domains!
			Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Challenges: []Challenge{
				{
					Type:      "http-01",
					URL:       challURL,
					Token:     randomString(32),
					Status:    "valid",
					Validated: time.Now().UTC().Format(time.RFC3339),
				},
				{
					Type:      "tls-alpn-01",
					URL:       challURL,
					Token:     randomString(32),
					Status:    "valid",
					Validated: time.Now().UTC().Format(time.RFC3339),
				},
			},
		}

		s.authzs[authzID] = authz
		authzURLs = append(authzURLs, authzURL)
		domains = append(domains, id.Value)
	}

	order := &Order{
		ID:             orderID,
		Status:         "ready", // Ready for CSR finalization
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers:    req.Identifiers,
		Authorizations: authzURLs,
		FinalizeURL:    fmt.Sprintf("%s/order/%s/finalize", s.baseURL, orderID),
		CertificateURL: fmt.Sprintf("%s/cert/%s", s.baseURL, orderID),
		CreatedAt:      time.Now().UTC(),
		Domains:        domains,
	}

	s.orders[orderID] = order

	loc := fmt.Sprintf("%s/order/%s", s.baseURL, orderID)
	w.Header().Set("Location", loc)
	s.jsonResponse(w, http.StatusCreated, order)
}

func (s *Server) handleOrderRouter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))

	path := strings.TrimPrefix(r.URL.Path, "/acme/order/")
	if strings.HasSuffix(path, "/finalize") {
		orderID := strings.TrimSuffix(path, "/finalize")
		s.handleFinalize(w, r, orderID)
		return
	}

	orderID := path
	s.mu.RLock()
	order, exists := s.orders[orderID]
	s.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	s.jsonResponse(w, http.StatusOK, order)
}

type finalizePayload struct {
	CSR string `json:"csr"` // Base64URL encoded DER
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, orderID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order, exists := s.orders[orderID]
	if !exists {
		http.NotFound(w, r)
		return
	}

	bodyBytes := extractPayloadBytes(r)
	var req finalizePayload
	_ = json.Unmarshal(bodyBytes, &req)

	if req.CSR == "" {
		s.jsonError(w, http.StatusBadRequest, "Missing CSR in finalize request")
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		csrDER, err = base64.StdEncoding.DecodeString(req.CSR)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "Invalid base64 encoding in CSR")
			return
		}
	}

	if s.caInstance == nil {
		s.jsonError(w, http.StatusInternalServerError, "Local Certificate Authority is not initialized")
		return
	}

	// Sign CSR with local CA
	issued, err := s.caInstance.IssueFromCSR(csrDER, 90)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign certificate: %v", err))
		return
	}

	s.certificates[orderID] = issued.BundlePEM
	order.Status = "valid"
	order.CertificateURL = fmt.Sprintf("%s/cert/%s", s.baseURL, orderID)

	loc := fmt.Sprintf("%s/order/%s", s.baseURL, orderID)
	w.Header().Set("Location", loc)
	s.jsonResponse(w, http.StatusOK, order)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))
	authzID := strings.TrimPrefix(r.URL.Path, "/acme/authz/")

	s.mu.RLock()
	authz, exists := s.authzs[authzID]
	s.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	s.jsonResponse(w, http.StatusOK, authz)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", randomString(24))
	challID := strings.TrimPrefix(r.URL.Path, "/acme/chall/")

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"type":   "http-01",
		"status": "valid",
		"url":    fmt.Sprintf("%s/chall/%s", s.baseURL, challID),
	})
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	certID := strings.TrimPrefix(r.URL.Path, "/acme/cert/")

	s.mu.RLock()
	bundle, exists := s.certificates[certID]
	s.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func (s *Server) jsonResponse(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:ietf:params:acme:error:serverInternal",
		"detail": msg,
		"status": statusCode,
	})
}

func extractPayloadBytes(r *http.Request) []byte {
	var bodyRaw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&bodyRaw); err != nil {
		return nil
	}

	// Check if this is JWS envelope { "payload": "base64url..." }
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(bodyRaw, &jws); err == nil && jws.Payload != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err == nil {
			return decoded
		}
	}

	return bodyRaw
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[num.Int64()]
	}
	return string(b)
}

func sanitizeID(val string) string {
	val = strings.ReplaceAll(val, "*", "wildcard")
	val = strings.ReplaceAll(val, ".", "_")
	val = strings.ReplaceAll(val, ":", "_")
	return val
}
