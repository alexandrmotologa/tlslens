package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alexandrmotologa/tlslens/internal/ca"
)

func TestACMEFlow(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "acme_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "ACME Test Root CA",
		ValidityDays: 1,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	acmeServer := NewServer("http://localhost:8080/acme", testCA)
	mux := http.NewServeMux()
	acmeServer.RegisterRoutes(mux)

	// 1. Directory
	reqDir := httptest.NewRequest("GET", "/acme/directory", nil)
	recDir := httptest.NewRecorder()
	mux.ServeHTTP(recDir, reqDir)

	if recDir.Code != http.StatusOK {
		t.Fatalf("directory returned %d", recDir.Code)
	}
	if !strings.Contains(recDir.Body.String(), "newOrder") {
		t.Errorf("directory missing newOrder: %s", recDir.Body.String())
	}

	// 2. New Nonce
	reqNonce := httptest.NewRequest("GET", "/acme/new-nonce", nil)
	recNonce := httptest.NewRecorder()
	mux.ServeHTTP(recNonce, reqNonce)

	nonce := recNonce.Header().Get("Replay-Nonce")
	if nonce == "" {
		t.Errorf("missing Replay-Nonce header")
	}

	// 3. New Account
	reqAcct := httptest.NewRequest("POST", "/acme/new-account", bytes.NewBufferString(`{"termsOfServiceAgreed": true}`))
	recAcct := httptest.NewRecorder()
	mux.ServeHTTP(recAcct, reqAcct)

	if recAcct.Code != http.StatusCreated {
		t.Fatalf("new-account returned %d: %s", recAcct.Code, recAcct.Body.String())
	}

	// 4. New Order
	orderPayload := `{"identifiers": [{"type": "dns", "value": "api.local"}]}`
	reqOrder := httptest.NewRequest("POST", "/acme/new-order", bytes.NewBufferString(orderPayload))
	recOrder := httptest.NewRecorder()
	mux.ServeHTTP(recOrder, reqOrder)

	if recOrder.Code != http.StatusCreated {
		t.Fatalf("new-order returned %d: %s", recOrder.Code, recOrder.Body.String())
	}

	var createdOrder Order
	if err := json.Unmarshal(recOrder.Body.Bytes(), &createdOrder); err != nil {
		t.Fatalf("failed to parse order response: %v", err)
	}

	if createdOrder.Status != "ready" {
		t.Errorf("expected order status ready, got %s", createdOrder.Status)
	}

	// 5. Finalize with CSR
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "api.local"},
		DNSNames: []string{"api.local"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)
	finalizePayload := map[string]string{"csr": csrB64}
	finalizeBytes, _ := json.Marshal(finalizePayload)

	finalizePath := strings.TrimPrefix(createdOrder.FinalizeURL, "http://localhost:8080")
	reqFinalize := httptest.NewRequest("POST", finalizePath, bytes.NewBuffer(finalizeBytes))
	recFinalize := httptest.NewRecorder()
	mux.ServeHTTP(recFinalize, reqFinalize)

	if recFinalize.Code != http.StatusOK {
		t.Fatalf("finalize returned %d: %s", recFinalize.Code, recFinalize.Body.String())
	}

	var finalizedOrder Order
	if err := json.Unmarshal(recFinalize.Body.Bytes(), &finalizedOrder); err != nil {
		t.Fatalf("failed to parse finalize order response: %v", err)
	}

	if finalizedOrder.Status != "valid" {
		t.Errorf("expected finalized order status valid, got %s", finalizedOrder.Status)
	}

	// 6. Download Certificate Chain
	certPath := strings.TrimPrefix(finalizedOrder.CertificateURL, "http://localhost:8080")
	reqCert := httptest.NewRequest("GET", certPath, nil)
	recCert := httptest.NewRecorder()
	mux.ServeHTTP(recCert, reqCert)

	if recCert.Code != http.StatusOK {
		t.Fatalf("download cert returned %d: %s", recCert.Code, recCert.Body.String())
	}

	if !strings.Contains(recCert.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("expected PEM certificate in cert response")
	}

	// 7. Verify Status Report
	status := acmeServer.GetStatus()
	if status.TotalAccounts != 1 {
		t.Errorf("expected 1 account, got %d", status.TotalAccounts)
	}
	if status.TotalOrders != 1 {
		t.Errorf("expected 1 order, got %d", status.TotalOrders)
	}
	if status.TotalCertificates != 1 {
		t.Errorf("expected 1 certificate, got %d", status.TotalCertificates)
	}
}
