package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestServerLifecycleAndEndpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "server_test")
	if err != nil {
		t.Fatalf("temp dir err: %v", err)
	}
	defer os.RemoveAll(tempDir)

	srv, err := NewServer(ServerOptions{
		Port:       0, // dynamic port
		StorageDir: tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		_ = srv.Stop(context.Background())
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())

	// 1. Check CA status (initially uninitialized)
	resp, err := http.Get(baseURL + "/api/ca/status")
	if err != nil {
		t.Fatalf("GET /api/ca/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var caStatus map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&caStatus)
	resp.Body.Close()
	if caStatus["initialized"] != false {
		t.Errorf("expected initialized: false initially")
	}

	// 2. Initialize Root CA
	initBody := bytes.NewBufferString(`{"commonName":"Test API Root CA","validityDays":5,"keyType":"ecdsa"}`)
	respInit, err := http.Post(baseURL+"/api/ca/init", "application/json", initBody)
	if err != nil {
		t.Fatalf("POST /api/ca/init failed: %v", err)
	}
	if respInit.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for init, got %d", respInit.StatusCode)
	}
	respInit.Body.Close()

	// 3. Issue leaf certificate
	issueBody := bytes.NewBufferString(`{"commonName":"test.local","domains":["test.local"],"ips":["127.0.0.1"],"validityDays":1}`)
	respIssue, err := http.Post(baseURL+"/api/ca/issue", "application/json", issueBody)
	if err != nil {
		t.Fatalf("POST /api/ca/issue failed: %v", err)
	}
	if respIssue.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for issue, got %d", respIssue.StatusCode)
	}
	var issueRes map[string]any
	_ = json.NewDecoder(respIssue.Body).Decode(&issueRes)
	respIssue.Body.Close()
	if issueRes["success"] != true {
		t.Errorf("expected issue success: true")
	}

	// 4. Test mTLS mock server start
	startBody := bytes.NewBufferString(`{"port":0,"clientAuth":"require_and_verify"}`)
	respStart, err := http.Post(baseURL+"/api/mtls/server/start", "application/json", startBody)
	if err != nil {
		t.Fatalf("POST /api/mtls/server/start failed: %v", err)
	}
	if respStart.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for mTLS server start, got %d", respStart.StatusCode)
	}
	respStart.Body.Close()

	// 5. Test configs endpoint
	confBody := bytes.NewBufferString(`{"domain":"app.test","port":443}`)
	respConf, err := http.Post(baseURL+"/api/configs", "application/json", confBody)
	if err != nil {
		t.Fatalf("POST /api/configs failed: %v", err)
	}
	if respConf.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for configs, got %d", respConf.StatusCode)
	}
	respConf.Body.Close()
}
