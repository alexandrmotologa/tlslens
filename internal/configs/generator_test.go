package configs

import (
	"strings"
	"testing"
)

func TestGenerateSnippets(t *testing.T) {
	snippets := GenerateSnippets(ConfigParameters{
		CertPath:    "/custom/cert.pem",
		KeyPath:     "/custom/key.pem",
		CAPath:      "/custom/root-ca.crt",
		Domain:      "test.local",
		Port:        8443,
		BackendAddr: "127.0.0.1:8000",
	})

	if len(snippets) < 6 {
		t.Errorf("expected at least 6 config snippets, got %d", len(snippets))
	}

	foundNginx := false
	for _, s := range snippets {
		if s.ID == "nginx-mtls" {
			foundNginx = true
			if !strings.Contains(s.Code, "server_name test.local;") {
				t.Errorf("nginx snippet missing custom domain")
			}
			if !strings.Contains(s.Code, "ssl_client_certificate /custom/root-ca.crt;") {
				t.Errorf("nginx snippet missing custom CA path")
			}
		}
	}

	if !foundNginx {
		t.Errorf("nginx snippet not found")
	}

	compose := GenerateComposeBlock("api-gateway", "./certs")
	if !strings.Contains(compose, "api-gateway:") {
		t.Errorf("compose block invalid")
	}
}
