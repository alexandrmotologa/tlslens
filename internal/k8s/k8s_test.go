package k8s

import (
	"strings"
	"testing"
)

func TestGenerateManifests(t *testing.T) {
	opts := ManifestOptions{
		Name:        "web-gateway",
		Namespace:   "production",
		CertPEM:     []byte("-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----"),
		KeyPEM:      []byte("-----BEGIN PRIVATE KEY-----\nTEST_KEY\n-----END PRIVATE KEY-----"),
		CAPEM:       []byte("-----BEGIN CERTIFICATE-----\nROOT_CA\n-----END CERTIFICATE-----"),
		Domains:     []string{"api.example.com", "gateway.example.com"},
		ServiceName: "web-svc",
		ServicePort: 8080,
	}

	bundle := GenerateManifests(opts)

	if !strings.Contains(bundle.TLSSecret, "kind: Secret") || !strings.Contains(bundle.TLSSecret, "web-gateway-tls") {
		t.Errorf("TLSSecret missing expected fields")
	}

	if !strings.Contains(bundle.CAConfigMap, "kind: ConfigMap") || !strings.Contains(bundle.CAConfigMap, "web-gateway-ca") {
		t.Errorf("CAConfigMap missing expected fields")
	}

	if !strings.Contains(bundle.CertManagerIssuer, "kind: ClusterIssuer") || !strings.Contains(bundle.CertManagerIssuer, "tlslens-local-ca") {
		t.Errorf("CertManagerIssuer missing expected ClusterIssuer")
	}

	if !strings.Contains(bundle.Ingress, "api.example.com") || !strings.Contains(bundle.Ingress, "web-svc") {
		t.Errorf("Ingress missing domain or service name")
	}

	if !strings.Contains(bundle.KubectlCommand, "kubectl apply -n production") {
		t.Errorf("KubectlCommand incorrect namespace")
	}
}
