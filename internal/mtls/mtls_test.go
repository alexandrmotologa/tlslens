package mtls

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/alexandrmotologa/tlslens/internal/ca"
)

func TestMTLSSuccessAndRejectionScenarios(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "mtls_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generate trusted server CA
	serverCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "mTLS Server Trusted Root CA",
		ValidityDays: 1,
		StorageDir:   tempDir,
	})
	if err != nil {
		t.Fatalf("failed to create server CA: %v", err)
	}

	// 2. Issue server cert
	serverLeaf, err := serverCA.Issue(ca.IssueRequest{
		CommonName:   "127.0.0.1",
		IPs:          []string{"127.0.0.1"},
		ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("failed to issue server leaf: %v", err)
	}

	// 3. Issue valid client cert from serverCA
	validClientLeaf, err := serverCA.Issue(ca.IssueRequest{
		CommonName:   "client.internal.test",
		Domains:      []string{"client.internal.test"},
		ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("failed to issue client leaf: %v", err)
	}

	// 4. Generate rogue/untrusted CA and client cert
	untrustedCA, err := ca.NewCA(ca.CAConfig{
		CommonName:   "Untrusted Rogue Root CA",
		ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("failed to create untrusted CA: %v", err)
	}
	rogueClientLeaf, err := untrustedCA.Issue(ca.IssueRequest{
		CommonName:   "rogue.client",
		ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("failed to issue rogue client leaf: %v", err)
	}

	// 5. Start Mock Server requiring and verifying client cert
	mockServer := NewMockServer(ServerConfig{
		Port:          0, // dynamic
		ClientAuth:    "require_and_verify",
		ServerCertPEM: serverLeaf.CertPEM,
		ServerKeyPEM:  serverLeaf.KeyPEM,
		ClientCAPEM:   serverCA.CertPEM,
	})

	if err := mockServer.Start(); err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer mockServer.Stop()

	serverURL := fmt.Sprintf("https://127.0.0.1:%d", mockServer.Port())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Scenario A: Valid client cert -> should succeed
	resSuccess, err := RunClientTest(ctx, ClientTestRequest{
		TargetURL:          serverURL,
		RootCAPEM:          serverCA.CertPEM,
		ClientCertPEM:      validClientLeaf.CertPEM,
		ClientKeyPEM:       validClientLeaf.KeyPEM,
		InsecureSkipVerify: false,
		ServerName:         "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("RunClientTest error: %v", err)
	}
	if !resSuccess.Success {
		t.Errorf("expected mTLS to succeed with valid cert, got failure: %s", resSuccess.Diagnostics.OriginalError)
	}

	// Scenario B: No client cert presented -> should fail
	resNoCert, err := RunClientTest(ctx, ClientTestRequest{
		TargetURL:          serverURL,
		RootCAPEM:          serverCA.CertPEM,
		InsecureSkipVerify: false,
		ServerName:         "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("RunClientTest error: %v", err)
	}
	if resNoCert.Success {
		t.Errorf("expected mTLS to fail without client cert, but it succeeded")
	}
	if resNoCert.Diagnostics.Summary == "" {
		t.Errorf("expected diagnostic summary for rejection")
	}

	// Scenario C: Rogue client cert (signed by untrusted CA) -> should fail with certificate unknown or bad cert
	resRogue, err := RunClientTest(ctx, ClientTestRequest{
		TargetURL:          serverURL,
		RootCAPEM:          serverCA.CertPEM,
		ClientCertPEM:      rogueClientLeaf.CertPEM,
		ClientKeyPEM:       rogueClientLeaf.KeyPEM,
		InsecureSkipVerify: false,
		ServerName:         "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("RunClientTest error: %v", err)
	}
	if resRogue.Success {
		t.Errorf("expected mTLS to fail with rogue cert, but it succeeded")
	}
	if len(resRogue.Diagnostics.RemediationSteps) == 0 {
		t.Errorf("expected remediation steps for rogue cert rejection")
	}

	// Check that events were recorded by server
	events := mockServer.GetEvents()
	if len(events) == 0 {
		t.Errorf("expected mock server to record connection events")
	}
}
