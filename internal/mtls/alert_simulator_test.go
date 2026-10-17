package mtls

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunAlertSimulation(t *testing.T) {
	testCodes := []int{40, 42, 45, 46, 48, 112}

	for _, code := range testCodes {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		res, err := TestAlertSimulation(ctx, code)
		cancel()

		if err != nil {
			t.Fatalf("TestAlertSimulation failed for alert %d: %v", code, err)
		}

		if res.DetectedAlert != code {
			// Some platforms might report error without exact code, but must have non-empty client error
			if !strings.Contains(strings.ToLower(res.ClientError), "alert") {
				t.Errorf("expected alert detection or alert in client error for %d, got: %s", code, res.ClientError)
			}
		}

		if res.Diagnostics.Summary == "" {
			t.Errorf("expected non-empty diagnostic summary for alert %d", code)
		}
	}
}
