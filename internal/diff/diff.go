package diff

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
	"github.com/alexandrmotologa/tlslens/internal/inspector"
)

// FieldDiff captures the comparison of a single property between two targets.
type FieldDiff struct {
	Field        string `json:"field"`
	ValueA       string `json:"valueA"`
	ValueB       string `json:"valueB"`
	IsDifferent  bool   `json:"isDifferent"`
	Significance string `json:"significance"` // "match", "info", "warning", "divergence"
}

// DiffResult encapsulates full side-by-side comparative analysis.
type DiffResult struct {
	TargetA           string                 `json:"targetA"`
	TargetB           string                 `json:"targetB"`
	ProbeA            *handshake.ProbeResult `json:"probeA"`
	ProbeB            *handshake.ProbeResult `json:"probeB"`
	HierarchyA        *inspector.ChainHierarchy `json:"hierarchyA,omitempty"`
	HierarchyB        *inspector.ChainHierarchy `json:"hierarchyB,omitempty"`
	LatencyDiffMs     float64                `json:"latencyDiffMs"`     // ProbeB - ProbeA
	FasterTarget      string                 `json:"fasterTarget"`      // "A", "B", or "equal"
	TotalDiffCount    int                    `json:"totalDiffCount"`
	ProtocolMatch     bool                   `json:"protocolMatch"`
	CipherMatch       bool                   `json:"cipherMatch"`
	ALPNMatch         bool                   `json:"alpnMatch"`
	IssuerMatch       bool                   `json:"issuerMatch"`
	Differences       []FieldDiff            `json:"differences"`
}

// CompareTargets runs concurrent probes against two endpoints and computes differences.
func CompareTargets(ctx context.Context, targetA, targetB string, rootPool *x509.CertPool) (*DiffResult, error) {
	if strings.TrimSpace(targetA) == "" || strings.TrimSpace(targetB) == "" {
		return nil, fmt.Errorf("both targetA and targetB are required for side-by-side diff")
	}

	optsA := handshake.ProbeOptions{RootCAs: rootPool, ALPNProtocols: []string{"h2", "http/1.1"}}
	optsB := handshake.ProbeOptions{RootCAs: rootPool, ALPNProtocols: []string{"h2", "http/1.1"}}

	var probeA, probeB *handshake.ProbeResult
	var errA, errB error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		probeA, errA = handshake.ProbeEndpoint(ctx, targetA, optsA)
	}()
	go func() {
		defer wg.Done()
		probeB, errB = handshake.ProbeEndpoint(ctx, targetB, optsB)
	}()
	wg.Wait()

	if errA != nil && probeA == nil {
		return nil, fmt.Errorf("probe failed for target A (%s): %w", targetA, errA)
	}
	if errB != nil && probeB == nil {
		return nil, fmt.Errorf("probe failed for target B (%s): %w", targetB, errB)
	}

	result := &DiffResult{
		TargetA: targetA,
		TargetB: targetB,
		ProbeA:  probeA,
		ProbeB:  probeB,
	}

	// Compute Latency Diff
	latencyDiff := probeB.TotalDurationMs - probeA.TotalDurationMs
	result.LatencyDiffMs = latencyDiff
	if latencyDiff > 0.5 {
		result.FasterTarget = "A"
	} else if latencyDiff < -0.5 {
		result.FasterTarget = "B"
	} else {
		result.FasterTarget = "equal"
	}

	// Compute Comparison Fields
	result.ProtocolMatch = probeA.TLSVersion == probeB.TLSVersion
	result.CipherMatch = probeA.Cipher.ID == probeB.Cipher.ID
	result.ALPNMatch = probeA.ALPN == probeB.ALPN

	var diffs []FieldDiff

	// 1. TLS Protocol Version
	diffs = append(diffs, makeFieldDiff(
		"TLS Version",
		probeA.TLSVersion,
		probeB.TLSVersion,
		"divergence",
	))

	// 2. Cipher Suite Name
	diffs = append(diffs, makeFieldDiff(
		"Cipher Suite",
		probeA.Cipher.Name,
		probeB.Cipher.Name,
		"warning",
	))

	// 3. Perfect Forward Secrecy (PFS)
	diffs = append(diffs, makeFieldDiff(
		"Forward Secrecy (PFS)",
		fmt.Sprintf("%t", probeA.Cipher.IsPFS),
		fmt.Sprintf("%t", probeB.Cipher.IsPFS),
		"divergence",
	))

	// 4. ALPN Protocol
	diffs = append(diffs, makeFieldDiff(
		"ALPN Negotiated",
		probeA.ALPN,
		probeB.ALPN,
		"info",
	))

	// 5. Total Handshake Latency
	diffs = append(diffs, FieldDiff{
		Field:        "Total Latency",
		ValueA:       fmt.Sprintf("%.2f ms", probeA.TotalDurationMs),
		ValueB:       fmt.Sprintf("%.2f ms", probeB.TotalDurationMs),
		IsDifferent:  result.FasterTarget != "equal",
		Significance: "info",
	})

	// 6. Certificate comparison if available
	if len(probeA.PeerCertificates) > 0 && len(probeB.PeerCertificates) > 0 {
		leafA := probeA.PeerCertificates[0]
		leafB := probeB.PeerCertificates[0]

		diffs = append(diffs, makeFieldDiff("Leaf Common Name", leafA.CommonName, leafB.CommonName, "divergence"))
		diffs = append(diffs, makeFieldDiff("Leaf Issuer", leafA.Issuer, leafB.Issuer, "divergence"))
		diffs = append(diffs, makeFieldDiff("SANs Count", fmt.Sprintf("%d SANs", len(leafA.DNSNames)), fmt.Sprintf("%d SANs", len(leafB.DNSNames)), "info"))
		diffs = append(diffs, makeFieldDiff("Key Type & Length", fmt.Sprintf("%s %d-bit", leafA.KeyType, leafA.KeyLength), fmt.Sprintf("%s %d-bit", leafB.KeyType, leafB.KeyLength), "warning"))
		diffs = append(diffs, makeFieldDiff("Days to Expiry", fmt.Sprintf("%d days", leafA.DaysRemaining), fmt.Sprintf("%d days", leafB.DaysRemaining), "info"))
		diffs = append(diffs, makeFieldDiff("SHA256 Fingerprint", leafA.FingerprintSHA256, leafB.FingerprintSHA256, "info"))

		result.IssuerMatch = leafA.Issuer == leafB.Issuer
	}

	// Count true differences
	diffCount := 0
	for _, d := range diffs {
		if d.IsDifferent {
			diffCount++
		}
	}

	result.TotalDiffCount = diffCount
	result.Differences = diffs

	return result, nil
}

func makeFieldDiff(field, valA, valB, diffSignificance string) FieldDiff {
	isDiff := valA != valB
	sig := "match"
	if isDiff {
		sig = diffSignificance
	}
	return FieldDiff{
		Field:        field,
		ValueA:       valA,
		ValueB:       valB,
		IsDifferent:  isDiff,
		Significance: sig,
	}
}
