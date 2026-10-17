package inspector

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/alexandrmotologa/tlslens/internal/handshake"
)

// ChainHierarchy represents an organized hierarchical tree for visual rendering.
type ChainHierarchy struct {
	Leaf          handshake.CertSummary   `json:"leaf"`
	Intermediates []handshake.CertSummary `json:"intermediates"`
	Root          *handshake.CertSummary  `json:"root,omitempty"`
	ChainLength   int                     `json:"chainLength"`
	IsValid       bool                    `json:"isValid"`
	ValidationError string                `json:"validationError,omitempty"`
}

// BuildHierarchy orders a slice of peer certificates into Leaf -> Intermediates -> Root.
func BuildHierarchy(certs []*x509.Certificate, rootPool *x509.CertPool) ChainHierarchy {
	if len(certs) == 0 {
		return ChainHierarchy{}
	}

	leaf := ParseCertSummary(certs[0])
	var intermediates []handshake.CertSummary
	var root *handshake.CertSummary

	for i := 1; i < len(certs); i++ {
		summary := ParseCertSummary(certs[i])
		if certs[i].IsCA && certs[i].CheckSignatureFrom(certs[i]) == nil {
			// Self-signed root certificate
			rootCopy := summary
			root = &rootCopy
		} else {
			intermediates = append(intermediates, summary)
		}
	}

	hierarchy := ChainHierarchy{
		Leaf:          leaf,
		Intermediates: intermediates,
		Root:          root,
		ChainLength:   len(certs),
		IsValid:       true,
	}

	// Run verification against roots
	verifyOpts := x509.VerifyOptions{
		DNSName:       leaf.CommonName,
		Roots:         rootPool,
		Intermediates: x509.NewCertPool(),
	}
	for i := 1; i < len(certs); i++ {
		verifyOpts.Intermediates.AddCert(certs[i])
	}

	if _, err := certs[0].Verify(verifyOpts); err != nil {
		hierarchy.IsValid = false
		hierarchy.ValidationError = err.Error()
	}

	return hierarchy
}

// ParseCertificatesFromPEM parses all certificates contained in a PEM block slice.
func ParseCertificatesFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate block: %w", err)
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found in PEM data")
	}

	return certs, nil
}
