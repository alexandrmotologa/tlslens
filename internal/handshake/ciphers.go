package handshake

import (
	"crypto/tls"
	"fmt"
)

// CipherInfo provides human-readable cryptographic details for a cipher suite.
type CipherInfo struct {
	ID             uint16 `json:"id"`
	Hex            string `json:"hex"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	KeyExchange    string `json:"keyExchange"`
	Encryption     string `json:"encryption"`
	IsPFS          bool   `json:"isPfs"`
	SecurityStatus string `json:"securityStatus"` // "recommended", "secure", "weak", "insecure"
}

// CipherSuiteMap holds known TLS 1.2 and TLS 1.3 cipher suites.
var CipherSuiteMap = map[uint16]CipherInfo{
	// TLS 1.3
	tls.TLS_AES_128_GCM_SHA256: {
		ID:             tls.TLS_AES_128_GCM_SHA256,
		Hex:            "0x1301",
		Name:           "TLS_AES_128_GCM_SHA256",
		Protocol:       "TLS 1.3",
		KeyExchange:    "ECDHE / DHE",
		Encryption:     "AES-128-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_AES_256_GCM_SHA384: {
		ID:             tls.TLS_AES_256_GCM_SHA384,
		Hex:            "0x1302",
		Name:           "TLS_AES_256_GCM_SHA384",
		Protocol:       "TLS 1.3",
		KeyExchange:    "ECDHE / DHE",
		Encryption:     "AES-256-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_CHACHA20_POLY1305_SHA256: {
		ID:             tls.TLS_CHACHA20_POLY1305_SHA256,
		Hex:            "0x1303",
		Name:           "TLS_CHACHA20_POLY1305_SHA256",
		Protocol:       "TLS 1.3",
		KeyExchange:    "ECDHE / DHE",
		Encryption:     "CHACHA20-POLY1305",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},

	// TLS 1.2 ECDHE Secure
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		ID:             tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Hex:            "0xC02B",
		Name:           "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-128-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {
		ID:             tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		Hex:            "0xC02C",
		Name:           "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-256-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		ID:             tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Hex:            "0xC02F",
		Name:           "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-128-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {
		ID:             tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		Hex:            "0xC030",
		Name:           "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-256-GCM",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {
		ID:             tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		Hex:            "0xCCA8",
		Name:           "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "CHACHA20-POLY1305",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {
		ID:             tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		Hex:            "0xCCA9",
		Name:           "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "CHACHA20-POLY1305",
		IsPFS:          true,
		SecurityStatus: "recommended",
	},

	// TLS 1.2 CBC (Acceptable / Weak)
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: {
		ID:             tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		Hex:            "0xC013",
		Name:           "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-128-CBC",
		IsPFS:          true,
		SecurityStatus: "weak",
	},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: {
		ID:             tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		Hex:            "0xC014",
		Name:           "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		Protocol:       "TLS 1.2",
		KeyExchange:    "ECDHE",
		Encryption:     "AES-256-CBC",
		IsPFS:          true,
		SecurityStatus: "weak",
	},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256: {
		ID:             tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		Hex:            "0x009C",
		Name:           "TLS_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:       "TLS 1.2",
		KeyExchange:    "RSA (No PFS)",
		Encryption:     "AES-128-GCM",
		IsPFS:          false,
		SecurityStatus: "weak",
	},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384: {
		ID:             tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		Hex:            "0x009D",
		Name:           "TLS_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:       "TLS 1.2",
		KeyExchange:    "RSA (No PFS)",
		Encryption:     "AES-256-GCM",
		IsPFS:          false,
		SecurityStatus: "weak",
	},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA: {
		ID:             tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		Hex:            "0x002F",
		Name:           "TLS_RSA_WITH_AES_128_CBC_SHA",
		Protocol:       "TLS 1.2",
		KeyExchange:    "RSA (No PFS)",
		Encryption:     "AES-128-CBC",
		IsPFS:          false,
		SecurityStatus: "insecure",
	},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: {
		ID:             tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		Hex:            "0x000A",
		Name:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:       "TLS 1.2",
		KeyExchange:    "RSA (No PFS)",
		Encryption:     "3DES-EDE-CBC",
		IsPFS:          false,
		SecurityStatus: "insecure",
	},
}

// GetCipherInfo looks up details for a cipher ID, falling back to dynamic name.
func GetCipherInfo(id uint16) CipherInfo {
	if info, ok := CipherSuiteMap[id]; ok {
		return info
	}

	name := tls.CipherSuiteName(id)
	if name == "" {
		name = fmt.Sprintf("Unknown Cipher (0x%04X)", id)
	}

	return CipherInfo{
		ID:             id,
		Hex:            fmt.Sprintf("0x%04X", id),
		Name:           name,
		Protocol:       "TLS",
		KeyExchange:    "Unknown",
		Encryption:     "Unknown",
		IsPFS:          false,
		SecurityStatus: "weak",
	}
}

// GetTLSVersionName converts TLS numeric constant to string.
func GetTLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionSSL30:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}
