package handshake

// ALPNProtocolInfo contains human-readable explanation of an ALPN string.
type ALPNProtocolInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ALPNRegistry maps common ALPN IDs to descriptions.
var ALPNRegistry = map[string]ALPNProtocolInfo{
	"h2": {
		ID:          "h2",
		Name:        "HTTP/2",
		Description: "Binary multiplexed framing protocol over TLS",
	},
	"http/1.1": {
		ID:          "http/1.1",
		Name:        "HTTP/1.1",
		Description: "Standard textual HTTP protocol over TLS",
	},
	"h3": {
		ID:          "h3",
		Name:        "HTTP/3",
		Description: "HTTP over QUIC transport",
	},
	"grpc-exp": {
		ID:          "grpc-exp",
		Name:        "gRPC Experimental",
		Description: "Experimental gRPC channel",
	},
}

// GetALPNInfo returns protocol metadata for an ALPN token.
func GetALPNInfo(token string) ALPNProtocolInfo {
	if info, ok := ALPNRegistry[token]; ok {
		return info
	}
	return ALPNProtocolInfo{
		ID:          token,
		Name:        token,
		Description: "Custom application layer protocol",
	}
}
