package ingress

import (
	"bytes"
	"encoding/binary"
)

type detectedProtocol struct {
	Protocol   string
	Source     string
	Confidence string
}

func detectOpaqueTCPProtocol(prefix []byte) detectedProtocol {
	if len(prefix) == 0 {
		return detectedProtocol{}
	}

	if isMySQLGreeting(prefix) {
		return detectedProtocol{
			Protocol:   "mysql",
			Source:     "first_bytes",
			Confidence: "definite",
		}
	}
	if isPostgresSSLRequest(prefix) {
		return detectedProtocol{
			Protocol:   "postgres",
			Source:     "first_bytes",
			Confidence: "definite",
		}
	}
	if isPostgresStartup(prefix) {
		return detectedProtocol{
			Protocol:   "postgres",
			Source:     "first_bytes",
			Confidence: "probable",
		}
	}
	if isRedisPrefix(prefix) {
		return detectedProtocol{
			Protocol:   "redis",
			Source:     "first_bytes",
			Confidence: "probable",
		}
	}
	if bytes.HasPrefix(prefix, []byte("SSH-")) {
		return detectedProtocol{
			Protocol:   "ssh",
			Source:     "first_bytes",
			Confidence: "definite",
		}
	}
	if looksLikeTLSClientHelloBytes(prefix) {
		return detectedProtocol{
			Protocol:   "tls_non_http",
			Source:     "tls_client_hello",
			Confidence: "probable",
		}
	}

	return detectedProtocol{
		Protocol:   "unknown",
		Source:     "first_bytes",
		Confidence: "unknown",
	}
}

func isMySQLGreeting(prefix []byte) bool {
	if len(prefix) < 5 {
		return false
	}
	payloadLen := int(prefix[0]) | int(prefix[1])<<8 | int(prefix[2])<<16
	if payloadLen < 1 {
		return false
	}
	return prefix[3] == 0x00 && prefix[4] == 0x0a
}

func isPostgresSSLRequest(prefix []byte) bool {
	if len(prefix) < 8 {
		return false
	}
	return binary.BigEndian.Uint32(prefix[:4]) == 8 && binary.BigEndian.Uint32(prefix[4:8]) == 80877103
}

func isPostgresStartup(prefix []byte) bool {
	if len(prefix) < 8 {
		return false
	}
	length := binary.BigEndian.Uint32(prefix[:4])
	version := binary.BigEndian.Uint32(prefix[4:8])
	if length < 8 || version != 196608 {
		return false
	}
	return bytes.Contains(prefix[8:], []byte{0x00})
}

func isRedisPrefix(prefix []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	switch prefix[0] {
	case '*', '+', '-', ':', '$':
		return true
	default:
		return false
	}
}

func looksLikeTLSClientHelloBytes(prefix []byte) bool {
	if len(prefix) < 3 {
		return false
	}
	return prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] >= 0x01 && prefix[2] <= 0x04
}
