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

	if isAMQPProtocolHeader(prefix) {
		return detectedProtocol{
			Protocol:   "amqp",
			Source:     "first_bytes",
			Confidence: "definite",
		}
	}
	if isMongoDBWireMessage(prefix) {
		return detectedProtocol{
			Protocol:   "mongodb",
			Source:     "first_bytes",
			Confidence: "definite",
		}
	}
	if isNATSClientPrefix(prefix) {
		return detectedProtocol{
			Protocol:   "nats",
			Source:     "first_bytes",
			Confidence: "probable",
		}
	}
	if isMemcachedPrefix(prefix) {
		return detectedProtocol{
			Protocol:   "memcached",
			Source:     "first_bytes",
			Confidence: "probable",
		}
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

func isAMQPProtocolHeader(prefix []byte) bool {
	if len(prefix) < 8 {
		return false
	}
	return bytes.Equal(prefix[:8], []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01})
}

func isMongoDBWireMessage(prefix []byte) bool {
	if len(prefix) < 16 {
		return false
	}
	messageLength := binary.LittleEndian.Uint32(prefix[:4])
	if messageLength < 16 || messageLength > 64<<20 {
		return false
	}
	switch binary.LittleEndian.Uint32(prefix[12:16]) {
	case 2004, 2010, 2012, 2013:
		return true
	default:
		return false
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

func isNATSClientPrefix(prefix []byte) bool {
	for _, candidate := range [][]byte{
		[]byte("CONNECT "),
		[]byte("PUB "),
		[]byte("HPUB "),
		[]byte("SUB "),
		[]byte("UNSUB "),
		[]byte("PING\r\n"),
		[]byte("PONG\r\n"),
	} {
		if bytes.HasPrefix(prefix, candidate) {
			return true
		}
	}
	return false
}

func isMemcachedPrefix(prefix []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	if prefix[0] == 0x80 || prefix[0] == 0x81 {
		return true
	}

	lower := bytes.ToLower(prefix)
	for _, candidate := range [][]byte{
		[]byte("set "),
		[]byte("add "),
		[]byte("replace "),
		[]byte("append "),
		[]byte("prepend "),
		[]byte("cas "),
		[]byte("get "),
		[]byte("gets "),
		[]byte("delete "),
		[]byte("incr "),
		[]byte("decr "),
		[]byte("touch "),
		[]byte("stats"),
		[]byte("version"),
		[]byte("flush_all"),
		[]byte("quit"),
	} {
		if bytes.HasPrefix(lower, candidate) {
			return true
		}
	}
	return false
}

func looksLikeTLSClientHelloBytes(prefix []byte) bool {
	if len(prefix) < 3 {
		return false
	}
	return prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] >= 0x01 && prefix[2] <= 0x04
}
