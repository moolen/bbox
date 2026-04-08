package ingress

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const transparentProtocolSniffTimeout = time.Second

func ServeTransparentTCPConn(conn net.Conn, rt Bridge, connectHost string, connectPort int) {
	if conn == nil {
		return
	}

	_ = conn.SetDeadline(timeNow().Add(transparentProtocolSniffTimeout))
	reader := bufio.NewReader(conn)
	wrappedConn := &preloadedConn{Conn: conn, reader: reader}

	switch detectTransparentTCPProtocol(reader) {
	case transparentTCPProtocolTLS:
		if !authorizeTransparentTCPConn(conn, rt, connectHost, connectPort, 443, helperproto.ProtocolMetadata{
			Protocol:   "https",
			Source:     "tls_client_hello",
			Confidence: "probable",
		}) {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		ServeTransparentHTTPSConn(wrappedConn, rt, connectHost, connectPort)
	case transparentTCPProtocolHTTP:
		if !authorizeTransparentTCPConn(conn, rt, connectHost, connectPort, 80, helperproto.ProtocolMetadata{
			Protocol:   "http",
			Source:     "first_bytes",
			Confidence: "probable",
		}) {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		serveTransparentHTTPConn(wrappedConn, rt, connectHost, connectPort)
	default:
		if !authorizeTransparentTCPConn(conn, rt, connectHost, connectPort, 0, opaqueProtocolMetadata(reader)) {
			return
		}
		closeWithRST(conn)
	}
}

func authorizeTransparentTCPConn(conn net.Conn, rt Bridge, connectHost string, connectPort int, defaultPort int, metadata helperproto.ProtocolMetadata) bool {
	connectHost = strings.TrimSpace(connectHost)
	if connectHost == "" {
		return true
	}
	if connectPort <= 0 {
		connectPort = defaultPort
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectHandshakeTimeout)
	defer cancel()

	response, err := rt.AuthorizeTransparentConnect(ctx, connectHost, connectPort, metadata)
	if err != nil {
		closeWithRST(conn)
		return false
	}
	if response == nil {
		closeWithRST(conn)
		return false
	}
	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	if response.Error != "" || statusCode < 200 || statusCode >= 300 {
		closeWithRST(conn)
		return false
	}
	return true
}

type transparentTCPProtocol string

const (
	transparentTCPProtocolUnknown transparentTCPProtocol = "unknown"
	transparentTCPProtocolHTTP    transparentTCPProtocol = "http"
	transparentTCPProtocolTLS     transparentTCPProtocol = "tls"
)

func detectTransparentTCPProtocol(reader *bufio.Reader) transparentTCPProtocol {
	if reader == nil {
		return transparentTCPProtocolUnknown
	}

	prefix, err := reader.Peek(1)
	if err != nil {
		return transparentTCPProtocolUnknown
	}
	if len(prefix) > 0 && prefix[0] == 0x16 {
		if looksLikeTLSClientHello(reader) {
			return transparentTCPProtocolTLS
		}
		return transparentTCPProtocolUnknown
	}
	if looksLikeHTTP2ClientPreface(reader) || looksLikeHTTP1Request(reader) {
		return transparentTCPProtocolHTTP
	}
	return transparentTCPProtocolUnknown
}

func opaqueProtocolMetadata(reader *bufio.Reader) helperproto.ProtocolMetadata {
	if reader == nil {
		return helperproto.ProtocolMetadata{}
	}

	prefix, err := reader.Peek(reader.Buffered())
	if err != nil && len(prefix) == 0 {
		return helperproto.ProtocolMetadata{}
	}

	detected := detectOpaqueTCPProtocol(prefix)
	if detected.Protocol == "" {
		return helperproto.ProtocolMetadata{}
	}
	return helperproto.ProtocolMetadata{
		Protocol:   detected.Protocol,
		Source:     detected.Source,
		Confidence: detected.Confidence,
	}
}

func serveTransparentHTTPConn(conn net.Conn, rt Bridge, connectHost string, connectPort int) {
	server := &http.Server{
		Handler: h2c.NewHandler(
			transparentHTTPHandlerForDestination(rt, connectHost, connectPort),
			&http2.Server{},
		),
	}
	serveErr := server.Serve(&singleConnListener{conn: conn})
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		bridgeLogger(rt).Printf("serve transparent TCP connection: %v", serveErr)
	}
}

func closeWithRST(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()
}

func looksLikeTLSClientHello(reader *bufio.Reader) bool {
	header, err := reader.Peek(3)
	if err != nil || len(header) < 3 {
		return false
	}
	return looksLikeTLSClientHelloBytes(header)
}

func looksLikeHTTP2ClientPreface(reader *bufio.Reader) bool {
	prefix, err := reader.Peek(len(http2ClientPreface))
	if err != nil || len(prefix) < len(http2ClientPreface) {
		return false
	}
	return string(prefix) == http2ClientPreface
}

func looksLikeHTTP1Request(reader *bufio.Reader) bool {
	peekLen := 16
	if reader.Buffered() > peekLen {
		peekLen = reader.Buffered()
	}
	prefix, err := reader.Peek(peekLen)
	if err != nil && len(prefix) == 0 {
		return false
	}
	upper := strings.ToUpper(string(prefix))
	for _, method := range []string{
		"GET ",
		"HEAD ",
		"POST ",
		"PUT ",
		"PATCH ",
		"DELETE ",
		"OPTIONS ",
		"TRACE ",
	} {
		if strings.HasPrefix(upper, method) {
			return true
		}
	}
	return false
}
