package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func TransparentHTTPHandler(rt Bridge) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			http.Error(w, "transparent HTTP listener does not accept CONNECT", http.StatusMethodNotAllowed)
			return
		}

		serveHTTPForward(w, req, rt, RewriteTransparentHTTPRequest)
	})
}

func ServeTransparentHTTPSConn(conn net.Conn, rt Bridge) {
	if conn == nil {
		return
	}
	if !rt.MITMEnabled() {
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(timeNow().Add(connectHandshakeTimeout))
	handshakeCtx, cancel := context.WithTimeout(context.Background(), connectHandshakeTimeout)
	defer cancel()

	var (
		serverName string
		leafCert   *tls.Certificate
	)
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if leafCert != nil {
				return leafCert, nil
			}

			serverName = strings.ToLower(strings.TrimSpace(hello.ServerName))
			if serverName == "" {
				return nil, fmt.Errorf("transparent HTTPS requires SNI")
			}

			cert, err := rt.RequestLeafCert(handshakeCtx, serverName)
			if err != nil {
				return nil, err
			}
			leafCert = &cert
			return leafCert, nil
		},
	})
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.SetDeadline(time.Time{})
		_ = tlsConn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	serveMITMConn(tlsConn, rt, serverName, 443)
}

func RewriteTransparentHTTPRequest(req *http.Request) (*http.Request, error) {
	if req.URL == nil {
		return nil, errors.New("transparent HTTP request URL is required")
	}

	host := strings.TrimSpace(req.Host)
	if host == "" {
		return nil, errors.New("transparent HTTP request host is required")
	}

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	out := req.Clone(req.Context())
	urlCopy := url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}
	out.URL = &urlCopy
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	out.Header.Del("Proxy-Connection")

	return out, nil
}
