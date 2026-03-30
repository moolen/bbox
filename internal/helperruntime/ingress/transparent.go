package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func TransparentHTTPHandler(rt Bridge) http.Handler {
	return transparentHTTPHandlerForDestination(rt, "", 0)
}

func transparentHTTPHandlerForDestination(rt Bridge, connectHost string, connectPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			http.Error(w, "transparent HTTP listener does not accept CONNECT", http.StatusMethodNotAllowed)
			return
		}

		serveHTTPForward(w, req, rt, func(req *http.Request) (*http.Request, error) {
			return RewriteTransparentHTTPRequestWithTarget(req, connectHost, connectPort)
		})
	})
}

func ServeTransparentHTTPSConn(conn net.Conn, rt Bridge, connectHost string, connectPort int) {
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
				serverName = strings.ToLower(strings.TrimSpace(connectHost))
			}
			if serverName == "" {
				return nil, fmt.Errorf("transparent HTTPS requires SNI or original destination")
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

	if connectPort == 0 {
		connectPort = 443
	}
	serveMITMConn(tlsConn, rt, serverName, connectPort)
}

func RewriteTransparentHTTPRequest(req *http.Request) (*http.Request, error) {
	return RewriteTransparentHTTPRequestWithTarget(req, "", 0)
}

func RewriteTransparentHTTPRequestWithTarget(req *http.Request, connectHost string, connectPort int) (*http.Request, error) {
	if req.URL == nil {
		return nil, errors.New("transparent HTTP request URL is required")
	}

	host := strings.TrimSpace(req.Host)
	if host == "" {
		host = transparentAuthority(connectHost, connectPort)
	}
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

func transparentAuthority(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if port <= 0 || port == 80 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
