package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	bridgepkg "github.com/moolen/bbox/internal/helperruntime/bridge"
	"golang.org/x/net/http2"
)

func HandleMITMConnect(rt Bridge, w http.ResponseWriter, req *http.Request) {
	host, port, err := parseConnectTarget(req.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijack proxy connection: %v", err), http.StatusBadGateway)
		return
	}

	bufferedPayload, err := drainHijackBufferedBytes(rw)
	if err != nil {
		writeConnectError(rt, conn, http.StatusBadGateway, fmt.Sprintf("read buffered connect payload: %v", err))
		return
	}

	_ = conn.SetDeadline(timeNow().Add(connectHandshakeTimeout))
	connectCtx, cancelConnect := context.WithTimeout(req.Context(), connectHandshakeTimeout)
	defer cancelConnect()

	response, err := rt.AuthorizeConnect(connectCtx, host, port)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		writeConnectError(rt, conn, connectErrorStatus(err), err.Error())
		return
	}
	if response == nil {
		_ = conn.SetDeadline(time.Time{})
		writeConnectError(rt, conn, http.StatusBadGateway, "empty connect response")
		return
	}

	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	if response.Error != "" || statusCode < 200 || statusCode >= 300 {
		message := response.Message
		if message == "" {
			message = response.Error
		}
		_ = conn.SetDeadline(time.Time{})
		writeConnectError(rt, conn, statusCode, message)
		return
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}

	leafCert, err := rt.RequestLeafCert(connectCtx, host)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		_ = conn.Close()
		return
	}

	serverConn := net.Conn(conn)
	if len(bufferedPayload) > 0 {
		serverConn = &preloadedConn{Conn: conn, reader: bytes.NewReader(bufferedPayload)}
	}

	tlsConn := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.HandshakeContext(connectCtx); err != nil {
		_ = conn.SetDeadline(time.Time{})
		_ = tlsConn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	serveMITMConn(tlsConn, rt, host, port)
}

func mitmHandler(rt Bridge, connectHost string, connectPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, tooLarge, err := bridgepkg.ReadBoundedBody(req.Body, rt.MaxRequestBodyBytes())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		host := req.Host
		if host == "" {
			host = connectHost
		}
		response, err := rt.MITMRoundTrip(req.Context(), helperproto.MITMRequest{
			Scheme:       "https",
			Authority:    net.JoinHostPort(connectHost, strconv.Itoa(connectPort)),
			Host:         host,
			Method:       req.Method,
			Path:         req.URL.Path,
			RawQuery:     req.URL.RawQuery,
			Header:       req.Header.Clone(),
			Body:         body,
			Proto:        req.Proto,
			BodyTooLarge: tooLarge,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		copyHeader(w.Header(), response.Header)
		if response.StatusCode == 0 {
			response.StatusCode = http.StatusBadGateway
		}
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, bytes.NewReader(response.Body)); err != nil {
			bridgeLogger(rt).Printf("copy MITM response body: %v", err)
		}
	})
}

func serveMITMConn(conn net.Conn, rt Bridge, connectHost string, connectPort int) {
	server := &http.Server{
		Handler: mitmHandler(rt, connectHost, connectPort),
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		bridgeLogger(rt).Printf("configure MITM HTTP/2 server: %v", err)
	}
	serveErr := server.Serve(&singleConnListener{conn: conn})
	if serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, net.ErrClosed) {
		bridgeLogger(rt).Printf("serve MITM connection: %v", serveErr)
	}
}

type preloadedConn struct {
	net.Conn
	reader io.Reader
}

func (c *preloadedConn) Read(p []byte) (int, error) {
	if c.reader != nil {
		n, err := c.reader.Read(p)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
		} else if err != nil || n > 0 {
			return n, err
		}
	}
	return c.Conn.Read(p)
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted net.Conn
	l.once.Do(func() {
		accepted = l.conn
		l.conn = nil
	})
	if accepted != nil {
		return accepted, nil
	}
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return listenerAddr("single-conn")
}

type listenerAddr string

func (a listenerAddr) Network() string { return string(a) }
func (a listenerAddr) String() string  { return string(a) }
