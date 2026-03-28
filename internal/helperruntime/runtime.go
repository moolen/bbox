package helperruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/moolen/bbox/internal/helperproto"
	bridgepkg "github.com/moolen/bbox/internal/helperruntime/bridge"
	"golang.org/x/net/http2"
)

func OpenBridgeFromFD(fd int) (io.ReadWriteCloser, error) {
	if fd < 0 {
		return nil, fmt.Errorf("bridge fd must be non-negative")
	}

	syscall.CloseOnExec(fd)

	file := os.NewFile(uintptr(fd), fmt.Sprintf("bbox-helper-bridge-%d", fd))
	if file == nil {
		return nil, fmt.Errorf("bridge fd %d is invalid", fd)
	}

	return file, nil
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Bridge == nil {
		return fmt.Errorf("bridge is required")
	}
	cfg = withDefaults(cfg)

	switch cfg.TrafficMode {
	case TrafficModeProxy:
		return runProxyMode(ctx, cfg)
	case TrafficModeTransparent:
		return runTransparentMode(ctx, cfg)
	default:
		return fmt.Errorf("unsupported traffic mode %q", cfg.TrafficMode)
	}
}

type bridge struct {
	runtimeBridge       *bridgepkg.RuntimeBridge
	logger              *log.Logger
	dnsAddr             string
	httpAddr            string
	httpsAddr           string
	mitmEnabled         bool
	maxRequestBodyBytes int64
	execMu              sync.Mutex
	execStateMu         sync.Mutex
	currentExec         *execSession
}

type execSession struct {
	stdin    io.WriteCloser
	ptyFile  *os.File
	terminal bool
}

func newBridge(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *bridge {
	return &bridge{
		runtimeBridge: bridgepkg.New(conn, logger, proxyAddr),
		logger:        logger,
	}
}

func (b *bridge) readLoop(ctx context.Context) error {
	b.runtimeBridge.SetReadyAddrs(b.dnsAddr, b.httpAddr, b.httpsAddr)
	b.runtimeBridge.SetExecHandlers(b.handleExec, b.handleExecInput)
	return b.runtimeBridge.ReadLoop(ctx)
}

func (b *bridge) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			if b.mitmEnabled {
				b.handleMITMConnect(w, req)
				return
			}
			b.handleConnect(w, req)
			return
		}

		b.serveHTTPForward(w, req, rewriteProxyRequest)
	})
}

func (b *bridge) transparentHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			http.Error(w, "transparent HTTP listener does not accept CONNECT", http.StatusMethodNotAllowed)
			return
		}

		b.serveHTTPForward(w, req, rewriteTransparentHTTPRequest)
	})
}

func (b *bridge) handleTransparentHTTPSConn(conn net.Conn) {
	if conn == nil {
		return
	}
	if !b.mitmEnabled {
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(time.Now().Add(connectHandshakeTimeout))
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

			cert, err := b.requestLeafCert(handshakeCtx, serverName)
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

	b.serveMITMConn(tlsConn, serverName, 443)
}

func (b *bridge) serveHTTPForward(w http.ResponseWriter, req *http.Request, rewrite func(*http.Request) (*http.Request, error)) {
	outReq, err := rewrite(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var body []byte
	if outReq.Body != nil {
		var tooLarge bool
		body, tooLarge, err = bridgepkg.ReadBoundedBody(outReq.Body, b.maxRequestBodyBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if tooLarge {
			http.Error(w, "request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
			return
		}
	}

	response, err := b.proxyRoundTrip(req.Context(), helperproto.ProxyRequest{
		Method: outReq.Method,
		URL:    outReq.URL.String(),
		Header: outReq.Header.Clone(),
		Body:   body,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, bytes.NewReader(response.Body)); err != nil {
		b.logger.Printf("copy proxied response body: %v", err)
	}
}

func (b *bridge) handleMITMConnect(w http.ResponseWriter, req *http.Request) {
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
		b.writeConnectError(conn, http.StatusBadGateway, fmt.Sprintf("read buffered connect payload: %v", err))
		return
	}

	_ = conn.SetDeadline(time.Now().Add(connectHandshakeTimeout))
	connectCtx, cancelConnect := context.WithTimeout(req.Context(), connectHandshakeTimeout)
	defer cancelConnect()

	response, err := b.authorizeConnect(connectCtx, host, port)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		b.writeConnectError(conn, connectErrorStatus(err), err.Error())
		return
	}
	if response == nil {
		_ = conn.SetDeadline(time.Time{})
		b.writeConnectError(conn, http.StatusBadGateway, "empty connect response")
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
		b.writeConnectError(conn, statusCode, message)
		return
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}

	leafCert, err := b.requestLeafCert(connectCtx, host)
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

	b.serveMITMConn(tlsConn, host, port)
}

type tunnelRelayResult struct {
	sendClose bool
	write     bool
	err       error
	terminal  bool
}

func (b *bridge) handleConnect(w http.ResponseWriter, req *http.Request) {
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
		b.writeConnectError(conn, http.StatusBadGateway, fmt.Sprintf("read buffered connect payload: %v", err))
		return
	}

	_ = conn.SetDeadline(time.Now().Add(connectHandshakeTimeout))
	connectCtx, cancelConnect := context.WithTimeout(req.Context(), connectHandshakeTimeout)
	defer cancelConnect()

	id, tunnelCh, response, err := b.connect(connectCtx, host, port)
	if err != nil {
		_ = conn.SetDeadline(time.Time{})
		b.unregisterTunnel(id)
		b.writeConnectError(conn, connectErrorStatus(err), err.Error())
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
		b.unregisterTunnel(id)
		b.writeConnectError(conn, statusCode, message)
		return
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		if sendErr := b.sendTunnelClose(id, false, err); sendErr != nil {
			b.logger.Printf("send tunnel close: %v", sendErr)
		}
		b.unregisterTunnel(id)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	tunnelCtx, cancelTunnel := context.WithCancel(req.Context())

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			cancelTunnel()
			_ = conn.Close()
		})
	}
	cleanup := func(result tunnelRelayResult) {
		if result.sendClose {
			if err := b.sendTunnelClose(id, result.write, result.err); err != nil {
				b.logger.Printf("send tunnel close: %v", err)
			}
		}
		if !result.terminal {
			return
		}
		shutdown()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		cleanup(b.relayPayloadToTunnel(conn, id, bufferedPayload))
	}()

	go func() {
		defer wg.Done()
		cleanup(b.relayTunnelToPayload(tunnelCtx, conn, tunnelCh))
	}()

	wg.Wait()
	shutdown()
	b.unregisterTunnel(id)
}

func (b *bridge) proxyRoundTrip(ctx context.Context, req helperproto.ProxyRequest) (*helperproto.ProxyResponse, error) {
	return b.runtimeBridge.ProxyRoundTrip(ctx, req)
}

func (b *bridge) connect(ctx context.Context, host string, port int) (uint64, <-chan helperproto.Envelope, *helperproto.ConnectResponse, error) {
	return b.runtimeBridge.Connect(ctx, host, port)
}

func (b *bridge) authorizeConnect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error) {
	return b.runtimeBridge.AuthorizeConnect(ctx, host, port)
}

func (b *bridge) requestLeafCert(ctx context.Context, host string) (tls.Certificate, error) {
	response, err := b.runtimeBridge.RequestLeafCert(ctx, host)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(response.CertPEM, response.KeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate key pair: %w", err)
	}
	return cert, nil
}

func (b *bridge) mitmRoundTrip(ctx context.Context, req helperproto.MITMRequest) (*helperproto.MITMResponse, error) {
	return b.runtimeBridge.MITMRoundTrip(ctx, req)
}

func (b *bridge) registerTunnel(id uint64) <-chan helperproto.Envelope {
	return b.runtimeBridge.RegisterTunnel(id)
}

func (b *bridge) unregisterTunnel(id uint64) {
	b.runtimeBridge.UnregisterTunnel(id)
}

func (b *bridge) deliverTunnel(env helperproto.Envelope) {
	b.runtimeBridge.DeliverTunnel(env)
}

func (b *bridge) sendTunnelClose(id uint64, write bool, tunnelErr error) error {
	return b.runtimeBridge.SendTunnelClose(id, write, tunnelErr)
}

func (b *bridge) relayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) tunnelRelayResult {
	return tunnelRelayResultFromBridge(b.runtimeBridge.RelayPayloadToTunnel(conn, id, bufferedPayload))
}

func drainHijackBufferedBytes(rw *bufio.ReadWriter) ([]byte, error) {
	if rw == nil || rw.Reader == nil {
		return nil, nil
	}
	n := rw.Reader.Buffered()
	if n == 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(rw.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *bridge) relayTunnelToPayload(ctx context.Context, conn net.Conn, tunnelCh <-chan helperproto.Envelope) tunnelRelayResult {
	return tunnelRelayResultFromBridge(b.runtimeBridge.RelayTunnelToPayload(ctx, conn, tunnelCh))
}

func tunnelRelayResultFromBridge(result bridgepkg.TunnelRelayResult) tunnelRelayResult {
	return tunnelRelayResult{
		sendClose: result.SendClose,
		write:     result.Write,
		err:       result.Err,
		terminal:  result.Terminal,
	}
}

func (b *bridge) writeConnectError(conn net.Conn, statusCode int, message string) {
	if statusCode < 400 || statusCode > 599 {
		statusCode = http.StatusBadGateway
	}
	message = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(message, "\r", " "), "\n", " "))
	if message == "" {
		message = http.StatusText(statusCode)
	}
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Error"
	}
	body := message + "\n"
	if _, err := io.WriteString(conn, fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", statusCode, statusText, len(body), body)); err != nil {
		b.logger.Printf("write connect error response: %v", err)
	}
	_ = conn.Close()
}

func connectErrorStatus(err error) int {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

func (b *bridge) mitmHandler(connectHost string, connectPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, tooLarge, err := bridgepkg.ReadBoundedBody(req.Body, b.maxRequestBodyBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		host := req.Host
		if host == "" {
			host = connectHost
		}
		response, err := b.mitmRoundTrip(req.Context(), helperproto.MITMRequest{
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
			b.logger.Printf("copy MITM response body: %v", err)
		}
	})
}

func (b *bridge) serveMITMConn(conn net.Conn, connectHost string, connectPort int) {
	server := &http.Server{
		Handler: b.mitmHandler(connectHost, connectPort),
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		b.logger.Printf("configure MITM HTTP/2 server: %v", err)
	}
	serveErr := server.Serve(&singleConnListener{conn: conn})
	if serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, net.ErrClosed) {
		b.logger.Printf("serve MITM connection: %v", serveErr)
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

func (b *bridge) handleExec(ctx context.Context, id uint64, req helperproto.ExecRequest) {
	b.execMu.Lock()
	defer b.execMu.Unlock()

	if len(req.Argv) == 0 {
		_ = b.send(helperproto.Envelope{
			ID: id,
			ExecResult: &helperproto.ExecResult{
				ExitCode: -1,
				Stderr:   []byte("argv is required"),
				Error:    "argv is required",
			},
		})
		return
	}

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Env = append([]string(nil), req.Env...)
	cmd.Dir = req.WorkDir

	session, streams, err := b.startExecSession(cmd, req)
	if err != nil {
		b.sendExecError(id, err)
		return
	}
	b.setCurrentExec(session)
	defer b.clearCurrentExec()

	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream execOutputStream) {
			defer wg.Done()
			b.streamOutput(id, stream.stream, stream.reader)
		}(stream)
	}

	waitErr := cmd.Wait()
	wg.Wait()
	if session != nil && session.ptyFile != nil {
		_ = session.ptyFile.Close()
	}

	result := &helperproto.ExecResult{}
	if waitErr == nil {
		result.ExitCode = 0
	} else {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Stderr = []byte(waitErr.Error())
			result.Error = waitErr.Error()
		}
	}

	if err := b.send(helperproto.Envelope{
		ID:         id,
		ExecResult: result,
	}); err != nil {
		b.logger.Printf("send exec result: %v", err)
	}
}

type execOutputStream struct {
	stream helperproto.StreamType
	reader io.Reader
}

func (b *bridge) startExecSession(cmd *exec.Cmd, req helperproto.ExecRequest) (*execSession, []execOutputStream, error) {
	if req.Interactive && req.Terminal {
		size := &pty.Winsize{Rows: 24, Cols: 80}
		if req.InitialSize != nil {
			if req.InitialSize.Rows > 0 {
				size.Rows = req.InitialSize.Rows
			}
			if req.InitialSize.Cols > 0 {
				size.Cols = req.InitialSize.Cols
			}
		}
		ptmx, err := pty.StartWithSize(cmd, size)
		if err != nil {
			return nil, nil, err
		}
		return &execSession{
				stdin:    ptmx,
				ptyFile:  ptmx,
				terminal: true,
			}, []execOutputStream{{
				stream: helperproto.StreamStdout,
				reader: ptmx,
			}}, nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	var session *execSession
	if req.Interactive {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, nil, err
		}
		session = &execSession{stdin: stdin}
	}

	if err := cmd.Start(); err != nil {
		if session != nil && session.stdin != nil {
			_ = session.stdin.Close()
		}
		return nil, nil, err
	}

	return session, []execOutputStream{
		{stream: helperproto.StreamStdout, reader: stdout},
		{stream: helperproto.StreamStderr, reader: stderr},
	}, nil
}

func (b *bridge) sendExecError(id uint64, err error) {
	if sendErr := b.send(helperproto.Envelope{
		ID: id,
		ExecResult: &helperproto.ExecResult{
			ExitCode: -1,
			Stderr:   []byte(err.Error()),
			Error:    err.Error(),
		},
	}); sendErr != nil {
		b.logger.Printf("send exec error: %v", sendErr)
	}
}

func (b *bridge) streamOutput(id uint64, stream helperproto.StreamType, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if sendErr := b.send(helperproto.Envelope{
				ID: id,
				StreamFrame: &helperproto.StreamFrame{
					Stream: stream,
					Data:   append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				b.logger.Printf("send %s frame: %v", stream, sendErr)
				return
			}
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if errors.Is(err, syscall.EIO) {
			return
		}
		if err != nil {
			b.logger.Printf("read %s stream: %v", stream, err)
			return
		}
	}
}

func (b *bridge) handleExecInput(input helperproto.ExecInput) {
	b.execStateMu.Lock()
	session := b.currentExec
	b.execStateMu.Unlock()
	if session == nil {
		return
	}

	if input.Resize != nil && session.terminal && session.ptyFile != nil {
		if input.Resize.Rows > 0 || input.Resize.Cols > 0 {
			_ = pty.Setsize(session.ptyFile, &pty.Winsize{
				Rows: maxUint16(input.Resize.Rows, 24),
				Cols: maxUint16(input.Resize.Cols, 80),
			})
		}
	}

	if len(input.Data) > 0 && session.stdin != nil {
		if _, err := session.stdin.Write(input.Data); err != nil {
			return
		}
	}
	if input.EOF && session.stdin != nil && !session.terminal {
		_ = session.stdin.Close()
	}
}

func (b *bridge) setCurrentExec(session *execSession) {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	b.currentExec = session
}

func (b *bridge) clearCurrentExec() {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	b.currentExec = nil
}

func maxUint16(value, fallback uint16) uint16 {
	if value == 0 {
		return fallback
	}
	return value
}

func (b *bridge) send(env helperproto.Envelope) error {
	return b.runtimeBridge.Send(env)
}

func rewriteProxyRequest(req *http.Request) (*http.Request, error) {
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return nil, errors.New("proxy request must use an absolute URL")
	}

	out := req.Clone(req.Context())
	urlCopy := *req.URL
	out.URL = &urlCopy
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	out.Header.Del("Proxy-Connection")

	return out, nil
}

func rewriteTransparentHTTPRequest(req *http.Request) (*http.Request, error) {
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

func parseConnectTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, errors.New("malformed CONNECT target: host is required")
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("malformed CONNECT target %q", target)
	}
	if host == "" {
		return "", 0, errors.New("malformed CONNECT target: host is required")
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("malformed CONNECT target %q", target)
	}

	return host, port, nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
