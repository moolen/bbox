package helperruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

const DefaultProxyAddr = "127.0.0.1:31111"
const DefaultTransparentDNSAddr = "127.0.0.1:53"
const DefaultTransparentHTTPAddr = "127.0.0.1:80"
const DefaultTransparentHTTPSAddr = "127.0.0.1:443"

const connectHandshakeTimeout = 5 * time.Second

type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)

type Config struct {
	Bridge              io.ReadWriteCloser
	TrafficMode         TrafficMode
	ProxyAddr           string
	DNSAddr             string
	HTTPAddr            string
	HTTPSAddr           string
	Logger              *log.Logger
	MITMEnabled         bool
	MaxRequestBodyBytes int64
}

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
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	if cfg.TrafficMode == "" {
		cfg.TrafficMode = TrafficModeProxy
	}

	switch cfg.TrafficMode {
	case TrafficModeProxy:
		return runProxyMode(ctx, cfg)
	case TrafficModeTransparent:
		return runTransparentMode(ctx, cfg)
	default:
		return fmt.Errorf("unsupported traffic mode %q", cfg.TrafficMode)
	}
}

func runProxyMode(ctx context.Context, cfg Config) error {
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = DefaultProxyAddr
	}

	listener, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return fmt.Errorf("listen on proxy address %q: %w", cfg.ProxyAddr, err)
	}
	defer listener.Close()

	bridge := newBridge(cfg.Bridge, cfg.Logger, listener.Addr().String())
	bridge.mitmEnabled = cfg.MITMEnabled
	bridge.maxRequestBodyBytes = cfg.MaxRequestBodyBytes

	server := &http.Server{
		Handler: bridge.proxyHandler(),
	}

	errCh := make(chan error, 2)

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
		_ = cfg.Bridge.Close()
	}()

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("serve proxy listener: %w", err)
		}
	}()

	go func() {
		errCh <- bridge.readLoop(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func runTransparentMode(ctx context.Context, cfg Config) error {
	if cfg.DNSAddr == "" {
		cfg.DNSAddr = DefaultTransparentDNSAddr
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultTransparentHTTPAddr
	}
	if cfg.HTTPSAddr == "" {
		cfg.HTTPSAddr = DefaultTransparentHTTPSAddr
	}

	dnsServer, err := newTransparentDNSServer(cfg.DNSAddr)
	if err != nil {
		return fmt.Errorf("listen on DNS address %q: %w", cfg.DNSAddr, err)
	}
	defer dnsServer.Close()

	httpListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on HTTP address %q: %w", cfg.HTTPAddr, err)
	}
	defer httpListener.Close()

	httpsListener, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("listen on HTTPS address %q: %w", cfg.HTTPSAddr, err)
	}
	defer httpsListener.Close()

	bridge := newBridge(cfg.Bridge, cfg.Logger, "")
	bridge.mitmEnabled = cfg.MITMEnabled
	bridge.maxRequestBodyBytes = cfg.MaxRequestBodyBytes
	bridge.dnsAddr = dnsServer.Addr()
	bridge.httpAddr = httpListener.Addr().String()
	bridge.httpsAddr = httpsListener.Addr().String()

	errCh := make(chan error, 4)

	go func() {
		<-ctx.Done()

		_ = dnsServer.Close()
		_ = httpListener.Close()
		_ = httpsListener.Close()
		_ = cfg.Bridge.Close()
	}()

	go func() {
		errCh <- dnsServer.Serve()
	}()
	go func() {
		errCh <- serveTransparentListener(httpListener)
	}()
	go func() {
		errCh <- serveTransparentListener(httpsListener)
	}()
	go func() {
		errCh <- bridge.readLoop(ctx)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func serveTransparentListener(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		_ = conn.Close()
	}
}

type transparentDNSServer struct {
	tcpListener net.Listener
	udpConn     net.PacketConn
}

func newTransparentDNSServer(addr string) (*transparentDNSServer, error) {
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	udpAddr, err := transparentDNSUDPAddr(tcpListener.Addr())
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	udpConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	return &transparentDNSServer{
		tcpListener: tcpListener,
		udpConn:     udpConn,
	}, nil
}

func transparentDNSUDPAddr(addr net.Addr) (string, error) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", fmt.Errorf("split DNS listener address %q: %w", addr.String(), err)
	}

	return net.JoinHostPort(host, port), nil
}

func (s *transparentDNSServer) Addr() string {
	return s.tcpListener.Addr().String()
}

func (s *transparentDNSServer) Close() error {
	var errs []error
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *transparentDNSServer) Serve() error {
	errCh := make(chan error, 2)

	go func() {
		errCh <- serveTransparentDNSUDP(s.udpConn)
	}()
	go func() {
		errCh <- serveTransparentDNSTCP(s.tcpListener)
	}()

	err := <-errCh
	if err != nil {
		_ = s.Close()
	}

	return err
}

func serveTransparentDNSUDP(conn net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}

		response, ok := handleTransparentDNSQuery(buf[:n])
		if !ok {
			continue
		}
		if _, err := conn.WriteTo(response, addr); err != nil {
			return err
		}
	}
}

func serveTransparentDNSTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func() {
			_ = serveTransparentDNSTCPConn(conn)
		}()
	}
}

func serveTransparentDNSTCPConn(conn net.Conn) error {
	defer conn.Close()

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return err
	}

	queryLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	query := make([]byte, queryLen)
	if _, err := io.ReadFull(conn, query); err != nil {
		return err
	}

	response, ok := handleTransparentDNSQuery(query)
	if !ok {
		return nil
	}

	frame := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(response)))
	copy(frame[2:], response)
	_, err := conn.Write(frame)
	return err
}

func handleTransparentDNSQuery(payload []byte) ([]byte, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return nil, false
	}

	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, false
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 header.ID,
			Response:           true,
			OpCode:             header.OpCode,
			Authoritative:      true,
			RecursionDesired:   header.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: questions,
	}

	question := questions[0]
	if question.Class != dnsmessage.ClassINET {
		response.Header.RCode = dnsmessage.RCodeRefused
	} else {
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			}}
		case dnsmessage.TypeAAAA:
		default:
			response.Header.RCode = dnsmessage.RCodeRefused
		}
	}

	packed, err := response.Pack()
	if err != nil {
		return nil, false
	}

	return packed, true
}

type bridge struct {
	conn                io.ReadWriteCloser
	enc                 *gob.Encoder
	dec                 *gob.Decoder
	logger              *log.Logger
	proxyAddr           string
	dnsAddr             string
	httpAddr            string
	httpsAddr           string
	mitmEnabled         bool
	maxRequestBodyBytes int64
	sendMu              sync.Mutex
	pending             map[uint64]chan helperproto.Envelope
	pendMu              sync.Mutex
	tunnels             map[uint64]*tunnelDelivery
	tunnelMu            sync.Mutex
	nextID              atomic.Uint64
	execMu              sync.Mutex
}

type tunnelDelivery struct {
	ch     chan helperproto.Envelope
	closed chan struct{}
}

func newBridge(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *bridge {
	return &bridge{
		conn:      conn,
		enc:       gob.NewEncoder(conn),
		dec:       gob.NewDecoder(conn),
		logger:    logger,
		proxyAddr: proxyAddr,
		pending:   make(map[uint64]chan helperproto.Envelope),
		tunnels:   make(map[uint64]*tunnelDelivery),
	}
}

func (b *bridge) readLoop(ctx context.Context) error {
	for {
		var env helperproto.Envelope
		if err := b.dec.Decode(&env); err != nil {
			return err
		}

		switch {
		case env.Hello != nil:
			if err := b.handleHello(env); err != nil {
				return err
			}
		case env.ProxyResponse != nil, env.MITMResponse != nil, env.LeafCertResponse != nil:
			b.deliver(env)
		case env.ConnectResponse != nil:
			b.deliver(env)
		case env.TunnelFrame != nil, env.TunnelClose != nil:
			b.deliverTunnel(env)
		case env.ExecRequest != nil:
			go b.handleExec(ctx, env.ID, *env.ExecRequest)
		default:
			b.logger.Printf("ignoring unsupported helper envelope kind %q", env.Kind())
		}
	}
}

func (b *bridge) handleHello(env helperproto.Envelope) error {
	if env.Hello.ProtocolVersion != helperproto.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", env.Hello.ProtocolVersion)
	}

	return b.send(helperproto.Envelope{
		ID: env.ID,
		Ready: &helperproto.Ready{
			ProtocolVersion: helperproto.ProtocolVersion,
			ProxyAddr:       b.proxyAddr,
			DNSAddr:         b.dnsAddr,
			HTTPAddr:        b.httpAddr,
			HTTPSAddr:       b.httpsAddr,
		},
	})
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

		outReq, err := rewriteProxyRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var body []byte
		if outReq.Body != nil {
			body, err = io.ReadAll(outReq.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
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
	})
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

	server := &http.Server{
		Handler: b.mitmHandler(host, port),
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		b.logger.Printf("configure MITM HTTP/2 server: %v", err)
	}
	serveErr := server.Serve(&singleConnListener{conn: tlsConn})
	if serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, net.ErrClosed) {
		b.logger.Printf("serve MITM connection: %v", serveErr)
	}
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
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID:           id,
		ProxyRequest: &req,
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.ProxyResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a proxy response", id)
		}
		if env.ProxyResponse.Error != "" {
			return nil, errors.New(env.ProxyResponse.Error)
		}
		return env.ProxyResponse, nil
	}
}

func (b *bridge) connect(ctx context.Context, host string, port int) (uint64, chan helperproto.Envelope, *helperproto.ConnectResponse, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)
	tunnelCh := b.registerTunnel(id)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID: id,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: host,
			Port: port,
		},
	}); err != nil {
		b.unregisterTunnel(id)
		return id, nil, nil, err
	}

	select {
	case <-ctx.Done():
		b.unregisterTunnel(id)
		return id, nil, nil, ctx.Err()
	case env := <-ch:
		if env.ConnectResponse == nil {
			b.unregisterTunnel(id)
			return id, nil, nil, fmt.Errorf("bridge response %d did not contain a connect response", id)
		}
		return id, tunnelCh, env.ConnectResponse, nil
	}
}

func (b *bridge) authorizeConnect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID: id,
		ConnectRequest: &helperproto.ConnectRequest{
			Host: host,
			Port: port,
		},
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.ConnectResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a connect response", id)
		}
		return env.ConnectResponse, nil
	}
}

func (b *bridge) requestLeafCert(ctx context.Context, host string) (tls.Certificate, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID: id,
		LeafCertRequest: &helperproto.LeafCertRequest{
			Host: host,
		},
	}); err != nil {
		return tls.Certificate{}, err
	}

	select {
	case <-ctx.Done():
		return tls.Certificate{}, ctx.Err()
	case env := <-ch:
		if env.LeafCertResponse == nil {
			return tls.Certificate{}, fmt.Errorf("bridge response %d did not contain a leaf cert response", id)
		}
		if env.LeafCertResponse.Error != "" {
			return tls.Certificate{}, errors.New(env.LeafCertResponse.Error)
		}
		cert, err := tls.X509KeyPair(env.LeafCertResponse.CertPEM, env.LeafCertResponse.KeyPEM)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse leaf certificate key pair: %w", err)
		}
		return cert, nil
	}
}

func (b *bridge) mitmRoundTrip(ctx context.Context, req helperproto.MITMRequest) (*helperproto.MITMResponse, error) {
	id := b.nextID.Add(1)
	ch := make(chan helperproto.Envelope, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	defer func() {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
	}()

	if err := b.send(helperproto.Envelope{
		ID:          id,
		MITMRequest: &req,
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case env := <-ch:
		if env.MITMResponse == nil {
			return nil, fmt.Errorf("bridge response %d did not contain a MITM response", id)
		}
		if env.MITMResponse.Error != "" && env.MITMResponse.StatusCode == 0 {
			return nil, errors.New(env.MITMResponse.Error)
		}
		return env.MITMResponse, nil
	}
}

func (b *bridge) deliver(env helperproto.Envelope) {
	b.pendMu.Lock()
	ch := b.pending[env.ID]
	b.pendMu.Unlock()
	if ch == nil {
		b.logger.Printf("dropping bridge response for unknown request %d", env.ID)
		return
	}

	select {
	case ch <- env:
	default:
		b.logger.Printf("dropping duplicate bridge response for request %d", env.ID)
	}
}

func (b *bridge) registerTunnel(id uint64) chan helperproto.Envelope {
	delivery := &tunnelDelivery{
		ch:     make(chan helperproto.Envelope, 32),
		closed: make(chan struct{}),
	}
	b.tunnelMu.Lock()
	b.tunnels[id] = delivery
	b.tunnelMu.Unlock()
	return delivery.ch
}

func (b *bridge) unregisterTunnel(id uint64) {
	b.tunnelMu.Lock()
	delivery := b.tunnels[id]
	delete(b.tunnels, id)
	b.tunnelMu.Unlock()
	if delivery != nil {
		close(delivery.closed)
	}
}

func (b *bridge) deliverTunnel(env helperproto.Envelope) {
	b.tunnelMu.Lock()
	delivery := b.tunnels[env.ID]
	b.tunnelMu.Unlock()
	if delivery == nil {
		b.logger.Printf("dropping tunnel message for unknown request %d", env.ID)
		return
	}

	select {
	case delivery.ch <- env:
	case <-delivery.closed:
		b.logger.Printf("dropping tunnel message for closed request %d", env.ID)
	}
}

func (b *bridge) sendTunnelClose(id uint64, write bool, tunnelErr error) error {
	closeErr := ""
	if tunnelErr != nil && !errors.Is(tunnelErr, io.EOF) && !errors.Is(tunnelErr, net.ErrClosed) {
		closeErr = tunnelErr.Error()
	}
	return b.send(helperproto.Envelope{
		ID: id,
		TunnelClose: &helperproto.TunnelClose{
			Write: write,
			Error: closeErr,
		},
	})
}

func (b *bridge) relayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) tunnelRelayResult {
	if len(bufferedPayload) > 0 {
		if sendErr := b.send(helperproto.Envelope{
			ID: id,
			TunnelFrame: &helperproto.TunnelFrame{
				Data: append([]byte(nil), bufferedPayload...),
			},
		}); sendErr != nil {
			return tunnelRelayResult{sendClose: true, err: sendErr, terminal: true}
		}
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := b.send(helperproto.Envelope{
				ID: id,
				TunnelFrame: &helperproto.TunnelFrame{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				return tunnelRelayResult{sendClose: true, err: sendErr, terminal: true}
			}
		}

		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return tunnelRelayResult{sendClose: true, write: true}
		}
		if errors.Is(err, net.ErrClosed) {
			return tunnelRelayResult{}
		}
		return tunnelRelayResult{sendClose: true, err: err, terminal: true}
	}
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
	for {
		select {
		case <-ctx.Done():
			return tunnelRelayResult{}
		case env := <-tunnelCh:
			switch {
			case env.TunnelFrame != nil:
				if len(env.TunnelFrame.Data) == 0 {
					continue
				}
				if err := writeAll(conn, env.TunnelFrame.Data); err != nil {
					return tunnelRelayResult{sendClose: true, err: err, terminal: true}
				}
			case env.TunnelClose != nil:
				if env.TunnelClose.Write {
					if err := closePayloadWrite(conn); err != nil {
						return tunnelRelayResult{sendClose: true, err: err, terminal: true}
					}
					return tunnelRelayResult{}
				}
				return tunnelRelayResult{terminal: true}
			default:
				b.logger.Printf("ignoring unexpected tunnel envelope kind %q", env.Kind())
			}
		}
	}
}

func writeAll(dst net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
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
		body, tooLarge, err := readBoundedBody(req.Body, b.maxRequestBodyBytes)
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

func closePayloadWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return conn.Close()
}

func readBoundedBody(body io.ReadCloser, maxBytes int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()

	if maxBytes <= 0 {
		data, err := io.ReadAll(body)
		return data, false, err
	}

	limited, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(limited)) > maxBytes {
		return limited[:maxBytes], true, nil
	}
	return limited, false, nil
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

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.sendExecError(id, err)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.sendExecError(id, err)
		return
	}

	if err := cmd.Start(); err != nil {
		b.sendExecError(id, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b.streamOutput(id, helperproto.StreamStdout, stdout)
	}()

	go func() {
		defer wg.Done()
		b.streamOutput(id, helperproto.StreamStderr, stderr)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

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
		if err != nil {
			b.logger.Printf("read %s stream: %v", stream, err)
			return
		}
	}
}

func (b *bridge) send(env helperproto.Envelope) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	return b.enc.Encode(&env)
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
