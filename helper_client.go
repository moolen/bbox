package bbox

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
)

type helperClient struct {
	sandboxID string
	manager   *ProxyManager
	conn      io.ReadWriteCloser
	enc       *gob.Encoder
	dec       *gob.Decoder
	ctx       context.Context
	cancel    context.CancelFunc

	sendMu sync.Mutex

	readyCh   chan helperReady
	readyOnce sync.Once
	loopDone  chan error
	nextID    atomic.Uint64

	execMu     sync.Mutex
	currentMu  sync.Mutex
	currentRun *runState

	tunnelMu       sync.Mutex
	tunnels        map[uint64]*hostTunnel
	pendingTunnels map[uint64]*hostTunnel

	closeOnce sync.Once
}

type helperReady struct {
	proxyAddr string
	dnsAddr   string
	httpAddr  string
	httpsAddr string
	err       error
}

type runState struct {
	stdout       bytes.Buffer
	stderr       bytes.Buffer
	stdoutWriter io.Writer
	stderrWriter io.Writer
	resultCh     chan runOutcome
}

type runOutcome struct {
	result *RunResult
	err    error
}

func newHelperClient(manager *ProxyManager, sandboxID string, conn io.ReadWriteCloser) *helperClient {
	clientCtx, cancel := context.WithCancel(context.Background())
	return &helperClient{
		sandboxID:      sandboxID,
		manager:        manager,
		conn:           conn,
		enc:            gob.NewEncoder(conn),
		dec:            gob.NewDecoder(conn),
		ctx:            clientCtx,
		cancel:         cancel,
		readyCh:        make(chan helperReady, 1),
		loopDone:       make(chan error, 1),
		tunnels:        make(map[uint64]*hostTunnel),
		pendingTunnels: make(map[uint64]*hostTunnel),
	}
}

func (c *helperClient) Start(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		c.loopDone <- c.readLoop()
	}()

	if err := c.send(helperproto.Envelope{
		ID: c.nextID.Add(1),
		Hello: &helperproto.Hello{
			ProtocolVersion: helperproto.ProtocolVersion,
			SandboxID:       c.sandboxID,
		},
	}); err != nil {
		return "", fmt.Errorf("send helper hello: %w", err)
	}

	select {
	case ready := <-c.readyCh:
		if ready.err != nil {
			return "", ready.err
		}
		if ready.proxyAddr != "" {
			return ready.proxyAddr, nil
		}
		if ready.hasTransparentListeners() {
			return "", nil
		}
		return "", errors.New("helper did not report proxy or transparent listener readiness")
	case err := <-c.loopDone:
		if err == nil {
			return "", errors.New("helper exited before signaling readiness")
		}
		return "", fmt.Errorf("wait for helper readiness: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *helperClient) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.execMu.Lock()
	defer c.execMu.Unlock()

	state := &runState{
		stdoutWriter: opts.Stdout,
		stderrWriter: opts.Stderr,
		resultCh:     make(chan runOutcome, 1),
	}

	c.currentMu.Lock()
	if c.currentRun != nil {
		c.currentMu.Unlock()
		return nil, errors.New("another command is already running")
	}
	c.currentRun = state
	c.currentMu.Unlock()

	interactive := opts.Interactive || opts.Stdin != nil || opts.Stdout != nil || opts.Stderr != nil || opts.Terminal || opts.Resize != nil

	var initialSize *helperproto.TerminalSize
	if opts.TerminalSize.Rows > 0 || opts.TerminalSize.Cols > 0 {
		initialSize = &helperproto.TerminalSize{
			Rows: opts.TerminalSize.Rows,
			Cols: opts.TerminalSize.Cols,
		}
	}

	env := helperproto.Envelope{
		ID: c.nextID.Add(1),
		ExecRequest: &helperproto.ExecRequest{
			Argv:        append([]string(nil), argv...),
			Env:         append([]string(nil), opts.Env...),
			WorkDir:     opts.WorkDir,
			Interactive: interactive,
			Terminal:    opts.Terminal,
			InitialSize: initialSize,
		},
	}
	if err := c.send(env); err != nil {
		runErr := fmt.Errorf("send exec request: %w", err)
		c.failCurrentRun(runErr)
		return nil, runErr
	}

	if interactive {
		if opts.Stdin != nil {
			go c.pumpRunInput(env.ID, opts.Stdin)
		}
		if opts.Resize != nil {
			go c.pumpRunResize(env.ID, opts.Resize)
		}
	}

	select {
	case outcome := <-state.resultCh:
		return outcome.result, outcome.err
	case err := <-c.loopDone:
		if err == nil {
			err = errors.New("helper bridge closed")
		}
		c.finishRun(state, nil, err)
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *helperClient) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		c.cancel()
		c.shutdownTunnels()
		closeErr = c.conn.Close()
		select {
		case err := <-c.loopDone:
			if normalized := normalizeLoopCloseError(err); normalized != nil {
				closeErr = errors.Join(closeErr, normalized)
			}
		default:
		}
	})

	return closeErr
}

func (c *helperClient) readLoop() error {
	defer c.cancel()

	for {
		var env helperproto.Envelope
		if err := c.dec.Decode(&env); err != nil {
			c.notifyReady(helperReady{err: err})
			c.failCurrentRun(err)
			c.shutdownTunnels()
			return err
		}

		switch {
		case env.Ready != nil:
			if env.Ready.ProtocolVersion != helperproto.ProtocolVersion {
				err := fmt.Errorf("unexpected helper protocol version %d", env.Ready.ProtocolVersion)
				c.notifyReady(helperReady{err: err})
				c.failCurrentRun(err)
				return err
			}
			c.notifyReady(helperReady{
				proxyAddr: env.Ready.ProxyAddr,
				dnsAddr:   env.Ready.DNSAddr,
				httpAddr:  env.Ready.HTTPAddr,
				httpsAddr: env.Ready.HTTPSAddr,
			})
		case env.ProxyRequest != nil:
			req := *env.ProxyRequest
			go c.handleProxyRequest(env.ID, req)
		case env.ConnectRequest != nil:
			req := *env.ConnectRequest
			go c.handleConnectRequest(env.ID, req)
		case env.LeafCertRequest != nil:
			req := *env.LeafCertRequest
			go c.handleLeafCertRequest(env.ID, req)
		case env.MITMRequest != nil:
			req := *env.MITMRequest
			go c.handleMITMRequest(env.ID, req)
		case env.TunnelFrame != nil:
			c.handleTunnelFrame(env.ID, *env.TunnelFrame)
		case env.TunnelClose != nil:
			c.handleTunnelClose(env.ID, *env.TunnelClose)
		case env.StreamFrame != nil:
			c.handleStream(*env.StreamFrame)
		case env.ExecResult != nil:
			c.handleExecResult(*env.ExecResult)
		}
	}
}

func (r helperReady) hasTransparentListeners() bool {
	return r.dnsAddr != "" && r.httpAddr != "" && r.httpsAddr != ""
}

func (c *helperClient) notifyReady(ready helperReady) {
	c.readyOnce.Do(func() {
		c.readyCh <- ready
	})
}

func (c *helperClient) handleProxyRequest(id uint64, req helperproto.ProxyRequest) {
	response := c.manager.handleProxyRequest(c.ctx, c.sandboxID, req)
	if err := c.send(helperproto.Envelope{
		ID:            id,
		ProxyResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) handleConnectRequest(id uint64, req helperproto.ConnectRequest) {
	response := c.manager.handleConnectRequest(c.ctx, c.sandboxID, req)
	if response == nil {
		response = &helperproto.ConnectResponse{
			StatusCode: http.StatusBadGateway,
			Error:      "connect request rejected: empty response",
		}
	}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusBadGateway
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = c.send(helperproto.Envelope{
			ID:              id,
			ConnectResponse: response,
		})
		return
	}

	conn, err := c.manager.dialTunnel(c.ctx, req.Host, req.Port)
	if err != nil {
		_ = c.send(helperproto.Envelope{
			ID: id,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusBadGateway,
				Error:      err.Error(),
			},
		})
		return
	}

	tunnel := newHostTunnel(c, id, conn)
	c.registerPendingTunnel(id, tunnel)

	if err := c.send(helperproto.Envelope{
		ID:              id,
		ConnectResponse: response,
	}); err != nil {
		c.unregisterTunnel(id)
		tunnel.shutdown()
		return
	}

	if !c.activateTunnel(id) {
		tunnel.shutdown()
		return
	}
	tunnel.start()
}

func (c *helperClient) handleLeafCertRequest(id uint64, req helperproto.LeafCertRequest) {
	response := c.manager.handleLeafCertRequest(req.Host)
	if response == nil {
		response = &helperproto.LeafCertResponse{
			Error: "leaf cert request rejected: empty response",
		}
	}

	if err := c.send(helperproto.Envelope{
		ID:               id,
		LeafCertResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) handleMITMRequest(id uint64, req helperproto.MITMRequest) {
	response := c.manager.handleMITMRequest(c.ctx, c.sandboxID, req)
	if response == nil {
		response = &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      "MITM request rejected: empty response",
		}
	}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusBadGateway
	}
	if err := c.send(helperproto.Envelope{
		ID:           id,
		MITMResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *helperClient) registerPendingTunnel(id uint64, tunnel *hostTunnel) {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	if c.pendingTunnels == nil {
		c.pendingTunnels = make(map[uint64]*hostTunnel)
	}
	c.pendingTunnels[id] = tunnel
}

func (c *helperClient) activateTunnel(id uint64) bool {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.pendingTunnels[id]
	if tunnel == nil {
		return false
	}
	delete(c.pendingTunnels, id)
	if c.tunnels == nil {
		c.tunnels = make(map[uint64]*hostTunnel)
	}
	c.tunnels[id] = tunnel
	return true
}

func (c *helperClient) unregisterTunnel(id uint64) *hostTunnel {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.tunnels[id]
	delete(c.tunnels, id)
	if tunnel == nil {
		tunnel = c.pendingTunnels[id]
	}
	delete(c.pendingTunnels, id)
	return tunnel
}

func (c *helperClient) tunnel(id uint64) *hostTunnel {
	c.tunnelMu.Lock()
	defer c.tunnelMu.Unlock()
	tunnel := c.tunnels[id]
	if tunnel != nil {
		return tunnel
	}
	return c.pendingTunnels[id]
}

func (c *helperClient) handleTunnelFrame(id uint64, frame helperproto.TunnelFrame) {
	tunnel := c.tunnel(id)
	if tunnel == nil {
		return
	}
	tunnel.deliver(helperproto.Envelope{
		ID:          id,
		TunnelFrame: &helperproto.TunnelFrame{Data: append([]byte(nil), frame.Data...)},
	})
}

func (c *helperClient) handleTunnelClose(id uint64, closeMsg helperproto.TunnelClose) {
	tunnel := c.tunnel(id)
	if tunnel == nil {
		return
	}
	tunnel.deliver(helperproto.Envelope{
		ID:          id,
		TunnelClose: &helperproto.TunnelClose{Write: closeMsg.Write, Error: closeMsg.Error},
	})
}

func (c *helperClient) shutdownTunnels() {
	c.tunnelMu.Lock()
	tunnels := make([]*hostTunnel, 0, len(c.tunnels)+len(c.pendingTunnels))
	for _, tunnel := range c.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	for _, tunnel := range c.pendingTunnels {
		tunnels = append(tunnels, tunnel)
	}
	c.tunnels = make(map[uint64]*hostTunnel)
	c.pendingTunnels = make(map[uint64]*hostTunnel)
	c.tunnelMu.Unlock()

	for _, tunnel := range tunnels {
		tunnel.shutdown()
	}
}

func (c *helperClient) handleStream(frame helperproto.StreamFrame) {
	c.currentMu.Lock()
	state := c.currentRun
	c.currentMu.Unlock()

	if state == nil {
		return
	}

	switch frame.Stream {
	case helperproto.StreamStdout:
		_, _ = state.stdout.Write(frame.Data)
		if state.stdoutWriter != nil {
			_, _ = state.stdoutWriter.Write(frame.Data)
		}
	case helperproto.StreamStderr:
		_, _ = state.stderr.Write(frame.Data)
		if state.stderrWriter != nil {
			_, _ = state.stderrWriter.Write(frame.Data)
		}
	}
}

func (c *helperClient) handleExecResult(result helperproto.ExecResult) {
	c.currentMu.Lock()
	state := c.currentRun
	c.currentRun = nil
	c.currentMu.Unlock()

	if state == nil {
		return
	}

	stderr := append([]byte(nil), state.stderr.Bytes()...)
	if len(result.Stderr) > 0 {
		stderr = append(stderr, result.Stderr...)
		if state.stderrWriter != nil {
			_, _ = state.stderrWriter.Write(result.Stderr)
		}
	}

	state.resultCh <- runOutcome{
		result: &RunResult{
			ExitCode: result.ExitCode,
			Stdout:   append([]byte(nil), state.stdout.Bytes()...),
			Stderr:   stderr,
		},
		err: execResultError(result),
	}
}

func (c *helperClient) failCurrentRun(err error) {
	c.currentMu.Lock()
	state := c.currentRun
	c.currentRun = nil
	c.currentMu.Unlock()

	if state == nil {
		return
	}

	c.finishRun(state, nil, err)
}

func (c *helperClient) finishRun(state *runState, result *RunResult, err error) {
	if state == nil {
		return
	}

	select {
	case state.resultCh <- runOutcome{result: result, err: err}:
	default:
	}
}

func normalizeLoopCloseError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func execResultError(result helperproto.ExecResult) error {
	if result.Error == "" {
		return nil
	}
	return errors.New(result.Error)
}

func (c *helperClient) pumpRunInput(id uint64, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if sendErr := c.send(helperproto.Envelope{
				ID: id,
				ExecInput: &helperproto.ExecInput{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			_ = c.send(helperproto.Envelope{
				ID: id,
				ExecInput: &helperproto.ExecInput{
					EOF: true,
				},
			})
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *helperClient) pumpRunResize(id uint64, sizes <-chan TerminalSize) {
	for size := range sizes {
		if size.Rows == 0 && size.Cols == 0 {
			continue
		}
		if err := c.send(helperproto.Envelope{
			ID: id,
			ExecInput: &helperproto.ExecInput{
				Resize: &helperproto.TerminalSize{
					Rows: size.Rows,
					Cols: size.Cols,
				},
			},
		}); err != nil {
			return
		}
	}
}

func (c *helperClient) send(env helperproto.Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.enc.Encode(&env)
}

type hostTunnel struct {
	client *helperClient
	id     uint64
	conn   net.Conn

	recvCh chan helperproto.Envelope
	closed chan struct{}

	closeOnce sync.Once

	sendWriteCloseOnce    sync.Once
	sendTerminalCloseOnce sync.Once
}

func newHostTunnel(client *helperClient, id uint64, conn net.Conn) *hostTunnel {
	return &hostTunnel{
		client: client,
		id:     id,
		conn:   conn,
		recvCh: make(chan helperproto.Envelope, 64),
		closed: make(chan struct{}),
	}
}

func (t *hostTunnel) start() {
	go t.relayOutboundToTunnel()
	go t.relayTunnelToOutbound()
}

func (t *hostTunnel) deliver(env helperproto.Envelope) {
	select {
	case <-t.closed:
		return
	default:
	}

	select {
	case t.recvCh <- env:
	case <-t.closed:
	default:
		// Backpressure: fail closed rather than wedging the helper client read loop forever.
		t.sendTerminalCloseAsync(errors.New("tunnel receive buffer overflow"))
		t.closeTerminal()
	}
}

func (t *hostTunnel) shutdown() {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.conn.Close()
	})
}

func (t *hostTunnel) sendWriteClose(err error) {
	t.sendWriteCloseOnce.Do(func() {
		_ = t.client.send(helperproto.Envelope{
			ID: t.id,
			TunnelClose: &helperproto.TunnelClose{
				Write: true,
				Error: normalizeTunnelError(err),
			},
		})
	})
}

func (t *hostTunnel) sendTerminalClose(err error) {
	t.sendTerminalCloseOnce.Do(func() {
		_ = t.client.send(helperproto.Envelope{
			ID: t.id,
			TunnelClose: &helperproto.TunnelClose{
				Write: false,
				Error: normalizeTunnelError(err),
			},
		})
	})
}

func (t *hostTunnel) sendTerminalCloseAsync(err error) {
	go t.sendTerminalClose(err)
}

func (t *hostTunnel) relayOutboundToTunnel() {
	buf := make([]byte, 32*1024)
	for {
		_ = t.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := t.conn.Read(buf)
		if n > 0 {
			if sendErr := t.client.send(helperproto.Envelope{
				ID: t.id,
				TunnelFrame: &helperproto.TunnelFrame{
					Data: append([]byte(nil), buf[:n]...),
				},
			}); sendErr != nil {
				t.sendTerminalClose(sendErr)
				t.closeTerminal()
				return
			}
		}

		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.sendWriteClose(nil)
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			continue
		}
		t.sendTerminalClose(err)
		t.closeTerminal()
		return
	}
}

func (t *hostTunnel) relayTunnelToOutbound() {
	defer func() {
		t.closeTerminal()
	}()

	for {
		select {
		case <-t.closed:
			return
		case env, ok := <-t.recvCh:
			if !ok {
				return
			}
			switch {
			case env.TunnelFrame != nil:
				if len(env.TunnelFrame.Data) == 0 {
					continue
				}
				_ = t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if err := writeAll(t.conn, env.TunnelFrame.Data); err != nil {
					t.sendTerminalClose(err)
					return
				}
			case env.TunnelClose != nil:
				if env.TunnelClose.Write {
					if err := closeTunnelWrite(t.conn); err != nil {
						t.sendTerminalClose(err)
						return
					}
					continue
				}
				// Terminal close from the helper.
				return
			default:
			}
		}
	}
}

func (t *hostTunnel) closeTerminal() {
	t.client.unregisterTunnel(t.id)
	t.shutdown()
}

func normalizeTunnelError(err error) string {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return ""
	}
	return err.Error()
}

func closeTunnelWrite(conn net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return conn.Close()
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
