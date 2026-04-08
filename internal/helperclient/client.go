package helperclient

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/moolen/bbox/internal/helperproto"
)

type Host interface {
	HandleProxyRequest(context.Context, string, helperproto.ProxyRequest) *helperproto.ProxyResponse
	HandleConnectRequest(context.Context, string, helperproto.ConnectRequest) *helperproto.ConnectResponse
	HandleDNSRequest(context.Context, string, helperproto.DNSRequest) *helperproto.DNSResponse
	HandleLeafCertRequest(string) *helperproto.LeafCertResponse
	HandleMITMRequest(context.Context, string, helperproto.MITMRequest) *helperproto.MITMResponse
	DialTunnel(context.Context, string, int) (net.Conn, error)
}

type Client struct {
	sandboxID string
	host      Host
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
	currentRun *runSession

	tunnelMu       sync.Mutex
	tunnels        map[uint64]*hostTunnel
	pendingTunnels map[uint64]*hostTunnel

	closeOnce sync.Once
}

type helperReady struct {
	proxyAddr string
	dnsAddr   string
	tcpAddr   string
	err       error
}

func (r helperReady) hasTransparentListeners() bool {
	return r.tcpAddr != ""
}

func New(host Host, sandboxID string, conn io.ReadWriteCloser) *Client {
	clientCtx, cancel := context.WithCancel(context.Background())
	return &Client{
		sandboxID:      sandboxID,
		host:           host,
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

func (c *Client) Context() context.Context {
	if c == nil {
		return nil
	}
	return c.ctx
}

func (c *Client) LoopDone() chan error {
	if c == nil {
		return nil
	}
	return c.loopDone
}

func (c *Client) Start(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	go func() {
		c.loopDone <- c.ReadLoop()
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

func (c *Client) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.execMu.Lock()
	defer c.execMu.Unlock()

	state := newRunSession(opts.Stdout, opts.Stderr)
	if err := c.installRunSession(state); err != nil {
		return nil, err
	}

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
		state.Finish(nil, err)
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) Close() error {
	var closeErr error

	c.closeOnce.Do(func() {
		c.cancel()
		c.ShutdownTunnels()
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

func (c *Client) ReadLoop() error {
	defer c.cancel()

	for {
		var env helperproto.Envelope
		if err := c.dec.Decode(&env); err != nil {
			c.notifyReady(helperReady{err: err})
			c.failCurrentRun(err)
			c.ShutdownTunnels()
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
				tcpAddr:   env.Ready.TCPAddr,
			})
		case env.ProxyRequest != nil:
			req := *env.ProxyRequest
			go c.HandleProxyRequest(env.ID, req)
		case env.ConnectRequest != nil:
			req := *env.ConnectRequest
			go c.HandleConnectRequest(env.ID, req)
		case env.DNSRequest != nil:
			req := *env.DNSRequest
			go c.HandleDNSRequest(env.ID, req)
		case env.LeafCertRequest != nil:
			req := *env.LeafCertRequest
			go c.HandleLeafCertRequest(env.ID, req)
		case env.MITMRequest != nil:
			req := *env.MITMRequest
			go c.HandleMITMRequest(env.ID, req)
		case env.TunnelFrame != nil:
			c.HandleTunnelFrame(env.ID, *env.TunnelFrame)
		case env.TunnelClose != nil:
			c.HandleTunnelClose(env.ID, *env.TunnelClose)
		case env.StreamFrame != nil:
			c.handleStream(*env.StreamFrame)
		case env.ExecResult != nil:
			c.handleExecResult(*env.ExecResult)
		}
	}
}

func (c *Client) notifyReady(ready helperReady) {
	c.readyOnce.Do(func() {
		c.readyCh <- ready
	})
}

func (c *Client) HandleProxyRequest(id uint64, req helperproto.ProxyRequest) {
	var response *helperproto.ProxyResponse
	if c.host != nil {
		response = c.host.HandleProxyRequest(c.ctx, c.sandboxID, req)
	}
	if response == nil {
		response = &helperproto.ProxyResponse{
			StatusCode: http.StatusBadGateway,
			Error:      "proxy request rejected: empty response",
		}
	}
	if response.StatusCode == 0 {
		response.StatusCode = http.StatusBadGateway
	}
	if err := c.send(helperproto.Envelope{
		ID:            id,
		ProxyResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *Client) HandleConnectRequest(id uint64, req helperproto.ConnectRequest) {
	var response *helperproto.ConnectResponse
	if c.host != nil {
		response = c.host.HandleConnectRequest(c.ctx, c.sandboxID, req)
	}
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

	if c.host == nil {
		_ = c.send(helperproto.Envelope{
			ID: id,
			ConnectResponse: &helperproto.ConnectResponse{
				StatusCode: http.StatusBadGateway,
				Error:      "connect request rejected: host bridge unavailable",
			},
		})
		return
	}

	conn, err := c.host.DialTunnel(c.ctx, req.Host, req.Port)
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

func (c *Client) HandleDNSRequest(id uint64, req helperproto.DNSRequest) {
	var response *helperproto.DNSResponse
	if c.host != nil {
		response = c.host.HandleDNSRequest(c.ctx, c.sandboxID, req)
	}
	if response == nil {
		response = &helperproto.DNSResponse{
			Error: "dns request rejected: empty response",
		}
	}
	if err := c.send(helperproto.Envelope{
		ID:          id,
		DNSResponse: response,
	}); err != nil {
		c.failCurrentRun(err)
	}
}

func (c *Client) HandleLeafCertRequest(id uint64, req helperproto.LeafCertRequest) {
	var response *helperproto.LeafCertResponse
	if c.host != nil {
		response = c.host.HandleLeafCertRequest(req.Host)
	}
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

func (c *Client) HandleMITMRequest(id uint64, req helperproto.MITMRequest) {
	var response *helperproto.MITMResponse
	if c.host != nil {
		response = c.host.HandleMITMRequest(c.ctx, c.sandboxID, req)
	}
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

func normalizeLoopCloseError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *Client) send(env helperproto.Envelope) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.enc.Encode(&env)
}
