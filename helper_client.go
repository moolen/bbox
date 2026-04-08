package bbox

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/moolen/bbox/internal/helperclient"
	"github.com/moolen/bbox/internal/helperproto"
)

type helperControl interface {
	Start(context.Context) (string, error)
	Run(context.Context, []string, RunOptions) (*RunResult, error)
	Close() error
}

type helperClient struct {
	client   *helperclient.Client
	ctx      context.Context
	conn     io.ReadWriteCloser
	loopDone chan error
}

func newHelperClient(manager *ProxyManager, sandboxID string, conn io.ReadWriteCloser) *helperClient {
	inner := helperclient.New(helperClientHost{manager: manager}, sandboxID, conn)
	return &helperClient{
		client:   inner,
		ctx:      inner.Context(),
		conn:     conn,
		loopDone: inner.LoopDone(),
	}
}

func (c *helperClient) Start(ctx context.Context) (string, error) {
	return c.client.Start(ctx)
}

func (c *helperClient) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if c == nil {
		return nil, errors.New("helper client is nil")
	}
	result, err := c.client.Run(ctx, argv, helperclient.RunOptions{
		Env:          append([]string(nil), opts.Env...),
		WorkDir:      opts.WorkDir,
		Interactive:  opts.Interactive,
		Stdin:        opts.Stdin,
		Stdout:       opts.Stdout,
		Stderr:       opts.Stderr,
		Terminal:     opts.Terminal,
		TerminalSize: helperclient.TerminalSize{Rows: opts.TerminalSize.Rows, Cols: opts.TerminalSize.Cols},
		Resize:       convertResizeChannel(ctx, opts.Resize),
	})
	if result == nil {
		return nil, err
	}
	return &RunResult{
		ExitCode: result.ExitCode,
		Stdout:   append([]byte(nil), result.Stdout...),
		Stderr:   append([]byte(nil), result.Stderr...),
	}, err
}

func (c *helperClient) Close() error {
	if c == nil {
		return nil
	}
	return c.client.Close()
}

func (c *helperClient) readLoop() error {
	return c.client.ReadLoop()
}

func (c *helperClient) handleConnectRequest(id uint64, req helperproto.ConnectRequest) {
	c.client.HandleConnectRequest(id, req)
}

func (c *helperClient) handleTunnelFrame(id uint64, frame helperproto.TunnelFrame) {
	c.client.HandleTunnelFrame(id, frame)
}

func (c *helperClient) shutdownTunnels() {
	c.client.ShutdownTunnels()
}

func (c *helperClient) registerPendingTunnel(id uint64, tunnel *hostTunnel) {
	if c == nil || tunnel == nil {
		return
	}
	c.client.RegisterPendingTunnel(id, tunnel.inner)
}

func (c *helperClient) activateTunnel(id uint64) bool {
	if c == nil {
		return false
	}
	return c.client.ActivateTunnel(id)
}

type helperClientHost struct {
	manager *ProxyManager
}

func (h helperClientHost) HandleProxyRequest(ctx context.Context, sandboxID string, req helperproto.ProxyRequest) *helperproto.ProxyResponse {
	if h.manager == nil {
		return nil
	}
	return h.manager.handleProxyRequest(ctx, sandboxID, req)
}

func (h helperClientHost) HandleConnectRequest(ctx context.Context, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse {
	if h.manager == nil {
		return nil
	}
	return h.manager.handleConnectRequest(ctx, sandboxID, req)
}

func (h helperClientHost) HandleDNSRequest(ctx context.Context, sandboxID string, req helperproto.DNSRequest) *helperproto.DNSResponse {
	if h.manager == nil {
		return nil
	}
	return h.manager.handleDNSRequest(ctx, sandboxID, req)
}

func (h helperClientHost) HandleLeafCertRequest(host string) *helperproto.LeafCertResponse {
	if h.manager == nil {
		return nil
	}
	return h.manager.handleLeafCertRequest(host)
}

func (h helperClientHost) HandleMITMRequest(ctx context.Context, sandboxID string, req helperproto.MITMRequest) *helperproto.MITMResponse {
	if h.manager == nil {
		return nil
	}
	return h.manager.handleMITMRequest(ctx, sandboxID, req)
}

func (h helperClientHost) DialTunnel(ctx context.Context, host string, port int) (net.Conn, error) {
	if h.manager == nil {
		return nil, errors.New("helper client host manager is nil")
	}
	return h.manager.dialTunnel(ctx, host, port)
}

func convertResizeChannel(ctx context.Context, sizes <-chan TerminalSize) <-chan helperclient.TerminalSize {
	if sizes == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	out := make(chan helperclient.TerminalSize)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case size, ok := <-sizes:
				if !ok {
					return
				}
				select {
				case out <- helperclient.TerminalSize{Rows: size.Rows, Cols: size.Cols}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

type runSession struct {
	inner *helperclient.RunSession
}

func newRunSession(stdout, stderr io.Writer) *runSession {
	return &runSession{inner: helperclient.NewRunSession(stdout, stderr)}
}

func (s *runSession) Finish(result *RunResult, err error) bool {
	if s == nil {
		return false
	}
	var converted *helperclient.RunResult
	if result != nil {
		converted = &helperclient.RunResult{
			ExitCode: result.ExitCode,
			Stdout:   append([]byte(nil), result.Stdout...),
			Stderr:   append([]byte(nil), result.Stderr...),
		}
	}
	return s.inner.Finish(converted, err)
}

type hostTunnel struct {
	inner *helperclient.HostTunnel
}

func newHostTunnel(client *helperClient, id uint64, conn net.Conn) *hostTunnel {
	if client == nil {
		return nil
	}
	return &hostTunnel{inner: helperclient.NewHostTunnel(client.client, id, conn)}
}

func (t *hostTunnel) start() {
	if t == nil {
		return
	}
	t.inner.Start()
}

func (t *hostTunnel) shutdown() {
	if t == nil {
		return
	}
	t.inner.Shutdown()
}

func (t *hostTunnel) SendWriteClose(err error) {
	if t == nil {
		return
	}
	t.inner.SendWriteClose(err)
}
