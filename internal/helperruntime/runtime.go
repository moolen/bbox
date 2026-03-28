package helperruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/moolen/bbox/internal/helperproto"
	bridgepkg "github.com/moolen/bbox/internal/helperruntime/bridge"
	hrexec "github.com/moolen/bbox/internal/helperruntime/exec"
	"github.com/moolen/bbox/internal/helperruntime/ingress"
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
	currentExec         *hrexec.Session
}

type tunnelRelayResult struct {
	sendClose bool
	write     bool
	err       error
	terminal  bool
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
	return ingress.ProxyHandler(b)
}

func (b *bridge) transparentHTTPHandler() http.Handler {
	return ingress.TransparentHTTPHandler(b)
}

func (b *bridge) handleTransparentHTTPSConn(conn net.Conn) {
	ingress.ServeTransparentHTTPSConn(conn, b)
}

func (b *bridge) handleMITMConnect(w http.ResponseWriter, req *http.Request) {
	ingress.HandleMITMConnect(b, w, req)
}

func (b *bridge) handleConnect(w http.ResponseWriter, req *http.Request) {
	ingress.HandleConnect(b, w, req)
}

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

	session, streams, err := hrexec.StartSession(cmd, req)
	if err != nil {
		b.sendExecError(id, err)
		return
	}
	b.setCurrentExec(session)
	defer b.clearCurrentExec()
	defer func() {
		if err := session.Close(); err != nil {
			b.logger.Printf("close exec session: %v", err)
		}
	}()

	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream hrexec.OutputStream) {
			defer wg.Done()
			hrexec.StreamOutput(id, stream, b.send, b.logger)
		}(stream)
	}

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

func (b *bridge) handleExecInput(input helperproto.ExecInput) {
	b.execStateMu.Lock()
	session := b.currentExec
	b.execStateMu.Unlock()

	hrexec.HandleInput(session, input)
}

func (b *bridge) setCurrentExec(session *hrexec.Session) {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	b.currentExec = session
}

func (b *bridge) clearCurrentExec() {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	b.currentExec = nil
}

func (b *bridge) ReadLoop(ctx context.Context) error {
	return b.readLoop(ctx)
}

func (b *bridge) Logger() *log.Logger {
	return b.logger
}

func (b *bridge) MITMEnabled() bool {
	return b.mitmEnabled
}

func (b *bridge) MaxRequestBodyBytes() int64 {
	return b.maxRequestBodyBytes
}

func (b *bridge) ProxyRoundTrip(ctx context.Context, req helperproto.ProxyRequest) (*helperproto.ProxyResponse, error) {
	return b.runtimeBridge.ProxyRoundTrip(ctx, req)
}

func (b *bridge) Connect(ctx context.Context, host string, port int) (uint64, <-chan helperproto.Envelope, *helperproto.ConnectResponse, error) {
	return b.runtimeBridge.Connect(ctx, host, port)
}

func (b *bridge) AuthorizeConnect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error) {
	return b.runtimeBridge.AuthorizeConnect(ctx, host, port)
}

func (b *bridge) RequestLeafCert(ctx context.Context, host string) (tls.Certificate, error) {
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

func (b *bridge) MITMRoundTrip(ctx context.Context, req helperproto.MITMRequest) (*helperproto.MITMResponse, error) {
	return b.runtimeBridge.MITMRoundTrip(ctx, req)
}

func (b *bridge) RegisterTunnel(id uint64) <-chan helperproto.Envelope {
	return b.runtimeBridge.RegisterTunnel(id)
}

func (b *bridge) UnregisterTunnel(id uint64) {
	b.runtimeBridge.UnregisterTunnel(id)
}

func (b *bridge) DeliverTunnel(env helperproto.Envelope) {
	b.runtimeBridge.DeliverTunnel(env)
}

func (b *bridge) SendTunnelClose(id uint64, write bool, tunnelErr error) error {
	return b.runtimeBridge.SendTunnelClose(id, write, tunnelErr)
}

func (b *bridge) RelayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) ingress.TunnelRelayResult {
	return tunnelRelayResultFromBridge(b.runtimeBridge.RelayPayloadToTunnel(conn, id, bufferedPayload))
}

func (b *bridge) relayPayloadToTunnel(conn net.Conn, id uint64, bufferedPayload []byte) tunnelRelayResult {
	result := b.RelayPayloadToTunnel(conn, id, bufferedPayload)
	return tunnelRelayResult{
		sendClose: result.SendClose,
		write:     result.Write,
		err:       result.Err,
		terminal:  result.Terminal,
	}
}

func (b *bridge) RelayTunnelToPayload(ctx context.Context, conn net.Conn, tunnelCh <-chan helperproto.Envelope) ingress.TunnelRelayResult {
	return tunnelRelayResultFromBridge(b.runtimeBridge.RelayTunnelToPayload(ctx, conn, tunnelCh))
}

func (b *bridge) relayTunnelToPayload(ctx context.Context, conn net.Conn, tunnelCh <-chan helperproto.Envelope) tunnelRelayResult {
	result := b.RelayTunnelToPayload(ctx, conn, tunnelCh)
	return tunnelRelayResult{
		sendClose: result.SendClose,
		write:     result.Write,
		err:       result.Err,
		terminal:  result.Terminal,
	}
}

func tunnelRelayResultFromBridge(result bridgepkg.TunnelRelayResult) ingress.TunnelRelayResult {
	return ingress.TunnelRelayResult{
		SendClose: result.SendClose,
		Write:     result.Write,
		Err:       result.Err,
		Terminal:  result.Terminal,
	}
}

func (b *bridge) send(env helperproto.Envelope) error {
	return b.runtimeBridge.Send(env)
}
