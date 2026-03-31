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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	bridgepkg "github.com/moolen/bbox/internal/helperruntime/bridge"
	hrexec "github.com/moolen/bbox/internal/helperruntime/exec"
	"github.com/moolen/bbox/internal/helperruntime/ingress"
	"github.com/moolen/bbox/internal/helperruntime/seccompnotify"
)

var (
	newSupervisorForExec  = seccompnotify.NewSupervisor
	prepareSupervisorExec = func(ctx context.Context, supervisor *seccompnotify.Supervisor, cmd *exec.Cmd) error {
		return supervisor.Prepare(ctx, cmd)
	}
	startSupervisorExec = func(ctx context.Context, supervisor *seccompnotify.Supervisor, pid int) error {
		return supervisor.Start(ctx, pid)
	}
)

// OpenBridgeFromFD adopts the already-open control bridge passed into the
// helper process by the parent launcher.
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

// Run starts the helper runtime in either proxy or transparent mode and serves
// the control bridge until the context or bridge terminates.
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

// bridge adapts the runtime packages to the helper's control bridge and keeps
// per-exec or per-connection state that is local to one helper process.
type bridge struct {
	runtimeBridge         *bridgepkg.RuntimeBridge
	logger                *log.Logger
	trafficMode           TrafficMode
	dnsAddr               string
	tcpAddr               string
	rawTCPAddr            string
	rawTCPAddrV6          string
	mitmEnabled           bool
	maxRequestBodyBytes   int64
	payloadSeccompBPFPath string
	execMu                sync.Mutex
	execStateMu           sync.Mutex
	currentExec           *execState
	rawTCPMu              sync.Mutex
	rawTCPOrigins         map[string]rawTCPDestination
}

func newBridge(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *bridge {
	return &bridge{
		runtimeBridge: bridgepkg.New(conn, logger, proxyAddr),
		logger:        logger,
		rawTCPOrigins: make(map[string]rawTCPDestination),
	}
}

type execState struct {
	id      uint64
	session *hrexec.Session
	cancel  context.CancelFunc
}

type rawTCPDestination struct {
	host string
	port int
}

const rawTCPOriginLookupTimeout = 1 * time.Second

func (b *bridge) readLoop(ctx context.Context) error {
	b.runtimeBridge.SetReadyAddrs(b.dnsAddr, b.tcpAddr)
	b.runtimeBridge.SetExecHandlers(b.handleExec, b.handleExecInput)
	return b.runtimeBridge.ReadLoop(ctx)
}

func (b *bridge) proxyHandler() http.Handler {
	return ingress.ProxyHandler(b)
}

func (b *bridge) transparentHTTPHandler() http.Handler {
	return ingress.TransparentHTTPHandler(b)
}

func (b *bridge) handleTransparentTCPConn(conn net.Conn) {
	if conn == nil {
		return
	}

	host, port, _ := b.waitRawTCPOrigin(conn.RemoteAddr().String(), rawTCPOriginLookupTimeout)
	ingress.ServeTransparentTCPConn(conn, b, host, port)
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

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(runCtx, req.Argv[0], req.Argv[1:]...)
	cmd.Env = append([]string(nil), req.Env...)
	cmd.Dir = req.WorkDir

	var (
		session    *hrexec.Session
		streams    []hrexec.OutputStream
		supervisor *seccompnotify.Supervisor
		err        error
	)
	if b.trafficMode == TrafficModeTransparent {
		session, streams, supervisor, err = runSupervisedExec(runCtx, cmd, req, b.transparentRuntime())
	} else {
		session, streams, err = hrexec.StartSession(cmd, req)
	}
	if err != nil {
		b.sendExecError(id, err)
		return
	}
	b.setCurrentExec(&execState{id: id, session: session, cancel: cancel})
	defer b.clearCurrentExec(id)
	defer func() {
		if err := session.Close(); err != nil {
			b.logger.Printf("close exec session: %v", err)
		}
	}()
	if supervisor != nil {
		defer func() {
			if err := supervisor.Close(); err != nil {
				b.logger.Printf("close exec supervisor: %v", err)
			}
		}()
	}

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

func (b *bridge) transparentRuntime() seccompnotify.RuntimeTargets {
	return seccompnotify.RuntimeTargets{
		DNSRoundTrip:          b.dnsRoundTrip,
		RawTCPAddr:            b.rawTCPAddr,
		RawTCPAddrV6:          b.rawTCPAddrV6,
		RecordRawTCPOrigin:    b.recordRawTCPOrigin,
		PayloadSeccompBPFPath: b.payloadSeccompBPFPath,
	}
}

func (b *bridge) dnsRoundTrip(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
	if b == nil || b.runtimeBridge == nil {
		return nil, fmt.Errorf("runtime bridge is required")
	}
	return b.runtimeBridge.DNSRoundTrip(ctx, helperproto.DNSRequest{
		Network: network,
		Host:    host,
		Port:    port,
		Payload: append([]byte(nil), payload...),
	})
}

func (b *bridge) recordRawTCPOrigin(localAddr, host string, port int) {
	if b == nil || localAddr == "" || host == "" || port < 1 || port > 65535 {
		return
	}
	localAddr = canonicalTCPOriginKey(localAddr)
	b.rawTCPMu.Lock()
	b.rawTCPOrigins[localAddr] = rawTCPDestination{host: host, port: port}
	b.rawTCPMu.Unlock()
}

func (b *bridge) takeRawTCPOrigin(localAddr string) (string, int, bool) {
	if b == nil || localAddr == "" {
		return "", 0, false
	}
	localAddr = canonicalTCPOriginKey(localAddr)

	b.rawTCPMu.Lock()
	dest, ok := b.rawTCPOrigins[localAddr]
	if ok {
		delete(b.rawTCPOrigins, localAddr)
	}
	b.rawTCPMu.Unlock()
	if !ok {
		return "", 0, false
	}
	return dest.host, dest.port, true
}

func (b *bridge) waitRawTCPOrigin(localAddr string, timeout time.Duration) (string, int, bool) {
	if timeout <= 0 {
		return b.takeRawTCPOrigin(localAddr)
	}

	deadline := time.Now().Add(timeout)
	for {
		host, port, ok := b.takeRawTCPOrigin(localAddr)
		if ok {
			return host, port, true
		}
		if time.Now().After(deadline) {
			return "", 0, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func canonicalTCPOriginKey(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	if _, err := strconv.Atoi(port); err != nil {
		return addr
	}
	return net.JoinHostPort(host, port)
}

func runSupervisedExec(runCtx context.Context, cmd *exec.Cmd, req helperproto.ExecRequest, runtimeTargets seccompnotify.RuntimeTargets) (*hrexec.Session, []hrexec.OutputStream, *seccompnotify.Supervisor, error) {
	supervisor, err := newSupervisorForExec(runtimeTargets)
	if err != nil {
		return nil, nil, nil, err
	}
	supervisor.SetPayloadSeccompBPFPath(runtimeTargets.PayloadSeccompBPFPath)
	if err := prepareSupervisorExec(runCtx, supervisor, cmd); err != nil {
		_ = supervisor.Close()
		return nil, nil, nil, err
	}

	session, streams, err := hrexec.StartSession(cmd, req)
	if err != nil {
		_ = supervisor.Close()
		return nil, nil, nil, err
	}
	if cmd.Process == nil {
		_ = session.Close()
		_ = supervisor.Close()
		return nil, nil, nil, fmt.Errorf("supervised exec started without child process")
	}
	if err := startSupervisorExec(runCtx, supervisor, cmd.Process.Pid); err != nil {
		_ = session.Close()
		_ = supervisor.Close()
		return nil, nil, nil, err
	}
	return session, streams, supervisor, nil
}

func (b *bridge) handleExecInput(id uint64, input helperproto.ExecInput) {
	b.execStateMu.Lock()
	state := b.currentExec
	b.execStateMu.Unlock()

	if state == nil || state.id != id {
		return
	}
	if input.Cancel {
		state.cancel()
		if state.session != nil {
			_ = state.session.Close()
		}
		return
	}
	hrexec.HandleInput(state.session, input)
}

func (b *bridge) setCurrentExec(state *execState) {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	b.currentExec = state
}

func (b *bridge) clearCurrentExec(id uint64) {
	b.execStateMu.Lock()
	defer b.execStateMu.Unlock()
	if b.currentExec == nil || b.currentExec.id != id {
		return
	}
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

func (b *bridge) AuthorizeTransparentConnect(ctx context.Context, host string, port int) (*helperproto.ConnectResponse, error) {
	return b.runtimeBridge.AuthorizeTransparentConnect(ctx, host, port)
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

func (b *bridge) RelayTunnelToPayload(ctx context.Context, conn net.Conn, tunnelCh <-chan helperproto.Envelope) ingress.TunnelRelayResult {
	return tunnelRelayResultFromBridge(b.runtimeBridge.RelayTunnelToPayload(ctx, conn, tunnelCh))
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
