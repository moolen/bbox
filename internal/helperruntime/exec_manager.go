package helperruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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

// bridge adapts the runtime packages to the helper's control bridge while
// delegating exec and transparent-network state to focused collaborators.
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
	exec                  *execManager
	transparent           *transparentNet
}

func newBridge(conn io.ReadWriteCloser, logger *log.Logger, proxyAddr string) *bridge {
	b := &bridge{
		runtimeBridge: bridgepkg.New(conn, logger, proxyAddr),
		logger:        logger,
		transparent:   newTransparentNet(),
	}
	b.exec = newExecManager(logger, func() TrafficMode {
		return b.trafficMode
	}, func() seccompnotify.RuntimeTargets {
		return b.transparentRuntime()
	}, b.send)
	return b
}

func (b *bridge) readLoop(ctx context.Context) error {
	b.runtimeBridge.SetReadyAddrs(b.dnsAddr, b.tcpAddr)
	b.runtimeBridge.SetExecHandlers(b.exec.handleExec, b.exec.handleExecInput)
	return b.runtimeBridge.ReadLoop(ctx)
}

func (b *bridge) handleExecInput(id uint64, input helperproto.ExecInput) {
	if b == nil || b.exec == nil {
		return
	}
	b.exec.handleExecInput(id, input)
}

type execState struct {
	id      uint64
	session *hrexec.Session
	cancel  context.CancelFunc
}

type execManager struct {
	logger         *log.Logger
	trafficMode    func() TrafficMode
	runtimeTargets func() seccompnotify.RuntimeTargets
	send           func(helperproto.Envelope) error
	execMu         sync.Mutex
	execStateMu    sync.Mutex
	currentExec    *execState
}

func newExecManager(logger *log.Logger, trafficMode func() TrafficMode, runtimeTargets func() seccompnotify.RuntimeTargets, send func(helperproto.Envelope) error) *execManager {
	return &execManager{
		logger:         logger,
		trafficMode:    trafficMode,
		runtimeTargets: runtimeTargets,
		send:           send,
	}
}

func (m *execManager) currentTrafficMode() TrafficMode {
	if m == nil || m.trafficMode == nil {
		return ""
	}
	return m.trafficMode()
}

func (m *execManager) handleExec(ctx context.Context, id uint64, req helperproto.ExecRequest) {
	m.execMu.Lock()
	defer m.execMu.Unlock()

	if len(req.Argv) == 0 {
		_ = m.send(helperproto.Envelope{
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

	commandPath, err := resolveExecCommandPath(req.Argv[0], req.Env, req.WorkDir)
	if err != nil {
		m.sendExecError(id, err)
		return
	}

	cmd := exec.CommandContext(runCtx, commandPath, req.Argv[1:]...)
	cmd.Env = append([]string(nil), req.Env...)
	cmd.Dir = req.WorkDir

	var (
		session    *hrexec.Session
		streams    []hrexec.OutputStream
		supervisor *seccompnotify.Supervisor
	)
	if m.currentTrafficMode() == TrafficModeTransparent {
		session, streams, supervisor, err = runSupervisedExec(runCtx, cmd, req, m.runtimeTargets())
	} else {
		session, streams, err = hrexec.StartSession(cmd, req)
	}
	if err != nil {
		m.sendExecError(id, err)
		return
	}
	m.setCurrentExec(&execState{id: id, session: session, cancel: cancel})
	defer m.clearCurrentExec(id)
	defer func() {
		if err := session.Close(); err != nil {
			m.logger.Printf("close exec session: %v", err)
		}
	}()
	if supervisor != nil {
		defer func() {
			if err := supervisor.Close(); err != nil {
				m.logger.Printf("close exec supervisor: %v", err)
			}
		}()
	}

	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream hrexec.OutputStream) {
			defer wg.Done()
			hrexec.StreamOutput(id, stream, m.send, m.logger)
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

	if err := m.send(helperproto.Envelope{
		ID:         id,
		ExecResult: result,
	}); err != nil {
		m.logger.Printf("send exec result: %v", err)
	}
}

func resolveExecCommandPath(name string, env []string, workDir string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("argv[0] is required")
	}
	if strings.Contains(name, string(filepath.Separator)) {
		return name, nil
	}

	pathValue, ok := envValue(env, "PATH")
	if !ok {
		return name, nil
	}

	cwd := workDir
	if strings.TrimSpace(cwd) == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve working directory for %q: %w", name, err)
		}
	}

	for _, dir := range strings.Split(pathValue, string(os.PathListSeparator)) {
		if dir == "" {
			dir = "."
		}
		candidate := dir
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		candidate = filepath.Join(candidate, name)

		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}

	return "", fmt.Errorf("exec: %q: executable file not found in $PATH", name)
}

func envValue(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		entryKey, value, ok := strings.Cut(env[i], "=")
		if !ok {
			continue
		}
		if entryKey == key {
			return value, true
		}
	}
	return "", false
}

func (m *execManager) sendExecError(id uint64, err error) {
	if sendErr := m.send(helperproto.Envelope{
		ID: id,
		ExecResult: &helperproto.ExecResult{
			ExitCode: -1,
			Stderr:   []byte(err.Error()),
			Error:    err.Error(),
		},
	}); sendErr != nil {
		m.logger.Printf("send exec error: %v", sendErr)
	}
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

func (m *execManager) handleExecInput(id uint64, input helperproto.ExecInput) {
	m.execStateMu.Lock()
	state := m.currentExec
	m.execStateMu.Unlock()

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

func (m *execManager) setCurrentExec(state *execState) {
	m.execStateMu.Lock()
	defer m.execStateMu.Unlock()
	m.currentExec = state
}

func (m *execManager) clearCurrentExec(id uint64) {
	m.execStateMu.Lock()
	defer m.execStateMu.Unlock()
	if m.currentExec == nil || m.currentExec.id != id {
		return
	}
	m.currentExec = nil
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

func (b *bridge) AuthorizeTransparentConnect(ctx context.Context, host string, port int, metadata helperproto.ProtocolMetadata) (*helperproto.ConnectResponse, error) {
	return b.runtimeBridge.AuthorizeTransparentConnect(ctx, host, port, metadata)
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
