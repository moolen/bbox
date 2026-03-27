package bbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"github.com/moolen/bbox/internal/helperruntime"
)

func newProxyManager(policy *compiledPolicy) *ProxyManager {
	return &ProxyManager{
		policy:          policy,
		sandboxes:       make(map[string]*Sandbox),
		sandboxPolicies: make(map[string]*compiledPolicy),
		transport:       cloneDefaultTransport(),
		listenAddr:      helperruntime.DefaultProxyAddr,
	}
}

func cloneDefaultTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}
	return &http.Transport{}
}

func (m *ProxyManager) registerSandbox(sandboxID string, policy *compiledPolicy) error {
	if sandboxID == "" {
		return fmt.Errorf("sandbox ID is required")
	}
	if policy == nil {
		policy = m.policy
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sandboxes[sandboxID]; exists {
		return fmt.Errorf("sandbox %q is already registered", sandboxID)
	}

	m.sandboxes[sandboxID] = nil
	m.sandboxPolicies[sandboxID] = policy
	return nil
}

func (m *ProxyManager) attachSandbox(sandboxID string, sandbox *Sandbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sandboxes[sandboxID]; !exists {
		return fmt.Errorf("sandbox %q is not registered", sandboxID)
	}
	m.sandboxes[sandboxID] = sandbox
	return nil
}

func (m *ProxyManager) unregisterSandbox(sandboxID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sandboxes, sandboxID)
	delete(m.sandboxPolicies, sandboxID)
}

func (m *ProxyManager) policyForSandbox(sandboxID string) (*compiledPolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.sandboxPolicies[sandboxID]
	return policy, ok
}

func (m *ProxyManager) outboundTransport() *http.Transport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.transport
}

func (m *ProxyManager) nextSandboxName(requested string) string {
	if trimmed := strings.TrimSpace(requested); trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("sandbox-%d", m.nextSandboxID.Add(1))
}

func (m *ProxyManager) helperBinary() (string, error) {
	m.helperBinaryOnce.Do(func() {
		moduleRoot, err := packageRoot()
		if err != nil {
			m.helperBinaryErr = err
			return
		}

		buildDir, err := os.MkdirTemp("", "bbox-helper-build-")
		if err != nil {
			m.helperBinaryErr = fmt.Errorf("create helper build dir: %w", err)
			return
		}

		helperPath := filepath.Join(buildDir, "bbox-helper")
		cmd := exec.Command("go", "build", "-o", helperPath, "./cmd/bbox-helper")
		cmd.Dir = moduleRoot

		output, err := cmd.CombinedOutput()
		if err != nil {
			_ = os.RemoveAll(buildDir)
			msg := strings.TrimSpace(string(output))
			if msg != "" {
				m.helperBinaryErr = fmt.Errorf("build helper binary: %w: %s", err, msg)
				return
			}
			m.helperBinaryErr = fmt.Errorf("build helper binary: %w", err)
			return
		}

		m.helperBinaryDir = buildDir
		m.helperBinaryPath = helperPath
	})

	if m.helperBinaryErr != nil {
		return "", m.helperBinaryErr
	}
	if m.helperBinaryPath == "" {
		return "", fmt.Errorf("helper binary path is empty")
	}
	return m.helperBinaryPath, nil
}

func packageRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("determine package root: runtime caller unavailable")
	}

	root := filepath.Dir(file)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("locate package root from %q: %w", root, err)
	}
	return root, nil
}

func (m *ProxyManager) handleProxyRequest(ctx context.Context, sandboxID string, req helperproto.ProxyRequest) *helperproto.ProxyResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("sandbox %q is not registered", sandboxID)}
	}

	targetURL, err := url.Parse(req.URL)
	if err != nil {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("parse request URL %q: %v", req.URL, err)}
	}
	if err := policy.Check(req.Method, targetURL.Host, req.Method == http.MethodConnect); err != nil {
		return &helperproto.ProxyResponse{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err.Error() + "\n"),
		}
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("build outbound request: %v", err)}
	}
	outReq.Header = req.Header.Clone()
	outReq.Host = targetURL.Host

	resp, err := m.outboundTransport().RoundTrip(outReq)
	if err != nil {
		return &helperproto.ProxyResponse{Error: err.Error()}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("read outbound response body: %v", err)}
	}

	return &helperproto.ProxyResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
}

func (m *ProxyManager) handleConnectRequest(ctx context.Context, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("sandbox %q is not registered", sandboxID),
		}
	}

	hostport := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	if err := policy.Check(http.MethodConnect, hostport, true); err != nil {
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusForbidden,
			Message:    "connect request denied",
			Error:      err.Error(),
		}
	}

	return &helperproto.ConnectResponse{
		StatusCode: http.StatusOK,
	}
}

var dialTunnelFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", address)
}

func (m *ProxyManager) dialTunnel(ctx context.Context, host string, port int) (net.Conn, error) {
	return dialTunnelFn(ctx, host, port)
}

func (m *ProxyManager) Close() error {
	var closeErr error

	m.closeOnce.Do(func() {
		m.mu.RLock()
		sandboxes := make([]*Sandbox, 0, len(m.sandboxes))
		for _, sandbox := range m.sandboxes {
			if sandbox != nil {
				sandboxes = append(sandboxes, sandbox)
			}
		}
		m.mu.RUnlock()

		for _, sandbox := range sandboxes {
			closeErr = errors.Join(closeErr, sandbox.Close())
		}

		if transport := m.outboundTransport(); transport != nil {
			transport.CloseIdleConnections()
		}
		if m.helperBinaryDir != "" {
			closeErr = errors.Join(closeErr, os.RemoveAll(m.helperBinaryDir))
		}
	})

	return closeErr
}
