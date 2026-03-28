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
	initAuditStateLocked(m, sandboxID)
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
	removeAuditStateLocked(m, sandboxID)
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
	trafficMode := m.trafficModeForSandbox(sandboxID)

	targetURL, err := url.Parse(req.URL)
	if err != nil {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("parse request URL %q: %v", req.URL, err)}
	}
	path := targetURL.Path
	if path == "" {
		path = "/"
	}
	port := 0
	if rawPort := targetURL.Port(); rawPort != "" {
		if parsed, err := strconv.Atoi(rawPort); err == nil {
			port = parsed
		}
	} else {
		switch strings.ToLower(targetURL.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	host, port := normalizeHostPort(targetURL.Host, port)
	if err := policy.Check(req.Method, targetURL.Host, req.Method == http.MethodConnect); err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "http",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     false,
			StatusCode:  http.StatusForbidden,
			Result:      "denied",
			Error:       err.Error(),
		})
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
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "http",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("build outbound request: %v", err)}
	}
	outReq.Header = req.Header.Clone()
	outReq.Host = targetURL.Host

	resp, err := m.outboundTransport().RoundTrip(outReq)
	if err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "http",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.ProxyResponse{Error: err.Error()}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "http",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			StatusCode:  resp.StatusCode,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("read outbound response body: %v", err)}
	}

	m.recordAccessEvent(accessEvent{
		SandboxID:   sandboxID,
		TrafficMode: trafficMode,
		Kind:        "http",
		Host:        host,
		Port:        port,
		Method:      req.Method,
		Path:        path,
		Allowed:     true,
		StatusCode:  resp.StatusCode,
		Result:      "allowed",
	})
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
	trafficMode := m.trafficModeForSandbox(sandboxID)

	host, port := normalizeHostPort(req.Host, req.Port)
	hostport := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	if err := policy.Check(http.MethodConnect, hostport, true); err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "connect",
			Host:        host,
			Port:        port,
			Method:      http.MethodConnect,
			Allowed:     false,
			StatusCode:  http.StatusForbidden,
			Result:      "denied",
			Error:       err.Error(),
		})
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusForbidden,
			Message:    "connect request denied",
			Error:      err.Error(),
		}
	}

	m.recordAccessEvent(accessEvent{
		SandboxID:   sandboxID,
		TrafficMode: trafficMode,
		Kind:        "connect",
		Host:        host,
		Port:        port,
		Method:      http.MethodConnect,
		Allowed:     true,
		StatusCode:  http.StatusOK,
		Result:      "allowed",
	})
	return &helperproto.ConnectResponse{
		StatusCode: http.StatusOK,
	}
}

func (m *ProxyManager) handleMITMRequest(ctx context.Context, sandboxID string, req helperproto.MITMRequest) *helperproto.MITMResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("sandbox %q is not registered", sandboxID),
		}
	}
	trafficMode := m.trafficModeForSandbox(sandboxID)
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := req.Authority
	if authority == "" {
		authority = req.Host
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	host, port := mitmHostPort(req.Host, authority, scheme)
	if req.BodyTooLarge {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     false,
			StatusCode:  http.StatusRequestEntityTooLarge,
			Result:      "denied",
			Error:       "request body exceeds inspection limit",
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusRequestEntityTooLarge,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: request body exceeds inspection limit\n"),
		}
	}

	if err := policy.CheckRequest(PolicyRequest{
		Method:       req.Method,
		Host:         req.Host,
		Path:         req.Path,
		Header:       req.Header,
		Body:         req.Body,
		BodyTooLarge: req.BodyTooLarge,
	}); err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     false,
			StatusCode:  http.StatusForbidden,
			Result:      "denied",
			Error:       err.Error(),
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Content-Type": []string{"text/plain; charset=utf-8"},
			},
			Body: []byte("proxy request denied: " + err.Error() + "\n"),
		}
	}
	if authority == "" {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     false,
			StatusCode:  http.StatusBadRequest,
			Result:      "denied",
			Error:       "MITM request authority is required",
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "MITM request authority is required",
		}
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     authority,
		Path:     path,
		RawQuery: req.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("build outbound MITM request: %v", err),
		}
	}
	outReq.Header = req.Header.Clone()
	if outReq.Header == nil {
		outReq.Header = make(http.Header)
	}
	if req.Host != "" {
		outReq.Host = req.Host
	}

	resp, err := m.outboundTransport().RoundTrip(outReq)
	if err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      err.Error(),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		m.recordAccessEvent(accessEvent{
			SandboxID:   sandboxID,
			TrafficMode: trafficMode,
			Kind:        "mitm",
			Host:        host,
			Port:        port,
			Method:      req.Method,
			Path:        path,
			Allowed:     true,
			StatusCode:  resp.StatusCode,
			Result:      "upstream_error",
			Error:       err.Error(),
		})
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("read outbound MITM response body: %v", err),
		}
	}

	m.recordAccessEvent(accessEvent{
		SandboxID:   sandboxID,
		TrafficMode: trafficMode,
		Kind:        "mitm",
		Host:        host,
		Port:        port,
		Method:      req.Method,
		Path:        path,
		Allowed:     true,
		StatusCode:  resp.StatusCode,
		Result:      "allowed",
	})
	return &helperproto.MITMResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
}

func authorityPort(authority string) string {
	if authority == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(authority)
	if err != nil {
		return ""
	}
	return port
}

func mitmHostPort(requestHost, authority, scheme string) (string, int) {
	requestHost = strings.TrimSpace(requestHost)
	base := requestHost
	if base == "" {
		base = authority
	}
	if base == "" {
		return normalizeHostPort(base, 0)
	}
	if requestHost != "" {
		if rawPort := authorityPort(base); rawPort != "" {
			if parsed, err := strconv.Atoi(rawPort); err == nil {
				return normalizeHostPort(base, parsed)
			}
			return normalizeHostPort(base, 0)
		}
		if rawPort := authorityPort(authority); rawPort != "" {
			if parsed, err := strconv.Atoi(rawPort); err == nil {
				return normalizeHostPort(base, parsed)
			}
		}
		port := defaultPortForScheme(scheme)
		return normalizeHostPort(base, port)
	}

	port := 0
	if rawPort := authorityPort(base); rawPort != "" {
		if parsed, err := strconv.Atoi(rawPort); err == nil {
			port = parsed
		}
	} else {
		port = defaultPortForScheme(scheme)
	}
	return normalizeHostPort(base, port)
}

func defaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}

func (m *ProxyManager) handleLeafCertRequest(host string) *helperproto.LeafCertResponse {
	if m == nil || m.mitmCA == nil {
		return &helperproto.LeafCertResponse{
			Error: "MITM CA is not configured",
		}
	}

	certPEM, keyPEM, err := m.mitmCA.LeafPEMForHost(host)
	if err != nil {
		return &helperproto.LeafCertResponse{
			Error: err.Error(),
		}
	}

	return &helperproto.LeafCertResponse{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
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

// CACertPEM returns the manager's MITM CA certificate in PEM form.
func (m *ProxyManager) CACertPEM() []byte {
	if m == nil || len(m.caCertPEM) == 0 {
		return nil
	}

	out := make([]byte, len(m.caCertPEM))
	copy(out, m.caCertPEM)
	return out
}

// Close stops all registered sandboxes, closes idle outbound proxy connections,
// and removes temporary helper build artifacts.
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

		m.mu.Lock()
		auditStateByManager.Delete(m)
		m.mu.Unlock()
	})

	return closeErr
}

func (m *ProxyManager) recordAccessEvent(event accessEvent) {
	if m == nil || event.SandboxID == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	event.TrafficMode = normalizeTrafficMode(event.TrafficMode)
	entry := event.toAccessLogEntry()

	m.mu.Lock()
	if _, ok := m.sandboxes[event.SandboxID]; !ok {
		m.mu.Unlock()
		return
	}
	updateAuditStateLocked(auditStateLocked(m), event)
	logger := m.accessLogger
	m.mu.Unlock()

	if logger != nil {
		func() {
			defer func() {
				_ = recover()
			}()
			logger.LogAccess(entry)
		}()
	}
}

func (m *ProxyManager) trafficModeForSandbox(sandboxID string) TrafficMode {
	if m == nil || sandboxID == "" {
		return TrafficModeProxy
	}

	m.mu.RLock()
	sandbox := m.sandboxes[sandboxID]
	m.mu.RUnlock()
	if sandbox == nil {
		return TrafficModeProxy
	}

	return normalizeTrafficMode(sandbox.trafficMode)
}

func (m *ProxyManager) accessedDomainsSnapshot(sandboxID string) []AccessedDomain {
	if m == nil || sandboxID == "" {
		return []AccessedDomain{}
	}

	m.mu.RLock()
	stateValue, ok := auditStateByManager.Load(m)
	if !ok {
		m.mu.RUnlock()
		return []AccessedDomain{}
	}
	state := stateValue.(*managerAuditState)
	sandboxState, ok := state.sandboxes[sandboxID]
	if !ok {
		m.mu.RUnlock()
		return []AccessedDomain{}
	}
	snapshot := snapshotAccessedDomains(sandboxState)
	m.mu.RUnlock()
	return snapshot
}
