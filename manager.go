package bbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	"github.com/moolen/bbox/internal/helperruntime"
)

func newProxyManager(policy *compiledPolicy) *ProxyManager {
	return &ProxyManager{
		registry:   newSandboxRegistry(policy),
		resolver:   newHelperBinaryResolver(),
		transport:  cloneDefaultTransport(),
		listenAddr: helperruntime.DefaultProxyAddr,
	}
}

func cloneDefaultTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}
	return &http.Transport{}
}

func (m *ProxyManager) registerSandbox(sandboxID string, policy *compiledPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.registry.Register(sandboxID, policy); err != nil {
		return err
	}
	initAuditStateLocked(m, sandboxID)
	return nil
}

func (m *ProxyManager) attachSandbox(sandboxID string, sandbox *Sandbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registry.Attach(sandboxID, sandbox)
}

func (m *ProxyManager) unregisterSandbox(sandboxID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry.Unregister(sandboxID)
	removeAuditStateLocked(m, sandboxID)
}

func (m *ProxyManager) policyForSandbox(sandboxID string) (*compiledPolicy, bool) {
	return m.registry.Policy(sandboxID)
}

func (m *ProxyManager) nextSandboxName(requested string) string {
	if trimmed := strings.TrimSpace(requested); trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("sandbox-%d", m.nextSandboxID.Add(1))
}

func (m *ProxyManager) helperBinary() (string, error) {
	return m.resolver.HelperBinary()
}

func (m *ProxyManager) handleProxyRequest(ctx context.Context, sandboxID string, req helperproto.ProxyRequest) *helperproto.ProxyResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.ProxyResponse{Error: fmt.Sprintf("sandbox %q is not registered", sandboxID)}
	}
	return newManagerProxyService(managerProxyConfig{
		transport:            m.transport,
		maxRequestBodyBytes:  m.requestBodyLimitBytes,
		maxResponseBodyBytes: m.responseBodyLimitBytes,
		record:               m.recordAccessEvent,
	}).HandleProxyRequest(ctx, policy, sandboxID, req)
}

func (m *ProxyManager) handleConnectRequest(ctx context.Context, sandboxID string, req helperproto.ConnectRequest) *helperproto.ConnectResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.ConnectResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("sandbox %q is not registered", sandboxID),
		}
	}
	return newManagerConnectService(m.recordAccessEvent).HandleConnectRequest(ctx, policy, sandboxID, req)
}

func (m *ProxyManager) handleMITMRequest(ctx context.Context, sandboxID string, req helperproto.MITMRequest) *helperproto.MITMResponse {
	policy, ok := m.policyForSandbox(sandboxID)
	if !ok {
		return &helperproto.MITMResponse{
			StatusCode: http.StatusBadGateway,
			Error:      fmt.Sprintf("sandbox %q is not registered", sandboxID),
		}
	}
	return newManagerProxyService(managerProxyConfig{
		transport:            m.transport,
		maxRequestBodyBytes:  m.requestBodyLimitBytes,
		maxResponseBodyBytes: m.responseBodyLimitBytes,
		record:               m.recordAccessEvent,
	}).HandleMITMRequest(ctx, policy, sandboxID, req)
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
		sandboxes := m.registry.AttachedSandboxes()

		for _, sandbox := range sandboxes {
			closeErr = errors.Join(closeErr, sandbox.Close())
		}

		newManagerProxyService(managerProxyConfig{transport: m.transport}).CloseIdleConnections()
		closeErr = errors.Join(closeErr, m.resolver.Cleanup())

		m.mu.Lock()
		auditStateByManager.Delete(m)
		m.mu.Unlock()
	})

	return closeErr
}
