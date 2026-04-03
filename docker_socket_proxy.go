package bbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultDockerSocketMountPath  = "/var/run/docker.sock"
	defaultDockerSocketTargetPath = "/var/run/docker.sock"
)

type dockerSocketProxy struct {
	listener   net.Listener
	client     *http.Client
	server     *http.Server
	socketPath string
	socketDir  string
}

func (p *dockerSocketProxy) Close() error {
	if p == nil {
		return nil
	}

	var closeErr error
	if p.server != nil {
		if err := p.server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	if p.client != nil {
		if transport, ok := p.client.Transport.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	}
	if p.listener != nil {
		if err := p.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	if p.socketPath != "" {
		if err := os.Remove(p.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErr = errors.Join(closeErr, fmt.Errorf("remove docker proxy socket %q: %w", p.socketPath, err))
		}
	}
	if p.socketDir != "" {
		if err := os.RemoveAll(p.socketDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErr = errors.Join(closeErr, fmt.Errorf("remove docker proxy dir %q: %w", p.socketDir, err))
		}
	}
	return closeErr
}

func (m *ProxyManager) effectiveDockerSocketConfig(opts SandboxOptions) (DockerSocketOptions, *compiledDockerSocketPolicy, error) {
	effective := m.dockerSocket
	if opts.DockerSocket.Enabled {
		effective.Enabled = true
	}
	if mountPath := strings.TrimSpace(opts.DockerSocket.MountPath); mountPath != "" {
		effective.MountPath = mountPath
	}
	if targetSocketPath := strings.TrimSpace(opts.DockerSocket.TargetSocketPath); targetSocketPath != "" {
		effective.TargetSocketPath = targetSocketPath
	}

	compiled := m.dockerSocketPolicy
	if hasDockerSocketPolicyOverride(opts.DockerSocket.Policy) {
		effective.Policy = opts.DockerSocket.Policy
		var err error
		compiled, err = compileDockerSocketPolicy(opts.DockerSocket.Policy)
		if err != nil {
			return DockerSocketOptions{}, nil, err
		}
	}
	if compiled == nil {
		var err error
		compiled, err = compileDockerSocketPolicy(effective.Policy)
		if err != nil {
			return DockerSocketOptions{}, nil, err
		}
	}

	if !effective.Enabled {
		return effective, compiled, nil
	}
	if strings.TrimSpace(effective.MountPath) == "" {
		effective.MountPath = defaultDockerSocketMountPath
	}
	if strings.TrimSpace(effective.TargetSocketPath) == "" {
		effective.TargetSocketPath = defaultDockerSocketTargetPath
	}
	return effective, compiled, nil
}

func hasDockerSocketPolicyOverride(policy DockerSocketPolicy) bool {
	return policy.DefaultAction != "" || len(policy.Rules) > 0
}

func (m *ProxyManager) startDockerSocketProxy(sandboxID string, opts DockerSocketOptions, policy *compiledDockerSocketPolicy) (*dockerSocketProxy, error) {
	if m == nil {
		return nil, fmt.Errorf("proxy manager is required")
	}
	if strings.TrimSpace(sandboxID) == "" {
		return nil, fmt.Errorf("sandbox ID is required")
	}
	if !opts.Enabled {
		return nil, fmt.Errorf("docker socket mediation is not enabled")
	}
	if policy == nil {
		return nil, fmt.Errorf("docker socket policy is required")
	}

	socketDir, err := os.MkdirTemp("", "bbox-docker-socket-"+sanitizeDockerSocketSandboxID(sandboxID)+"-")
	if err != nil {
		return nil, fmt.Errorf("create docker proxy temp dir: %w", err)
	}
	socketPath := filepath.Join(socketDir, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		return nil, fmt.Errorf("listen docker proxy socket: %w", err)
	}

	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", opts.TargetSocketPath)
		},
	}
	client := &http.Client{Transport: transport}

	proxy := &dockerSocketProxy{
		listener:   listener,
		client:     client,
		socketPath: socketPath,
		socketDir:  socketDir,
	}
	proxy.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			m.serveDockerSocketProxy(w, req, sandboxID, policy, client)
		}),
	}

	go func() {
		_ = proxy.server.Serve(listener)
	}()

	return proxy, nil
}

func (m *ProxyManager) serveDockerSocketProxy(w http.ResponseWriter, req *http.Request, sandboxID string, policy *compiledDockerSocketPolicy, client *http.Client) {
	meta := mapDockerRequest(req.Method, req.URL.Path)
	mode := m.policyModeForSandbox(sandboxID)
	event := accessEvent{
		SandboxID: sandboxID,
		Kind:      "docker_socket",
		Method:    strings.ToUpper(strings.TrimSpace(req.Method)),
		Path:      meta.Path,
		Host:      "docker",
		Port:      0,
	}

	if meta.Operation == DockerOperation("unknown") {
		m.writeDockerSocketDenied(w, dockerSocketEventWithPolicy(event, mode, false, fmt.Sprintf("docker endpoint %q is not supported", meta.Path)), http.StatusForbidden)
		return
	}
	if !isPhase1DockerOperationSupported(meta.Operation) {
		m.writeDockerSocketDenied(w, dockerSocketEventWithPolicy(event, mode, false, fmt.Sprintf("docker operation %q is not supported in phase 1", meta.Operation)), http.StatusForbidden)
		return
	}

	inspectBody := requiresDockerSocketRequestInspection(meta.Operation)
	var (
		body    []byte
		outBody io.Reader
		err     error
	)
	if inspectBody {
		var tooLarge bool
		body, tooLarge, err = readBoundedResponse(req.Body, m.requestBodyLimitBytes)
		if err != nil {
			m.writeDockerSocketDenied(w, dockerSocketEventWithPolicy(event, mode, false, fmt.Sprintf("read docker request body: %v", err)), http.StatusForbidden)
			return
		}
		if tooLarge {
			m.writeDockerSocketDenied(w, dockerSocketEventWithPolicy(event, mode, false, "docker request body exceeds inspection limit"), http.StatusRequestEntityTooLarge)
			return
		}
		outBody = bytes.NewReader(body)
	} else {
		outBody = req.Body
	}

	var buildReq *dockerBuildRequest
	if meta.Operation == DockerOperation("build") {
		inspected, err := inspectDockerBuildRequest(req, body)
		if err != nil {
			m.writeDockerSocketDenied(w, dockerSocketEventWithPolicy(event, mode, false, err.Error()), http.StatusForbidden)
			return
		}
		buildReq = &inspected
	}

	decision := policy.evaluate(dockerSocketRequest{
		Method:    meta.Method,
		Path:      meta.Path,
		Operation: meta.Operation,
		Build:     buildReq,
	})
	policyAllowed := decision == DockerRuleActionAllow
	event = dockerSocketEventWithPolicy(event, mode, policyAllowed, fmt.Sprintf("docker operation %q is not allowed by policy", meta.Operation))
	if !policyAllowed && mode != PolicyModeAudit {
		m.writeDockerSocketDenied(w, event, http.StatusForbidden)
		return
	}

	targetURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}
	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, targetURL.String(), outBody)
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		m.recordAccessEvent(event)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	outReq.Header = req.Header.Clone()
	stripHopByHopHeaders(outReq.Header)
	outReq.Host = req.Host
	if !inspectBody {
		outReq.ContentLength = req.ContentLength
	}

	resp, err := client.Do(outReq)
	if err != nil {
		event.Allowed = true
		event.Result = "upstream_error"
		event.Error = err.Error()
		m.recordAccessEvent(event)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := writeDockerSocketUpstreamResponse(w, resp); err != nil {
		event.Allowed = true
		event.StatusCode = resp.StatusCode
		event.Result = "upstream_error"
		event.Error = err.Error()
		m.recordAccessEvent(event)
		return
	}

	event.Allowed = true
	event.StatusCode = resp.StatusCode
	event.Result = "allowed"
	event.Error = ""
	m.recordAccessEvent(event)
}

func dockerSocketEventWithPolicy(event accessEvent, mode PolicyMode, allowed bool, reason string) accessEvent {
	event.PolicyMode = normalizedPolicyModeOrDefault(mode)
	event.PolicyAllowed = allowed
	if !allowed && strings.TrimSpace(reason) != "" {
		event.PolicyViolations = []string{reason}
	}
	return event
}

func isPhase1DockerOperationSupported(op DockerOperation) bool {
	switch normalizeDockerOperation(string(op)) {
	case DockerOperation("image_pull"), DockerOperation("image_inspect"), DockerOperation("build"):
		return true
	default:
		return false
	}
}

func (m *ProxyManager) writeDockerSocketDenied(w http.ResponseWriter, event accessEvent, statusCode int) {
	if event.StatusCode == 0 {
		event.StatusCode = statusCode
	}
	event.Allowed = false
	event.Result = "denied"
	if event.Error == "" && len(event.PolicyViolations) > 0 {
		event.Error = event.PolicyViolations[0]
	}
	m.recordAccessEvent(event)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, "docker request denied: "+event.Error+"\n")
}

func requiresDockerSocketRequestInspection(op DockerOperation) bool {
	switch normalizeDockerOperation(string(op)) {
	case DockerOperation("build"):
		return true
	default:
		return false
	}
}

func writeDockerSocketUpstreamResponse(w http.ResponseWriter, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body == nil {
		return nil
	}
	_, err := io.Copy(w, resp.Body)
	return err
}

func stripHopByHopHeaders(header http.Header) {
	if header == nil {
		return
	}

	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(token)
			if trimmed == "" {
				continue
			}
			header.Del(textproto.CanonicalMIMEHeaderKey(trimmed))
		}
	}

	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func sanitizeDockerSocketSandboxID(sandboxID string) string {
	trimmed := strings.TrimSpace(sandboxID)
	if trimmed == "" {
		return "sandbox"
	}

	var b strings.Builder
	lastDash := false
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	sanitized := strings.Trim(b.String(), "-_.")
	if sanitized == "" {
		return "sandbox"
	}
	if len(sanitized) > 48 {
		return sanitized[:48]
	}
	return sanitized
}
