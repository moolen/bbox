package integration_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

type recordingAccessLogger struct {
	mu      sync.Mutex
	entries []bbox.AccessLogEntry
}

func (r *recordingAccessLogger) LogAccess(entry bbox.AccessLogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry)
}

func (r *recordingAccessLogger) snapshot() []bbox.AccessLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := make([]bbox.AccessLogEntry, len(r.entries))
	copy(entries, r.entries)
	return entries
}

func findAccessedDomain(domains []bbox.AccessedDomain, host string) (bbox.AccessedDomain, bool) {
	for _, domain := range domains {
		if domain.Host == host {
			return domain, true
		}
	}
	return bbox.AccessedDomain{}, false
}

func findAccessLogEntry(entries []bbox.AccessLogEntry, kind string) (bbox.AccessLogEntry, bool) {
	for _, entry := range entries {
		if entry.Kind == kind {
			return entry, true
		}
	}
	return bbox.AccessLogEntry{}, false
}

func findAccessedHostSummary(hosts []bbox.AccessedHostSummary, host string) (bbox.AccessedHostSummary, bool) {
	for _, summary := range hosts {
		if summary.Host == host {
			return summary, true
		}
	}
	return bbox.AccessedHostSummary{}, false
}

func findRequestAggregate(rows []bbox.RequestAggregate, kind, host string, port int, method, path string) (bbox.RequestAggregate, bool) {
	for _, row := range rows {
		if row.Kind == kind && row.Host == host && row.Port == port && row.Method == method && row.Path == path {
			return row, true
		}
	}
	return bbox.RequestAggregate{}, false
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()

	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("parse integer %q: %v", value, err)
	}
	return parsed
}

func findSandboxAccessLogEntry(entries []bbox.AccessLogEntry, sandboxID, kind string) (bbox.AccessLogEntry, bool) {
	for _, entry := range entries {
		if entry.SandboxID == sandboxID && entry.Kind == kind {
			return entry, true
		}
	}
	return bbox.AccessLogEntry{}, false
}

func startLoopbackDNSTestServerOnPort(t *testing.T, port int) *loopbackDNSServer {
	t.Helper()

	tcpListener, err := listenLoopbackPort(port)
	if err != nil {
		t.Skipf("DNS audit integration test requires binding 127.0.0.1:%d: %v", port, err)
	}
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Skipf("DNS audit integration test requires binding UDP 127.0.0.1:%d: %v", port, err)
	}

	server := &loopbackDNSServer{
		host: "127.0.0.1",
		port: port,
		udp:  udpConn,
		tcp:  tcpListener,
	}
	t.Cleanup(func() {
		_ = server.udp.Close()
		_ = server.tcp.Close()
	})

	go server.serveUDP()
	go server.serveTCP()

	return server
}

func TestSandboxAuditMode(t *testing.T) {
	requireSandboxPrereqs(t)

	t.Run("HTTP policy violation allowed in audit", func(t *testing.T) {
		curlPath, err := requireTool("curl")
		if err != nil {
			t.Skip(err.Error())
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ok" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("audit ok"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := &recordingAccessLogger{}
		manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
			AccessLogger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := manager.Close(); err != nil {
				t.Fatalf("close manager: %v", err)
			}
		}()

		portStr := mustPortForServer(t, server)
		sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
			Name:       "audit-http-mode",
			Binaries:   []string{curlPath},
			PolicyMode: bbox.PolicyModeAudit,
			Policy: bbox.NetworkPolicy{
				Rules: []bbox.PolicyRule{
					{
						HostPatterns: []string{`^127[.]0[.]0[.]1$`},
						HTTPMethods:  []string{http.MethodGet},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("create sandbox: %v", err)
		}
		defer func() {
			if err := sandbox.Close(); err != nil {
				t.Fatalf("close sandbox: %v", err)
			}
		}()

		targetURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)
		result, err := sandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			"-X", http.MethodPost,
			targetURL,
		}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("audit request failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected audit run result")
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected audit request to succeed, exit=%d stderr=%q", result.ExitCode, string(result.Stderr))
		}
		if got := strings.TrimSpace(string(result.Stdout)); got != "audit ok\n200" {
			t.Fatalf("unexpected audit stdout: %q", got)
		}

		entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "audit-http-mode", "http")
		if !ok {
			t.Fatalf("expected HTTP access log entry, got %#v", logger.snapshot())
		}
		if !entry.Allowed {
			t.Fatalf("expected runtime allow in audit mode, got %#v", entry)
		}
		if entry.PolicyAllowed {
			t.Fatalf("expected policy denial in audit mode, got %#v", entry)
		}
		if len(entry.PolicyViolations) == 0 {
			t.Fatalf("expected policy violation details, got %#v", entry)
		}
		if !strings.Contains(entry.PolicyViolations[0], "method POST is not allowed") {
			t.Fatalf("expected POST violation, got %#v", entry.PolicyViolations)
		}
	})

	t.Run("DNS policy violation allowed in audit", func(t *testing.T) {
		dnsClient := buildStaticTestClient(t, "dns-audit-client", `package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x04, 't', 'e', 's', 't',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}

	if _, err := conn.WriteTo(query, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	buf := make([]byte, 512)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if n < 12 || buf[0] != 0x12 || buf[1] != 0x34 || buf[2]&0x80 == 0 {
		fmt.Fprintf(os.Stderr, "unexpected DNS response: %x\n", buf[:n])
		os.Exit(1)
	}

	fmt.Println("dns ok")
}`)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := &recordingAccessLogger{}
		manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
			MITM:         bbox.MITMOptions{Enabled: true},
			AccessLogger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := manager.Close(); err != nil {
				t.Fatalf("close manager: %v", err)
			}
		}()

		sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
			Name:        "audit-dns-mode",
			Binaries:    []string{dnsClient},
			Mounts:      []bbox.Mount{{Source: filepath.Dir(dnsClient), Target: "/workspace", ReadOnly: true}},
			TrafficMode: bbox.TrafficModeTransparent,
			PolicyMode:  bbox.PolicyModeAudit,
			Policy: bbox.NetworkPolicy{
				Rules: []bbox.PolicyRule{
					{HostPatterns: []string{`^allowed[.]test$`}},
				},
			},
		})
		if err != nil {
			t.Fatalf("create sandbox: %v", err)
		}
		defer func() {
			if err := sandbox.Close(); err != nil {
				t.Fatalf("close sandbox: %v", err)
			}
		}()

		result, err := sandbox.Run(ctx, []string{"/workspace/" + filepath.Base(dnsClient)}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("audit dns lookup failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected audit DNS run result")
		}
		combinedOutput := strings.ToLower(string(result.Stdout) + "\n" + string(result.Stderr))
		if strings.Contains(combinedOutput, "dns request denied") || strings.Contains(combinedOutput, "not allowed by policy") {
			t.Fatalf("expected audit DNS path to avoid policy enforcement, got stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
		}

		entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "audit-dns-mode", "dns")
		if !ok {
			t.Fatalf("expected DNS access log entry, got %#v", logger.snapshot())
		}
		if !entry.Allowed {
			t.Fatalf("expected runtime allow in audit mode, got %#v", entry)
		}
		if entry.PolicyAllowed {
			t.Fatalf("expected policy denial in audit mode, got %#v", entry)
		}
		if len(entry.PolicyViolations) == 0 {
			t.Fatalf("expected policy violation details, got %#v", entry)
		}
		if !strings.Contains(entry.PolicyViolations[0], "hostname example.test is not allowed by policy") {
			t.Fatalf("expected DNS violation for example.test, got %#v", entry.PolicyViolations)
		}

		summary := sandbox.AccessSummary()
		hostSummary, ok := findAccessedHostSummary(summary.Hosts, "example.test")
		if !ok {
			t.Fatalf("expected DNS host summary for example.test, got %#v", summary.Hosts)
		}
		if !hostSummary.DNSSeen {
			t.Fatalf("expected DNS host summary to set DNSSeen, got %#v", hostSummary)
		}
		if hostSummary.PolicyDeniedCount != 1 {
			t.Fatalf("expected 1 policy-denied DNS attempt, got %d", hostSummary.PolicyDeniedCount)
		}
		if hostSummary.PolicyViolations != 1 {
			t.Fatalf("expected 1 DNS policy violation, got %#v", hostSummary)
		}

		requestSummary, ok := findRequestAggregate(summary.Requests, "dns", "example.test", 53, "", "")
		if !ok {
			t.Fatalf("expected DNS request summary, got %#v", summary.Requests)
		}
		if requestSummary.Attempts != 1 {
			t.Fatalf("expected 1 DNS attempt, got %d", requestSummary.Attempts)
		}
		if requestSummary.AllowedCount != 1 {
			t.Fatalf("expected 1 runtime-allowed DNS attempt, got %d", requestSummary.AllowedCount)
		}
		if requestSummary.PolicyDeniedCount != 1 {
			t.Fatalf("expected 1 policy-denied DNS attempt, got %d", requestSummary.PolicyDeniedCount)
		}
	})

	t.Run("CONNECT policy violation allowed in audit", func(t *testing.T) {
		curlPath, err := requireTool("curl")
		if err != nil {
			t.Skip(err.Error())
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ok" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("connect ok"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := &recordingAccessLogger{}
		manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
			AccessLogger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := manager.Close(); err != nil {
				t.Fatalf("close manager: %v", err)
			}
		}()

		portStr := mustPortForServer(t, server)
		port := mustAtoi(t, portStr)
		sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
			Name:       "audit-connect-mode",
			Binaries:   []string{curlPath},
			PolicyMode: bbox.PolicyModeAudit,
			Policy: bbox.NetworkPolicy{
				Rules: []bbox.PolicyRule{
					{
						HostPatterns: []string{`^127[.]0[.]0[.]1$`},
						ConnectPorts: []string{"443"},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("create sandbox: %v", err)
		}
		defer func() {
			if err := sandbox.Close(); err != nil {
				t.Fatalf("close sandbox: %v", err)
			}
		}()

		targetURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)
		result, err := sandbox.Run(ctx, []string{
			curlPath,
			"--proxytunnel",
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			targetURL,
		}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("audit CONNECT request failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected audit CONNECT run result")
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected audit CONNECT request to succeed, exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
		}
		if got := strings.TrimSpace(string(result.Stdout)); got != "connect ok\n200" {
			t.Fatalf("unexpected audit CONNECT stdout: %q", got)
		}

		entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "audit-connect-mode", "connect")
		if !ok {
			t.Fatalf("expected CONNECT access log entry, got %#v", logger.snapshot())
		}
		if !entry.Allowed {
			t.Fatalf("expected runtime allow in audit mode, got %#v", entry)
		}
		if entry.PolicyAllowed {
			t.Fatalf("expected policy denial in audit mode, got %#v", entry)
		}
		if len(entry.PolicyViolations) == 0 {
			t.Fatalf("expected policy violation details, got %#v", entry)
		}
		if !strings.Contains(entry.PolicyViolations[0], fmt.Sprintf("CONNECT port %d is not allowed", port)) {
			t.Fatalf("expected CONNECT port violation, got %#v", entry.PolicyViolations)
		}

		summary := sandbox.AccessSummary()
		requestSummary, ok := findRequestAggregate(summary.Requests, "connect", "127.0.0.1", port, http.MethodConnect, "")
		if !ok {
			t.Fatalf("expected CONNECT request summary, got %#v", summary.Requests)
		}
		if requestSummary.Attempts != 1 {
			t.Fatalf("expected 1 CONNECT attempt, got %d", requestSummary.Attempts)
		}
		if requestSummary.AllowedCount != 1 {
			t.Fatalf("expected 1 runtime-allowed CONNECT attempt, got %d", requestSummary.AllowedCount)
		}
		if requestSummary.PolicyDeniedCount != 1 {
			t.Fatalf("expected 1 policy-denied CONNECT attempt, got %d", requestSummary.PolicyDeniedCount)
		}
	})

	t.Run("enforce mode logs violation while still returning 403", func(t *testing.T) {
		curlPath, err := requireTool("curl")
		if err != nil {
			t.Skip(err.Error())
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ok" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte("enforce ok"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := &recordingAccessLogger{}
		manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
			AccessLogger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := manager.Close(); err != nil {
				t.Fatalf("close manager: %v", err)
			}
		}()

		portStr := mustPortForServer(t, server)
		sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
			Name:       "enforce-http-mode",
			Binaries:   []string{curlPath},
			PolicyMode: bbox.PolicyModeEnforce,
			Policy: bbox.NetworkPolicy{
				Rules: []bbox.PolicyRule{
					{
						HostPatterns: []string{`^127[.]0[.]0[.]1$`},
						HTTPMethods:  []string{http.MethodGet},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("create sandbox: %v", err)
		}
		defer func() {
			if err := sandbox.Close(); err != nil {
				t.Fatalf("close sandbox: %v", err)
			}
		}()

		targetURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)
		result, err := sandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			"-X", http.MethodPost,
			targetURL,
		}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("enforce request failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected enforce run result")
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected enforce request to return HTTP response, exit=%d stderr=%q", result.ExitCode, string(result.Stderr))
		}
		output := strings.TrimSpace(string(result.Stdout))
		if !strings.Contains(output, "proxy request denied") {
			t.Fatalf("expected denied response body, got %q", output)
		}
		if !strings.HasSuffix(output, "403") {
			t.Fatalf("expected denied response status 403, got %q", output)
		}

		entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "enforce-http-mode", "http")
		if !ok {
			t.Fatalf("expected enforce HTTP access log entry, got %#v", logger.snapshot())
		}
		if entry.Allowed {
			t.Fatalf("expected runtime denial in enforce mode, got %#v", entry)
		}
		if entry.PolicyAllowed {
			t.Fatalf("expected policy denial in enforce mode, got %#v", entry)
		}
		if len(entry.PolicyViolations) == 0 {
			t.Fatalf("expected policy violation details, got %#v", entry)
		}
		if !strings.Contains(entry.PolicyViolations[0], "method POST is not allowed") {
			t.Fatalf("expected POST violation, got %#v", entry.PolicyViolations)
		}
		if entry.StatusCode != http.StatusForbidden {
			t.Fatalf("expected logged status code 403, got %#v", entry)
		}
	})
}

func TestDockerAccessAuditMode(t *testing.T) {
	requireSandboxPrereqs(t)

	shPath, err := requireTool("sh")
	if err != nil {
		t.Skip(err.Error())
	}

	daemonSocketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %q", r.Method)
		}
		if r.URL.Path != "/v1.52/images/create" {
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
		if r.URL.RawQuery != "fromImage=busybox" {
			t.Fatalf("unexpected query: %q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := &recordingAccessLogger{}
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		AccessLogger: logger,
		DockerSocket: bbox.DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: daemonSocketPath,
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:       "audit-docker-mode",
		Binaries:   []string{shPath},
		PolicyMode: bbox.PolicyModeAudit,
		DockerSocket: bbox.DockerSocketOptions{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	if got := sandbox.DockerSocketMountPath(); got != "/var/run/docker.sock" {
		t.Fatalf("unexpected docker socket mount path: got %q", got)
	}
	proxyPath := sandbox.DockerSocketProxyPath()
	if proxyPath == "" {
		t.Fatal("expected docker socket proxy path")
	}

	resp := doUnixSocketRequest(t, proxyPath, http.MethodPost, "/v1.52/images/create?fromImage=busybox", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected docker proxy status: got %d want %d", resp.StatusCode, http.StatusCreated)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read docker proxy response body: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected docker proxy response body: %q", string(body))
	}

	entry, ok := findSandboxAccessLogEntry(logger.snapshot(), "audit-docker-mode", "docker_socket")
	if !ok {
		t.Fatalf("expected docker socket access log entry, got %#v", logger.snapshot())
	}
	if !entry.Allowed {
		t.Fatalf("expected audit-mode docker request to be allowed at runtime, got %#v", entry)
	}
	if entry.PolicyAllowed {
		t.Fatalf("expected audit-mode docker request to violate policy, got %#v", entry)
	}
	if entry.Path != "/images/create" {
		t.Fatalf("expected normalized docker path, got %q", entry.Path)
	}

	summary := sandbox.AccessSummary()
	row, ok := findRequestAggregate(summary.Requests, "docker_socket", "docker", 0, http.MethodPost, "/images/create")
	if !ok {
		t.Fatalf("expected docker request aggregate, got %#v", summary.Requests)
	}
	if row.AllowedCount != 1 || row.PolicyDeniedCount != 1 {
		t.Fatalf("unexpected docker request aggregate: %#v", row)
	}
}

func startUnixSocketHTTPServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	return socketPath
}

func doUnixSocketRequest(t *testing.T, socketPath, method, requestPath string, body io.Reader, header http.Header) *http.Response {
	t.Helper()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://docker"+requestPath, body)
	if err != nil {
		t.Fatalf("build unix socket request: %v", err)
	}
	if header != nil {
		req.Header = header.Clone()
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute unix socket request: %v", err)
	}
	return resp
}

func TestSandboxAccessSummary(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("summary ok"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	portStr := mustPortForServer(t, server)
	port := mustAtoi(t, portStr)
	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:       "access-summary",
		Binaries:   []string{curlPath},
		PolicyMode: bbox.PolicyModeAudit,
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{http.MethodGet},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	targetURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)
	for i := 0; i < 2; i++ {
		result, err := sandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			targetURL,
		}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("allowed request %d failed: %v", i+1, err)
		}
		if result == nil {
			t.Fatalf("expected allowed result for request %d", i+1)
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected allowed request %d to succeed, exit=%d stderr=%q", i+1, result.ExitCode, string(result.Stderr))
		}
		if got := strings.TrimSpace(string(result.Stdout)); got != "summary ok\n200" {
			t.Fatalf("unexpected allowed stdout for request %d: %q", i+1, got)
		}
	}

	auditResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("audit POST request failed: %v", err)
	}
	if auditResult == nil {
		t.Fatal("expected audit POST run result")
	}
	if auditResult.ExitCode != 0 {
		t.Fatalf("expected audit POST request to succeed, exit=%d stderr=%q", auditResult.ExitCode, string(auditResult.Stderr))
	}
	if got := strings.TrimSpace(string(auditResult.Stdout)); got != "summary ok\n200" {
		t.Fatalf("unexpected audit POST stdout: %q", got)
	}

	summary := sandbox.AccessSummary()
	if len(summary.Requests) != 2 {
		t.Fatalf("expected 2 grouped request entries, got %#v", summary.Requests)
	}

	hostSummary, ok := findAccessedHostSummary(summary.Hosts, "127.0.0.1")
	if !ok {
		t.Fatalf("expected host summary for 127.0.0.1, got %#v", summary.Hosts)
	}
	if hostSummary.Attempts != 3 {
		t.Fatalf("expected 3 host attempts, got %d", hostSummary.Attempts)
	}
	if hostSummary.PolicyAllowedCount != 2 {
		t.Fatalf("expected 2 policy-allowed host attempts, got %d", hostSummary.PolicyAllowedCount)
	}
	if hostSummary.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied host attempt, got %d", hostSummary.PolicyDeniedCount)
	}
	if hostSummary.PolicyViolations != 1 {
		t.Fatalf("expected 1 host policy violation, got %#v", hostSummary)
	}

	getSummary, ok := findRequestAggregate(summary.Requests, "http", "127.0.0.1", port, http.MethodGet, "/ok")
	if !ok {
		t.Fatalf("expected grouped GET request summary, got %#v", summary.Requests)
	}
	if getSummary.Attempts != 2 {
		t.Fatalf("expected 2 GET attempts, got %d", getSummary.Attempts)
	}
	if getSummary.AllowedCount != 2 || getSummary.DeniedCount != 0 {
		t.Fatalf("expected GET runtime counters 2/0, got %#v", getSummary)
	}
	if getSummary.PolicyAllowedCount != 2 || getSummary.PolicyDeniedCount != 0 {
		t.Fatalf("expected GET policy counters 2/0, got %#v", getSummary)
	}
	if getSummary.LastStatusCode != http.StatusOK {
		t.Fatalf("expected GET last status 200, got %#v", getSummary)
	}

	postSummary, ok := findRequestAggregate(summary.Requests, "http", "127.0.0.1", port, http.MethodPost, "/ok")
	if !ok {
		t.Fatalf("expected POST request summary, got %#v", summary.Requests)
	}
	if postSummary.Attempts != 1 {
		t.Fatalf("expected 1 POST attempt, got %d", postSummary.Attempts)
	}
	if postSummary.AllowedCount != 1 || postSummary.DeniedCount != 0 {
		t.Fatalf("expected POST runtime counters 1/0, got %#v", postSummary)
	}
	if postSummary.PolicyAllowedCount != 0 || postSummary.PolicyDeniedCount != 1 {
		t.Fatalf("expected POST policy counters 0/1, got %#v", postSummary)
	}
	if postSummary.LastStatusCode != http.StatusOK {
		t.Fatalf("expected POST last status 200, got %#v", postSummary)
	}
}

func TestSandboxAccessedDomainsTracksAllowedAndDeniedHTTPRequests(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("audit ok"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	portStr := mustPortForServer(t, server)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse server port %q: %v", portStr, err)
	}

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "audit-http",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{http.MethodGet},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	allowedURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)
	allowedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		allowedURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("allowed request failed: %v", err)
	}
	if allowedResult == nil {
		t.Fatal("expected allowed run result")
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected allowed exit code 0, got %d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "audit ok\n200" {
		t.Fatalf("unexpected allowed stdout: %q", got)
	}

	deniedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		allowedURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("denied request failed: %v", err)
	}
	if deniedResult == nil {
		t.Fatal("expected denied run result")
	}
	if deniedResult.ExitCode != 0 {
		t.Fatalf("expected denied request to return HTTP response, exit=%d stderr=%q", deniedResult.ExitCode, string(deniedResult.Stderr))
	}
	deniedOutput := strings.TrimSpace(string(deniedResult.Stdout))
	if !strings.Contains(deniedOutput, "proxy request denied") {
		t.Fatalf("expected denied output to mention policy denial, got %q", deniedOutput)
	}
	if !strings.HasSuffix(deniedOutput, "403") {
		t.Fatalf("expected denied request HTTP 403, got %q", deniedOutput)
	}

	domains := sandbox.AccessedDomains()
	if len(domains) == 0 {
		t.Fatal("expected accessed domains to contain entries")
	}
	domain, ok := findAccessedDomain(domains, "127.0.0.1")
	if !ok {
		t.Fatalf("expected accessed domains to include 127.0.0.1, got %#v", domains)
	}
	if domain.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", domain.Attempts)
	}
	if !domain.HTTPSeen {
		t.Fatalf("expected HTTP access flag to be set, got %#v", domain)
	}
	if domain.LastResult != "denied" {
		t.Fatalf("expected last result denied, got %q", domain.LastResult)
	}
	if !strings.Contains(domain.LastError, "method POST is not allowed") {
		t.Fatalf("expected last error to mention POST denial, got %q", domain.LastError)
	}
	if domain.LastPort != port {
		t.Fatalf("expected last port %d, got %d", port, domain.LastPort)
	}
}

func TestSandboxAuditModeAllowsDeniedHTTPRequestButLogsViolation(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("audit ok"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := &recordingAccessLogger{}
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		AccessLogger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	portStr := mustPortForServer(t, server)
	policy := bbox.NetworkPolicy{
		Rules: []bbox.PolicyRule{
			{
				HostPatterns: []string{`^127[.]0[.]0[.]1$`},
				HTTPMethods:  []string{http.MethodGet},
			},
		},
	}

	enforceSandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:       "enforce-http",
		Binaries:   []string{curlPath},
		PolicyMode: bbox.PolicyModeEnforce,
		Policy:     policy,
	})
	if err != nil {
		t.Fatalf("create enforce sandbox: %v", err)
	}
	defer func() {
		if err := enforceSandbox.Close(); err != nil {
			t.Fatalf("close enforce sandbox: %v", err)
		}
	}()

	auditSandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:       "audit-http",
		Binaries:   []string{curlPath},
		PolicyMode: bbox.PolicyModeAudit,
		Policy:     policy,
	})
	if err != nil {
		t.Fatalf("create audit sandbox: %v", err)
	}
	defer func() {
		if err := auditSandbox.Close(); err != nil {
			t.Fatalf("close audit sandbox: %v", err)
		}
	}()

	targetURL := fmt.Sprintf("http://127.0.0.1:%s/ok", portStr)

	enforceResult, err := enforceSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("enforce request failed: %v", err)
	}
	if enforceResult == nil {
		t.Fatal("expected enforce run result")
	}
	if enforceResult.ExitCode != 0 {
		t.Fatalf("expected enforce request to return HTTP response, exit=%d stderr=%q", enforceResult.ExitCode, string(enforceResult.Stderr))
	}
	enforceOutput := strings.TrimSpace(string(enforceResult.Stdout))
	if !strings.Contains(enforceOutput, "proxy request denied") {
		t.Fatalf("expected enforce output to mention policy denial, got %q", enforceOutput)
	}
	if !strings.HasSuffix(enforceOutput, "403") {
		t.Fatalf("expected enforce request HTTP 403, got %q", enforceOutput)
	}

	auditResult, err := auditSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("audit request failed: %v", err)
	}
	if auditResult == nil {
		t.Fatal("expected audit run result")
	}
	if auditResult.ExitCode != 0 {
		t.Fatalf("expected audit request to succeed, exit=%d stderr=%q", auditResult.ExitCode, string(auditResult.Stderr))
	}
	if got := strings.TrimSpace(string(auditResult.Stdout)); got != "audit ok\n200" {
		t.Fatalf("unexpected audit stdout: %q", got)
	}

	entries := logger.snapshot()
	enforceEntry, ok := findSandboxAccessLogEntry(entries, "enforce-http", "http")
	if !ok {
		t.Fatalf("expected enforce access log entry, got %#v", entries)
	}
	auditEntry, ok := findSandboxAccessLogEntry(entries, "audit-http", "http")
	if !ok {
		t.Fatalf("expected audit access log entry, got %#v", entries)
	}

	if enforceEntry.Allowed {
		t.Fatalf("expected enforce runtime denial, got %#v", enforceEntry)
	}
	if enforceEntry.PolicyAllowed {
		t.Fatalf("expected enforce policy denial, got %#v", enforceEntry)
	}
	if len(enforceEntry.PolicyViolations) == 0 {
		t.Fatalf("expected enforce policy violations, got %#v", enforceEntry)
	}
	if !strings.Contains(enforceEntry.PolicyViolations[0], "method POST is not allowed") {
		t.Fatalf("expected enforce denial reason, got %#v", enforceEntry.PolicyViolations)
	}

	if !auditEntry.Allowed {
		t.Fatalf("expected audit runtime allow, got %#v", auditEntry)
	}
	if auditEntry.PolicyAllowed {
		t.Fatalf("expected audit policy denial, got %#v", auditEntry)
	}
	if len(auditEntry.PolicyViolations) == 0 {
		t.Fatalf("expected audit policy violations, got %#v", auditEntry)
	}
	if !strings.Contains(auditEntry.PolicyViolations[0], "method POST is not allowed") {
		t.Fatalf("expected audit denial reason, got %#v", auditEntry.PolicyViolations)
	}

	summary := auditSandbox.AccessSummary()
	hostSummary, ok := findAccessedHostSummary(summary.Hosts, "127.0.0.1")
	if !ok {
		t.Fatalf("expected host summary for 127.0.0.1, got %#v", summary.Hosts)
	}
	if hostSummary.Attempts != 1 {
		t.Fatalf("expected 1 audit host attempt, got %d", hostSummary.Attempts)
	}
	if hostSummary.PolicyAllowedCount != 0 {
		t.Fatalf("expected 0 policy-allowed audit host attempts, got %d", hostSummary.PolicyAllowedCount)
	}
	if hostSummary.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied audit host attempt, got %d", hostSummary.PolicyDeniedCount)
	}
	if hostSummary.PolicyViolations == 0 {
		t.Fatalf("expected policy violations to be counted, got %#v", hostSummary)
	}

	requestSummary, ok := findRequestAggregate(summary.Requests, "http", "127.0.0.1", mustAtoi(t, portStr), http.MethodPost, "/ok")
	if !ok {
		t.Fatalf("expected request summary for audit POST /ok, got %#v", summary.Requests)
	}
	if requestSummary.Attempts != 1 {
		t.Fatalf("expected 1 audit request attempt, got %d", requestSummary.Attempts)
	}
	if requestSummary.AllowedCount != 1 {
		t.Fatalf("expected 1 runtime-allowed audit request, got %d", requestSummary.AllowedCount)
	}
	if requestSummary.DeniedCount != 0 {
		t.Fatalf("expected 0 runtime-denied audit requests, got %d", requestSummary.DeniedCount)
	}
	if requestSummary.PolicyAllowedCount != 0 {
		t.Fatalf("expected 0 policy-allowed audit requests, got %d", requestSummary.PolicyAllowedCount)
	}
	if requestSummary.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied audit request, got %d", requestSummary.PolicyDeniedCount)
	}
	if requestSummary.LastStatusCode != http.StatusOK {
		t.Fatalf("expected audit request status 200, got %d", requestSummary.LastStatusCode)
	}
}

func TestSandboxAccessedDomainsTracksConnectWhenMITMDenied(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("mitm ok"))
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MaxRequestBodyBytes: 1024,
		MITM:                bbox.MITMOptions{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	portStr := mustPortForServer(t, server)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse server port %q: %v", portStr, err)
	}

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "audit-mitm",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{portStr},
				},
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{http.MethodGet},
					PathPatterns: []string{`^/ok$`},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	deniedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		server.URL + "/blocked",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("blocked MITM request failed: %v", err)
	}
	if deniedResult == nil {
		t.Fatal("expected denied run result")
	}
	if deniedResult.ExitCode != 0 {
		t.Fatalf("expected blocked MITM request to return HTTP response, exit=%d stderr=%q", deniedResult.ExitCode, string(deniedResult.Stderr))
	}
	deniedOutput := strings.TrimSpace(string(deniedResult.Stdout))
	if !strings.Contains(deniedOutput, "proxy request denied") {
		t.Fatalf("expected blocked output to mention policy denial, got %q", deniedOutput)
	}
	if !strings.HasSuffix(deniedOutput, "403") {
		t.Fatalf("expected blocked MITM HTTP 403, got %q", deniedOutput)
	}

	domains := sandbox.AccessedDomains()
	if len(domains) == 0 {
		t.Fatal("expected accessed domains to contain entries")
	}
	domain, ok := findAccessedDomain(domains, "127.0.0.1")
	if !ok {
		t.Fatalf("expected accessed domains to include 127.0.0.1, got %#v", domains)
	}
	if domain.Attempts < 2 {
		t.Fatalf("expected at least 2 attempts (CONNECT + MITM), got %d", domain.Attempts)
	}
	if !domain.ConnectSeen {
		t.Fatalf("expected CONNECT attempt to be recorded, got %#v", domain)
	}
	if !domain.MITMSeen {
		t.Fatalf("expected MITM attempt to be recorded, got %#v", domain)
	}
	if domain.LastResult != "denied" {
		t.Fatalf("expected last result denied, got %q", domain.LastResult)
	}
	if domain.LastPort != port {
		t.Fatalf("expected last port %d, got %d", port, domain.LastPort)
	}
}

func TestSandboxInjectedAccessLoggerReceivesConnectAndMITMEntries(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("logger ok"))
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	logger := &recordingAccessLogger{}
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MaxRequestBodyBytes: 1024,
		MITM:                bbox.MITMOptions{Enabled: true},
		AccessLogger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	portStr := mustPortForServer(t, server)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse server port %q: %v", portStr, err)
	}

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "audit-logger",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					ConnectPorts: []string{portStr},
				},
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{http.MethodGet},
					PathPatterns: []string{`^/ok$`},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		server.URL + "/ok",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("MITM request failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected run result")
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected MITM request to succeed, exit=%d stderr=%q", result.ExitCode, string(result.Stderr))
	}
	if got := strings.TrimSpace(string(result.Stdout)); got != "logger ok\n200" {
		t.Fatalf("unexpected MITM stdout: %q", got)
	}

	entries := logger.snapshot()
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 access log entries, got %d", len(entries))
	}
	connectEntry, ok := findAccessLogEntry(entries, "connect")
	if !ok {
		t.Fatalf("expected a CONNECT access log entry, got %#v", entries)
	}
	mitmEntry, ok := findAccessLogEntry(entries, "mitm")
	if !ok {
		t.Fatalf("expected a MITM access log entry, got %#v", entries)
	}
	if connectEntry.SandboxID != "audit-logger" {
		t.Fatalf("expected connect entry sandbox id audit-logger, got %q", connectEntry.SandboxID)
	}
	if mitmEntry.SandboxID != "audit-logger" {
		t.Fatalf("expected mitm entry sandbox id audit-logger, got %q", mitmEntry.SandboxID)
	}
	if connectEntry.Host != "127.0.0.1" || mitmEntry.Host != "127.0.0.1" {
		t.Fatalf("expected host 127.0.0.1, got connect=%q mitm=%q", connectEntry.Host, mitmEntry.Host)
	}
	if connectEntry.Port != port || mitmEntry.Port != port {
		t.Fatalf("expected port %d, got connect=%d mitm=%d", port, connectEntry.Port, mitmEntry.Port)
	}
	if connectEntry.Kind != "connect" || mitmEntry.Kind != "mitm" {
		t.Fatalf("unexpected entry kinds connect=%q mitm=%q", connectEntry.Kind, mitmEntry.Kind)
	}
	if !connectEntry.Allowed || connectEntry.Result != "allowed" {
		t.Fatalf("expected connect entry allowed, got allowed=%v result=%q", connectEntry.Allowed, connectEntry.Result)
	}
	if !mitmEntry.Allowed || mitmEntry.Result != "allowed" {
		t.Fatalf("expected mitm entry allowed, got allowed=%v result=%q", mitmEntry.Allowed, mitmEntry.Result)
	}
	if mitmEntry.Path != "/ok" {
		t.Fatalf("expected mitm path /ok, got %q", mitmEntry.Path)
	}
	if mitmEntry.Method != http.MethodGet {
		t.Fatalf("expected mitm method GET, got %q", mitmEntry.Method)
	}
	if mitmEntry.StatusCode != http.StatusOK {
		t.Fatalf("expected mitm status 200, got %d", mitmEntry.StatusCode)
	}
}
