package bbox

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerSocketProxyDeniesUnknownEndpoint(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: filepath.Join(t.TempDir(), "daemon.sock"),
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodGet, "/v1.52/containers/json", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "docker request denied") {
		t.Fatalf("expected denial body, got %q", string(body))
	}
}

func TestDockerSocketProxyAllowsConfiguredImagePull(t *testing.T) {
	var gotPath string
	var gotQuery string
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("X-Docker-Upstream", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pulling"}`))
	}))

	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action:     DockerRuleActionAllow,
						Operations: []DockerOperation{"image_pull"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/images/create?fromImage=alpine%3Alatest", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusOK)
	}
	if gotPath != "/v1.52/images/create" {
		t.Fatalf("unexpected upstream path: got %q want %q", gotPath, "/v1.52/images/create")
	}
	if gotQuery != "fromImage=alpine%3Alatest" {
		t.Fatalf("unexpected upstream query: got %q", gotQuery)
	}
	if got := resp.Header.Get("X-Docker-Upstream"); got != "ok" {
		t.Fatalf("unexpected upstream header: %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != `{"status":"pulling"}` {
		t.Fatalf("unexpected response body: %q", string(body))
	}
}

func TestDockerSocketProxyStreamsImagePullResponsePastBodyLimit(t *testing.T) {
	responseBody := bytes.Repeat([]byte("x"), 4096)
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		MaxResponseBodyBytes: 32,
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action:     DockerRuleActionAllow,
						Operations: []DockerOperation{"image_pull"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/images/create?fromImage=alpine%3Alatest", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !bytes.Equal(body, responseBody) {
		t.Fatalf("unexpected streamed body length: got %d want %d", len(body), len(responseBody))
	}
}

func TestDockerSocketProxyStripsHopByHopHeaders(t *testing.T) {
	var gotConnection string
	var gotProxyConnection string
	var gotRequestHop string
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotProxyConnection = r.Header.Get("Proxy-Connection")
		gotRequestHop = r.Header.Get("X-Docker-Hop")

		w.Header().Set("Connection", "X-Docker-Hop-Response")
		w.Header().Set("X-Docker-Hop-Response", "secret")
		w.WriteHeader(http.StatusOK)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action:     DockerRuleActionAllow,
						Operations: []DockerOperation{"image_pull"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/images/create?fromImage=alpine%3Alatest", nil, http.Header{
		"Connection":       []string{"X-Docker-Hop"},
		"Proxy-Connection": []string{"keep-alive"},
		"X-Docker-Hop":     []string{"secret"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusOK)
	}
	if gotConnection != "" {
		t.Fatalf("expected request Connection header to be stripped, got %q", gotConnection)
	}
	if gotProxyConnection != "" {
		t.Fatalf("expected request Proxy-Connection header to be stripped, got %q", gotProxyConnection)
	}
	if gotRequestHop != "" {
		t.Fatalf("expected request hop-by-hop header to be stripped, got %q", gotRequestHop)
	}
	if got := resp.Header.Get("Connection"); got != "" {
		t.Fatalf("expected response Connection header to be stripped, got %q", got)
	}
	if got := resp.Header.Get("X-Docker-Hop-Response"); got != "" {
		t.Fatalf("expected response hop-by-hop header to be stripped, got %q", got)
	}
}

func TestDockerSocketProxyDeniesExecStart(t *testing.T) {
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionAllow,
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/exec/exec-123/start", strings.NewReader(`{"Detach":false}`), http.Header{
		"Content-Type": []string{"application/json"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "phase 1") && !strings.Contains(string(body), "exec_start") {
		t.Fatalf("expected phase-1 denial body, got %q", string(body))
	}
}

func TestDockerSocketProxyBuildRejectsOversizedInspectedRequestBody(t *testing.T) {
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		MaxRequestBodyBytes: 32,
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action:     DockerRuleActionAllow,
						Operations: []DockerOperation{"build"},
						Build: &DockerBuildMatch{
							Context: DockerBuildContextMatchLocalOnly,
							DockerfilePaths: []string{
								"^Dockerfile$",
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	body := bytes.Repeat(buildContextTar(t, "Dockerfile"), 8)
	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/build", bytes.NewReader(body), http.Header{
		"Content-Type": []string{"application/x-tar"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestDockerSocketProxyRecordsDockerAccessEvent(t *testing.T) {
	logger := &stubAccessLogger{}
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		AccessLogger: logger,
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
			Policy: DockerSocketPolicy{
				DefaultAction: DockerRuleActionDeny,
				Rules: []DockerSocketRule{
					{
						Action:     DockerRuleActionAllow,
						Operations: []DockerOperation{"image_pull"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/images/create?fromImage=busybox", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusAccepted)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "docker_socket" {
		t.Fatalf("expected docker_socket kind, got %q", entry.Kind)
	}
	if entry.Host != "docker" {
		t.Fatalf("expected docker host, got %q", entry.Host)
	}
	if entry.Port != 0 {
		t.Fatalf("expected docker port 0, got %d", entry.Port)
	}
	if entry.Method != http.MethodPost {
		t.Fatalf("expected POST method, got %q", entry.Method)
	}
	if entry.Path != "/images/create" {
		t.Fatalf("expected normalized docker path, got %q", entry.Path)
	}
	if !entry.Allowed {
		t.Fatalf("expected allowed access entry, got %#v", entry)
	}
	if entry.Result != "allowed" {
		t.Fatalf("expected allowed result, got %q", entry.Result)
	}
}

func TestDockerAccessAuditModeAllowsPolicyViolationAndRecordsIt(t *testing.T) {
	logger := &stubAccessLogger{}
	socketPath := startUnixSocketHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	manager, err := NewProxyManager(ProxyOptions{
		AccessLogger: logger,
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: socketPath,
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	sandbox := &Sandbox{policyMode: PolicyModeAudit}
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}
	if err := manager.attachSandbox("sandbox-a", sandbox); err != nil {
		t.Fatalf("attach sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	resp := doDockerSocketProxyRequest(t, proxy.listener.Addr().String(), http.MethodPost, "/v1.52/images/create?fromImage=busybox", nil, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusCreated)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if !entry.Allowed {
		t.Fatal("expected audit-mode docker request to be allowed at runtime")
	}
	if entry.PolicyMode != PolicyModeAudit {
		t.Fatalf("expected policy mode audit, got %q", entry.PolicyMode)
	}
	if entry.PolicyAllowed {
		t.Fatal("expected docker policy evaluation to be denied")
	}
	if len(entry.PolicyViolations) == 0 {
		t.Fatal("expected docker policy violation details to be recorded")
	}
}

func TestStartDockerSocketProxySanitizesSandboxIDForTempDir(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: filepath.Join(t.TempDir(), "daemon.sock"),
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	proxy, err := manager.startDockerSocketProxy("sandbox/../../name", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}
	defer proxy.Close()

	if strings.Contains(proxy.socketDir, "sandbox/../../name") {
		t.Fatalf("expected sanitized socket dir, got %q", proxy.socketDir)
	}
	if _, err := os.Stat(proxy.socketPath); err != nil {
		t.Fatalf("stat docker socket proxy path: %v", err)
	}
}

func TestProxyManagerSandboxCloseRemovesDockerSocketProxySocket(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: filepath.Join(t.TempDir(), "daemon.sock"),
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	proxy, err := manager.startDockerSocketProxy("sandbox-a", manager.dockerSocket, manager.dockerSocketPolicy)
	if err != nil {
		t.Fatalf("start docker socket proxy: %v", err)
	}

	socketPath := proxy.listener.Addr().String()
	sandbox := &Sandbox{
		manager:           manager,
		id:                "sandbox-a",
		root:              t.TempDir(),
		dockerSocketProxy: proxy,
		registered:        true,
		dockerSocketPath:  socketPath,
		dockerSocketMount: defaultDockerSocketMountPath,
	}
	if err := manager.attachSandbox("sandbox-a", sandbox); err != nil {
		t.Fatalf("attach sandbox: %v", err)
	}

	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("stat docker socket proxy path before close: %v", err)
	}

	if err := sandbox.Close(); err != nil {
		t.Fatalf("close sandbox: %v", err)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected docker socket proxy path to be removed, got err=%v", err)
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

func doDockerSocketProxyRequest(t *testing.T, socketPath, method, requestPath string, body io.Reader, header http.Header) *http.Response {
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
		t.Fatalf("build docker socket proxy request: %v", err)
	}
	if header != nil {
		req.Header = header.Clone()
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute docker socket proxy request: %v", err)
	}
	return resp
}
