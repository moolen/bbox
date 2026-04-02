package bbox

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewSandboxDarwinRejectsTransparentMode(t *testing.T) {
	prevPlatform := sandboxPlatform
	sandboxPlatform = "darwin"
	t.Cleanup(func() {
		sandboxPlatform = prevPlatform
	})

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("NewProxyManager() error = %v", err)
	}
	defer manager.Close()

	_, err = manager.NewSandbox(context.Background(), SandboxOptions{
		TrafficMode: TrafficModeTransparent,
	})
	if err == nil {
		t.Fatal("expected transparent mode to fail on darwin")
	}
	if !strings.Contains(err.Error(), "transparent traffic mode is not supported on darwin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	return parsed
}

func TestNewSandboxDarwinRejectsMounts(t *testing.T) {
	prevPlatform := sandboxPlatform
	sandboxPlatform = "darwin"
	t.Cleanup(func() {
		sandboxPlatform = prevPlatform
	})

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("NewProxyManager() error = %v", err)
	}
	defer manager.Close()

	_, err = manager.NewSandbox(context.Background(), SandboxOptions{
		Mounts: []Mount{{Source: t.TempDir(), Target: "/workspace", ReadOnly: true}},
	})
	if err == nil {
		t.Fatal("expected mounts to fail on darwin")
	}
	if !strings.Contains(err.Error(), "mount_ro is not supported on darwin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSandboxDarwinRejectsSeccomp(t *testing.T) {
	prevPlatform := sandboxPlatform
	sandboxPlatform = "darwin"
	t.Cleanup(func() {
		sandboxPlatform = prevPlatform
	})

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("NewProxyManager() error = %v", err)
	}
	defer manager.Close()

	_, err = manager.NewSandbox(context.Background(), SandboxOptions{
		Seccomp: SeccompOptions{Profile: SeccompProfileRestricted},
	})
	if err == nil {
		t.Fatal("expected seccomp to fail on darwin")
	}
	if !strings.Contains(err.Error(), "seccomp is not supported on darwin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDarwinLaunchEnvStripsDYLDVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"FOO=bar",
		"DYLD_LIBRARY_PATH=/tmp/lib",
	}

	got := sanitizeDarwinEnv(env)
	want := []string{
		"PATH=/usr/bin:/bin",
		"FOO=bar",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sanitizeDarwinEnv() = %#v, want %#v", got, want)
	}
}

func TestGenerateDarwinProfileAllowsOnlyProxyLoopbackEndpoints(t *testing.T) {
	profile, err := generateDarwinSeatbeltProfile(darwinProfileConfig{
		WorkDir:          "/tmp/project",
		AllowedExecPaths: []string{"/usr/bin/env"},
		ProxyAddrs: []string{
			"127.0.0.1:31111",
			net.JoinHostPort("localhost", "40123"),
		},
	})
	if err != nil {
		t.Fatalf("generateDarwinSeatbeltProfile() error = %v", err)
	}

	for _, port := range []string{"31111", "40123"} {
		if !strings.Contains(profile, `remote ip "localhost:`+port+`"`) {
			t.Fatalf("expected loopback proxy port %s in profile, got:\n%s", port, profile)
		}
	}
	if strings.Contains(profile, "(allow network*)") {
		t.Fatalf("expected profile to avoid blanket network allow, got:\n%s", profile)
	}
	if strings.Contains(profile, `remote ip "localhost:*"`) {
		t.Fatalf("expected profile to avoid wildcard localhost outbound rules, got:\n%s", profile)
	}
}

func TestGenerateDarwinProfileTreatsBinAsExecAllowlist(t *testing.T) {
	profile, err := generateDarwinSeatbeltProfile(darwinProfileConfig{
		WorkDir: "/tmp/project",
		AllowedExecPaths: []string{
			"/usr/bin/git",
			"/usr/local/bin/opencode",
		},
	})
	if err != nil {
		t.Fatalf("generateDarwinSeatbeltProfile() error = %v", err)
	}

	for _, path := range []string{`"/usr/bin/git"`, `"/usr/local/bin/opencode"`} {
		if !strings.Contains(profile, "(allow process-exec") || !strings.Contains(profile, path) {
			t.Fatalf("expected exec allowlist entry for %s in profile, got:\n%s", path, profile)
		}
	}
}

func TestDarwinRuntimeRunUsesSandboxExecWithSanitizedEnv(t *testing.T) {
	workDir := t.TempDir()
	runtime := &darwinSandboxRuntime{
		proxyAddr: "127.0.0.1:31111",
		binaries:  []string{"/usr/bin/env"},
		workDir:   workDir,
	}

	var (
		gotName string
		gotArgs []string
		gotCmd  *exec.Cmd
	)
	prevExec := darwinExecCommandContext
	darwinExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		gotCmd = exec.CommandContext(ctx, "sh", "-c", "printf out; printf err >&2")
		return gotCmd
	}
	t.Cleanup(func() {
		darwinExecCommandContext = prevExec
	})

	result, err := runtime.Run(context.Background(), []string{"/usr/bin/env"}, RunOptions{
		Env: []string{
			"PATH=/usr/bin:/bin",
			"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
			"FOO=bar",
		},
		WorkDir: workDir,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 0 || string(result.Stdout) != "out" || string(result.Stderr) != "err" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if gotName != "sandbox-exec" {
		t.Fatalf("command name = %q, want sandbox-exec", gotName)
	}
	if len(gotArgs) < 3 || gotArgs[0] != "-p" || gotArgs[2] != "/usr/bin/env" {
		t.Fatalf("unexpected sandbox args: %#v", gotArgs)
	}
	for _, entry := range gotCmd.Env {
		if strings.HasPrefix(entry, "DYLD_") {
			t.Fatalf("unexpected DYLD entry in env: %#v", gotCmd.Env)
		}
	}
	if gotCmd.Dir != workDir {
		t.Fatalf("command dir = %q, want %q", gotCmd.Dir, workDir)
	}
}

func TestDarwinRuntimeInteractiveRunUsesSameSandboxLaunchPath(t *testing.T) {
	workDir := t.TempDir()
	runtime := &darwinSandboxRuntime{
		proxyAddr: "127.0.0.1:31111",
		binaries:  []string{"/bin/sh"},
		workDir:   workDir,
	}

	var (
		gotName string
		gotArgs []string
		stdout  strings.Builder
	)
	prevExec := darwinExecCommandContext
	darwinExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "sh", "-c", "cat")
	}
	t.Cleanup(func() {
		darwinExecCommandContext = prevExec
	})

	result, err := runtime.Run(context.Background(), []string{"/bin/sh"}, RunOptions{
		Env:         []string{"PATH=/bin:/usr/bin"},
		WorkDir:     workDir,
		Interactive: true,
		Stdin:       strings.NewReader("hello"),
		Stdout:      &stdout,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if stdout.String() != "hello" {
		t.Fatalf("interactive stdout = %q, want hello", stdout.String())
	}
	if gotName != "sandbox-exec" {
		t.Fatalf("command name = %q, want sandbox-exec", gotName)
	}
	if len(gotArgs) < 3 || gotArgs[0] != "-p" || gotArgs[2] != "/bin/sh" {
		t.Fatalf("unexpected sandbox args: %#v", gotArgs)
	}
}

func TestDarwinRuntimeProxyURLUsesManagerProxyAddr(t *testing.T) {
	runtime := &darwinSandboxRuntime{proxyAddr: "127.0.0.1:40123"}
	if got := runtime.ProxyAddr(); got != "127.0.0.1:40123" {
		t.Fatalf("ProxyAddr() = %q, want 127.0.0.1:40123", got)
	}
}

func TestNewSandboxDarwinProxyModeRoutesHTTPViaHostHelper(t *testing.T) {
	prevPlatform := sandboxPlatform
	sandboxPlatform = "darwin"
	t.Cleanup(func() {
		sandboxPlatform = prevPlatform
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	manager, err := NewProxyManager(ProxyOptions{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewProxyManager() error = %v", err)
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(context.Background(), SandboxOptions{
		Binaries: []string{"/bin/sh"},
		WorkDir:  t.TempDir(),
		Policy: NetworkPolicy{
			Rules: []PolicyRule{
				{IPCIDRs: []string{"127.0.0.0/8"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewSandbox() error = %v", err)
	}
	defer sandbox.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, sandbox.ProxyURL())),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("proxy GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected proxy response: status=%d body=%q", resp.StatusCode, string(body))
	}
}

func TestDarwinSandboxAllowsLoopbackHTTPViaProxy(t *testing.T) {
	requireDarwinSmokePrereqs(t)

	server := newLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))

	sandbox := newDarwinSmokeSandbox(t, NetworkPolicy{
		Rules: []PolicyRule{
			{IPCIDRs: []string{"127.0.0.0/8"}, HTTPMethods: []string{"GET"}},
		},
	})

	result, err := runDarwinSmokeCurl(t, sandbox, server.URL)
	if err != nil {
		t.Fatalf("runDarwinSmokeCurl() error = %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected allowed proxied curl to succeed, exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}
	if strings.TrimSpace(string(result.Stdout)) != "ok" {
		t.Fatalf("unexpected proxied curl stdout: %q", string(result.Stdout))
	}

	summary := sandbox.AccessSummary()
	if !hasRequestAggregate(summary.Requests, "127.0.0.1", 1, 0) {
		t.Fatalf("expected allowed proxied request in summary, got %#v", summary.Requests)
	}
}

func TestDarwinSandboxBlocksDirectLoopbackHTTP(t *testing.T) {
	requireDarwinSmokePrereqs(t)

	server := newLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))

	sandbox := newDarwinSmokeSandbox(t, NetworkPolicy{
		Rules: []PolicyRule{
			{IPCIDRs: []string{"127.0.0.0/8"}, HTTPMethods: []string{"GET"}},
		},
	})

	result, err := runDarwinSmokeCurl(t, sandbox, server.URL,
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"ALL_PROXY=",
		"all_proxy=",
		"NO_PROXY=*",
		"no_proxy=*",
	)
	if err != nil {
		t.Fatalf("runDarwinSmokeCurl() error = %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("expected direct curl to be blocked by seatbelt, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}

	summary := sandbox.AccessSummary()
	if len(summary.Requests) != 0 {
		t.Fatalf("expected direct-blocked request to bypass bbox proxy accounting, got %#v", summary.Requests)
	}
}

func TestDarwinSandboxDeniesLoopbackHTTPViaProxyWithoutRule(t *testing.T) {
	requireDarwinSmokePrereqs(t)

	server := newLoopbackHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))

	sandbox := newDarwinSmokeSandbox(t, NetworkPolicy{})

	result, err := runDarwinSmokeCurl(t, sandbox, server.URL)
	if err != nil {
		t.Fatalf("runDarwinSmokeCurl() error = %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("expected proxied curl without allow rule to fail, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}

	summary := sandbox.AccessSummary()
	if !hasRequestAggregate(summary.Requests, "127.0.0.1", 0, 1) {
		t.Fatalf("expected denied proxied request in summary, got %#v", summary.Requests)
	}
}

func requireDarwinSmokePrereqs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("darwin smoke test")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("curl not available")
	}
}

func newDarwinSmokeSandbox(t *testing.T, policy NetworkPolicy) *Sandbox {
	t.Helper()

	manager, err := NewProxyManager(ProxyOptions{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewProxyManager() error = %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("Close() manager error = %v", err)
		}
	})

	sandbox, err := manager.NewSandbox(context.Background(), SandboxOptions{
		Binaries: []string{"/usr/bin/curl"},
		WorkDir:  t.TempDir(),
		Policy:   policy,
	})
	if err != nil {
		t.Fatalf("NewSandbox() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("Close() sandbox error = %v", err)
		}
	})

	return sandbox
}

func runDarwinSmokeCurl(t *testing.T, sandbox *Sandbox, rawURL string, env ...string) (*RunResult, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return sandbox.Run(ctx, []string{
		"/usr/bin/curl",
		"-q",
		"--max-time", "5",
		"-fsS",
		rawURL,
	}, RunOptions{
		Env: env,
	})
}

func newLoopbackHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func hasRequestAggregate(requests []RequestAggregate, host string, minAllowed int, minDenied int) bool {
	for _, req := range requests {
		if req.Host != host {
			continue
		}
		if req.AllowedCount >= minAllowed && req.DeniedCount >= minDenied {
			return true
		}
	}
	return false
}
