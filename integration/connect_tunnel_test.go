package integration_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestConnectTunnelUsesDifferentConnectPolicies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap sandbox integration test requires linux")
	}
	if _, err := requireTool("bwrap"); err != nil {
		t.Skip(err.Error())
	}
	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("connect tunneled through bbox"))
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

	port := server.Listener.Addr().(*net.TCPAddr).Port

	allowed, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "allowed-connect",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{strconv.Itoa(port)},
		},
	})
	if err != nil {
		t.Fatalf("create allowed sandbox: %v", err)
	}
	defer func() {
		if err := allowed.Close(); err != nil {
			t.Fatalf("close allowed sandbox: %v", err)
		}
	}()

	denied, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "denied-connect",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowConnect:      true,
			AllowConnectPorts: []string{"443"},
		},
	})
	if err != nil {
		t.Fatalf("create denied sandbox: %v", err)
	}
	defer func() {
		if err := denied.Close(); err != nil {
			t.Fatalf("close denied sandbox: %v", err)
		}
	}()

	targetURL := fmt.Sprintf("http://127.0.0.1:%d/ok", port)

	allowedResult, err := allowed.Run(ctx, []string{
		curlPath,
		"--proxytunnel",
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("expected allowed tunnel to succeed, got error: %v", err)
	}
	if allowedResult == nil {
		t.Fatal("expected allowed sandbox result")
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected allowed tunnel exit code 0, got %d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "connect tunneled through bbox\n200" {
		t.Fatalf("unexpected allowed tunnel stdout: %q", got)
	}

	deniedResult, err := denied.Run(ctx, []string{
		curlPath,
		"--proxytunnel",
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetURL,
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("expected denied sandbox run transport to complete, got error: %v", err)
	}
	if deniedResult == nil {
		t.Fatal("expected denied sandbox result")
	}
	if deniedResult.ExitCode == 0 {
		t.Fatalf("expected denied tunnel to fail, got exit code 0 stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
	deniedCombined := strings.ToLower(string(deniedResult.Stdout) + "\n" + string(deniedResult.Stderr))
	if !strings.Contains(deniedCombined, "403") {
		t.Fatalf("expected denied tunnel stderr to report a CONNECT 403, got stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
	if strings.Contains(deniedCombined, "connect tunneled through bbox") {
		t.Fatalf("expected denied tunnel output to exclude success body, got stdout=%q stderr=%q", string(deniedResult.Stdout), string(deniedResult.Stderr))
	}
}
