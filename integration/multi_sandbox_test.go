package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestTwoSandboxesUseDifferentPolicies(t *testing.T) {
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
		_, _ = w.Write([]byte("proxied through bbox"))
	}))
	defer server.Close()

	targetURL := server.URL + "/ok"

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allowed, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "allowed",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^127[.]0[.]0[.]1$`},
					HTTPMethods:  []string{"GET"},
				},
			},
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
		Name:     "denied",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			Rules: []bbox.PolicyRule{
				{
					HostPatterns: []string{`^example[.]com$`},
					HTTPMethods:  []string{"GET"},
				},
			},
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

	type runOutcome struct {
		result *bbox.RunResult
		err    error
	}

	outcomes := make(chan struct {
		name string
		runOutcome
	}, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		result, err := allowed.Run(ctx, []string{curlPath, "-sS", "-o", "-", "-w", "\n%{http_code}\n", targetURL}, bbox.RunOptions{})
		outcomes <- struct {
			name string
			runOutcome
		}{name: "allowed", runOutcome: runOutcome{result: result, err: err}}
	}()

	go func() {
		defer wg.Done()
		result, err := denied.Run(ctx, []string{curlPath, "-sS", "-o", "-", "-w", "\n%{http_code}\n", targetURL}, bbox.RunOptions{})
		outcomes <- struct {
			name string
			runOutcome
		}{name: "denied", runOutcome: runOutcome{result: result, err: err}}
	}()

	wg.Wait()
	close(outcomes)

	got := map[string]runOutcome{}
	for outcome := range outcomes {
		got[outcome.name] = outcome.runOutcome
	}

	allowedResult := got["allowed"]
	if allowedResult.err != nil {
		t.Fatalf("expected allowed sandbox to succeed, got error: %v", allowedResult.err)
	}
	if allowedResult.result == nil {
		t.Fatal("expected allowed sandbox result")
	}
	if allowedResult.result.ExitCode != 0 {
		t.Fatalf("expected allowed sandbox exit code 0, got %d, stderr=%q", allowedResult.result.ExitCode, string(allowedResult.result.Stderr))
	}
	if body := strings.TrimSpace(string(allowedResult.result.Stdout)); body != "proxied through bbox\n200" {
		t.Fatalf("unexpected allowed sandbox stdout: %q", body)
	}

	deniedResult := got["denied"]
	if deniedResult.err != nil {
		t.Fatalf("expected denied sandbox run transport to complete, got error: %v", deniedResult.err)
	}
	if deniedResult.result == nil {
		t.Fatal("expected denied sandbox result")
	}
	if deniedResult.result.ExitCode != 0 {
		t.Fatalf("expected denied sandbox HTTP response to complete, exit=%d stderr=%q", deniedResult.result.ExitCode, string(deniedResult.result.Stderr))
	}
	deniedOutput := strings.TrimSpace(string(deniedResult.result.Stdout))
	if !strings.Contains(deniedOutput, "proxy request denied: hostname 127.0.0.1 is not allowed by policy") {
		t.Fatalf("expected denial body to surface policy message, got %q", deniedOutput)
	}
	if !strings.HasSuffix(deniedOutput, "403") {
		t.Fatalf("expected denied sandbox to receive HTTP 403, got %q", deniedOutput)
	}
}

func requireTool(name string) (string, error) {
	t, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return t, nil
}
