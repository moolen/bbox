package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestTransparentHTTPWithCurl(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePorts(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTransparentHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "allowed.localhost" {
			t.Fatalf("unexpected host: %q", r.Host)
		}
		if r.URL.Path != "/allowed" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("transparent http ok"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM: bbox.MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 1024,
		},
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
		Name:        "transparent-http",
		Binaries:    []string{curlPath},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^allowed[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/allowed$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent HTTP sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close transparent HTTP sandbox: %v", err)
		}
	}()

	if got := sandbox.ProxyURL(); got != "" {
		t.Fatalf("expected transparent sandbox proxy URL to be empty, got %q", got)
	}

	allowedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"http://allowed.localhost/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("transparent HTTP curl failed: %v", err)
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected transparent HTTP curl to succeed, exit=%d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "transparent http ok\n200" {
		t.Fatalf("unexpected transparent HTTP output: %q", got)
	}

	deniedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"http://blocked.localhost/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("blocked transparent HTTP curl failed: %v", err)
	}
	if deniedResult.ExitCode != 0 {
		t.Fatalf("expected blocked transparent HTTP request to return an HTTP response, exit=%d stderr=%q", deniedResult.ExitCode, string(deniedResult.Stderr))
	}
	deniedOutput := strings.TrimSpace(string(deniedResult.Stdout))
	if !strings.Contains(deniedOutput, "proxy request denied: hostname blocked.localhost is not allowed by policy") {
		t.Fatalf("unexpected blocked transparent HTTP output: %q", deniedOutput)
	}
	if !strings.HasSuffix(deniedOutput, "403") {
		t.Fatalf("expected blocked transparent HTTP request to receive HTTP 403, got %q", deniedOutput)
	}
}
