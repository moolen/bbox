package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestTransparentHTTPSWithCurl(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePortsStrict(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTransparentTLSTestServer(t, "secure.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "secure.localhost" {
			t.Fatalf("unexpected host: %q", r.Host)
		}
		switch r.URL.Path {
		case "/allowed":
			_, _ = w.Write([]byte("transparent https ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

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
		Name:        "transparent-https",
		Binaries:    []string{curlPath},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^secure[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/allowed$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent HTTPS sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close transparent HTTPS sandbox: %v", err)
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
		"https://secure.localhost/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("transparent HTTPS curl failed: %v", err)
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected transparent HTTPS curl to succeed, exit=%d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "transparent https ok\n200" {
		t.Fatalf("unexpected transparent HTTPS output: %q", got)
	}

	deniedResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"https://secure.localhost/blocked",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("blocked transparent HTTPS curl failed: %v", err)
	}
	if deniedResult.ExitCode != 0 {
		t.Fatalf("expected blocked transparent HTTPS request to return an HTTP response, exit=%d stderr=%q", deniedResult.ExitCode, string(deniedResult.Stderr))
	}
	deniedOutput := strings.TrimSpace(string(deniedResult.Stdout))
	if !strings.Contains(deniedOutput, "proxy request denied: path \"/blocked\" is not allowed by policy") {
		t.Fatalf("unexpected blocked transparent HTTPS output: %q", deniedOutput)
	}
	if !strings.HasSuffix(deniedOutput, "403") {
		t.Fatalf("expected blocked transparent HTTPS request to receive HTTP 403, got %q", deniedOutput)
	}
}

func TestTransparentModeRejectsIPLiteralAndNonDefaultPorts(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePortsStrict(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

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
		Name:        "transparent-unsupported",
		Binaries:    []string{curlPath},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^secure[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/allowed$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent limitation sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close transparent limitation sandbox: %v", err)
		}
	}()

	ipLiteralResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"--connect-timeout", "5",
		"--max-time", "10",
		"https://127.0.0.1/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("run IP-literal transparent curl: %v", err)
	}
	if ipLiteralResult.ExitCode == 0 {
		t.Fatalf("expected IP-literal transparent HTTPS request to fail, stdout=%q stderr=%q", string(ipLiteralResult.Stdout), string(ipLiteralResult.Stderr))
	}

	nonDefaultPortResult, err := sandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"--connect-timeout", "5",
		"--max-time", "10",
		"https://secure.localhost:8443/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("run non-default-port transparent curl: %v", err)
	}
	if nonDefaultPortResult.ExitCode == 0 {
		t.Fatalf("expected non-default-port transparent HTTPS request to fail, stdout=%q stderr=%q", string(nonDefaultPortResult.Stdout), string(nonDefaultPortResult.Stderr))
	}
}

func TestProxyAndTransparentSandboxesCanRunConcurrently(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePortsStrict(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("proxy mode ok"))
	}))
	defer proxyServer.Close()

	transparentServer := startTransparentHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "allowed.localhost" {
			t.Fatalf("unexpected transparent host: %q", r.Host)
		}
		if r.URL.Path != "/transparent" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("transparent mode ok"))
	}))
	defer transparentServer.Close()

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

	proxySandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "proxy-concurrent",
		Binaries: []string{curlPath},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/proxy$`},
		},
	})
	if err != nil {
		t.Fatalf("create proxy sandbox: %v", err)
	}
	defer func() {
		if err := proxySandbox.Close(); err != nil {
			t.Fatalf("close proxy sandbox: %v", err)
		}
	}()

	transparentSandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:        "transparent-concurrent",
		Binaries:    []string{curlPath},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^allowed[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/transparent$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent sandbox: %v", err)
	}
	defer func() {
		if err := transparentSandbox.Close(); err != nil {
			t.Fatalf("close transparent sandbox: %v", err)
		}
	}()

	type outcome struct {
		name   string
		result *bbox.RunResult
		err    error
	}

	outcomes := make(chan outcome, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		result, err := proxySandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			proxyServer.URL + "/proxy",
		}, bbox.RunOptions{})
		outcomes <- outcome{name: "proxy", result: result, err: err}
	}()

	go func() {
		defer wg.Done()
		result, err := transparentSandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			"http://allowed.localhost/transparent",
		}, bbox.RunOptions{})
		outcomes <- outcome{name: "transparent", result: result, err: err}
	}()

	wg.Wait()
	close(outcomes)

	got := make(map[string]outcome, 2)
	for outcome := range outcomes {
		got[outcome.name] = outcome
	}

	if got["proxy"].err != nil {
		t.Fatalf("proxy-mode curl failed: %v", got["proxy"].err)
	}
	if got["proxy"].result == nil || got["proxy"].result.ExitCode != 0 {
		t.Fatalf("expected proxy-mode curl to succeed, result=%#v", got["proxy"].result)
	}
	if body := strings.TrimSpace(string(got["proxy"].result.Stdout)); body != "proxy mode ok\n200" {
		t.Fatalf("unexpected proxy-mode output: %q", body)
	}

	if got["transparent"].err != nil {
		t.Fatalf("transparent-mode curl failed: %v", got["transparent"].err)
	}
	if got["transparent"].result == nil || got["transparent"].result.ExitCode != 0 {
		t.Fatalf("expected transparent-mode curl to succeed, result=%#v", got["transparent"].result)
	}
	if body := strings.TrimSpace(string(got["transparent"].result.Stdout)); body != "transparent mode ok\n200" {
		t.Fatalf("unexpected transparent-mode output: %q", body)
	}
}
