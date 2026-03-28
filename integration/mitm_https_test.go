package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestSandboxMITMHTTPSWithCurl(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/allowed":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("mitm ok"))
		case "/submit":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("posted:" + r.Header.Get("X-Mode")))
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
			MaxRequestBodyBytes: 8,
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

	port := mustPortForServer(t, server)
	targetBase := server.URL

	allowPolicy := bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
		AllowHTTPMethods:  []string{"GET", "POST"},
		AllowConnect:      true,
		AllowConnectPorts: []string{port},
		AllowPathPatterns: []string{`^/allowed$`},
	}

	allowSandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "mitm-curl-allow",
		Binaries: []string{curlPath},
		Policy:   allowPolicy,
	})
	if err != nil {
		t.Fatalf("create allow sandbox: %v", err)
	}
	defer func() {
		if err := allowSandbox.Close(); err != nil {
			t.Fatalf("close allow sandbox: %v", err)
		}
	}()

	allowedResult, err := allowSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetBase + "/allowed",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("allowed HTTPS curl failed: %v", err)
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected allowed HTTPS curl to succeed, exit=%d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "mitm ok\n200" {
		t.Fatalf("unexpected allowed HTTPS output: %q", got)
	}

	deniedPathResult, err := allowSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		targetBase + "/blocked",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("blocked path curl failed: %v", err)
	}
	if deniedPathResult.ExitCode != 0 {
		t.Fatalf("expected blocked path to return HTTP response, exit=%d stderr=%q", deniedPathResult.ExitCode, string(deniedPathResult.Stderr))
	}
	deniedPathOutput := strings.TrimSpace(string(deniedPathResult.Stdout))
	if !strings.Contains(deniedPathOutput, "proxy request denied: path \"/blocked\" is not allowed by policy") {
		t.Fatalf("unexpected blocked path output: %q", deniedPathOutput)
	}
	if !strings.HasSuffix(deniedPathOutput, "403") {
		t.Fatalf("expected blocked path HTTP 403, got %q", deniedPathOutput)
	}

	requestPolicy := bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
		AllowHTTPMethods:  []string{"POST"},
		AllowConnect:      true,
		AllowConnectPorts: []string{port},
		AllowPathPatterns: []string{`^/submit$`},
		DenyHeaderPatterns: map[string][]string{
			"X-Mode": {`^blocked$`},
		},
		AllowBodyPatterns: []string{`^safe=`},
	}

	requestSandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "mitm-curl-request-policy",
		Binaries: []string{curlPath},
		Policy:   requestPolicy,
	})
	if err != nil {
		t.Fatalf("create request policy sandbox: %v", err)
	}
	defer func() {
		if err := requestSandbox.Close(); err != nil {
			t.Fatalf("close request policy sandbox: %v", err)
		}
	}()

	deniedHeaderResult, err := requestSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		"-H", "X-Mode: blocked",
		"--data", "safe=yes",
		targetBase + "/submit",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("blocked header curl failed: %v", err)
	}
	if deniedHeaderResult.ExitCode != 0 {
		t.Fatalf("expected blocked header to return HTTP response, exit=%d stderr=%q", deniedHeaderResult.ExitCode, string(deniedHeaderResult.Stderr))
	}
	deniedHeaderOutput := strings.TrimSpace(string(deniedHeaderResult.Stdout))
	if !strings.Contains(deniedHeaderOutput, "proxy request denied: header x-mode is denied by policy") {
		t.Fatalf("unexpected blocked header output: %q", deniedHeaderOutput)
	}
	if !strings.HasSuffix(deniedHeaderOutput, "403") {
		t.Fatalf("expected blocked header HTTP 403, got %q", deniedHeaderOutput)
	}

	tooLargeResult, err := requestSandbox.Run(ctx, []string{
		curlPath,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		"-X", http.MethodPost,
		"-H", "X-Mode: safe",
		"--data", "safe=0123456789",
		targetBase + "/submit",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("oversized body curl failed: %v", err)
	}
	if tooLargeResult.ExitCode != 0 {
		t.Fatalf("expected oversized body to return HTTP response, exit=%d stderr=%q", tooLargeResult.ExitCode, string(tooLargeResult.Stderr))
	}
	tooLargeOutput := strings.TrimSpace(string(tooLargeResult.Stdout))
	if !strings.Contains(tooLargeOutput, "proxy request denied: request body exceeds inspection limit") {
		t.Fatalf("unexpected oversized body output: %q", tooLargeOutput)
	}
	if !strings.HasSuffix(tooLargeOutput, "413") {
		t.Fatalf("expected oversized body HTTP 413, got %q", tooLargeOutput)
	}
}

func TestMITMSharedManagerServesMultipleSandboxes(t *testing.T) {
	requireSandboxPrereqs(t)

	curlPath, err := requireTool("curl")
	if err != nil {
		t.Skip(err.Error())
	}

	server := startTrustedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shared" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("shared-manager"))
	}))
	defer server.Close()
	trustHTTPSServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true, MaxRequestBodyBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	policy := bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
		AllowHTTPMethods:  []string{"GET"},
		AllowConnect:      true,
		AllowConnectPorts: []string{mustPortForServer(t, server)},
		AllowPathPatterns: []string{`^/shared$`},
	}

	alpha, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "mitm-alpha",
		Binaries: []string{curlPath},
		Policy:   policy,
	})
	if err != nil {
		t.Fatalf("create alpha sandbox: %v", err)
	}
	defer func() {
		if err := alpha.Close(); err != nil {
			t.Fatalf("close alpha sandbox: %v", err)
		}
	}()

	beta, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "mitm-beta",
		Binaries: []string{curlPath},
		Policy:   policy,
	})
	if err != nil {
		t.Fatalf("create beta sandbox: %v", err)
	}
	defer func() {
		if err := beta.Close(); err != nil {
			t.Fatalf("close beta sandbox: %v", err)
		}
	}()

	for name, sandbox := range map[string]*bbox.Sandbox{
		"alpha": alpha,
		"beta":  beta,
	} {
		result, err := sandbox.Run(ctx, []string{
			curlPath,
			"-sS",
			"-o", "-",
			"-w", "\n%{http_code}\n",
			server.URL + "/shared",
		}, bbox.RunOptions{})
		if err != nil {
			t.Fatalf("%s sandbox HTTPS curl failed: %v", name, err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("%s sandbox expected exit 0, got %d stderr=%q", name, result.ExitCode, string(result.Stderr))
		}
		if got := strings.TrimSpace(string(result.Stdout)); got != "shared-manager\n200" {
			t.Fatalf("%s sandbox unexpected output: %q", name, got)
		}
	}
}
