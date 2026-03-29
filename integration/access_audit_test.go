package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowHTTPMethods:  []string{http.MethodGet},
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
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowHTTPMethods:  []string{http.MethodGet},
			AllowConnect:      true,
			AllowConnectPorts: []string{portStr},
			AllowPathPatterns: []string{`^/ok$`},
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
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
			AllowHTTPMethods:  []string{http.MethodGet},
			AllowConnect:      true,
			AllowConnectPorts: []string{portStr},
			AllowPathPatterns: []string{`^/ok$`},
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
