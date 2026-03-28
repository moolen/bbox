package bbox

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestProxyManagerRegistryLifecycle(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	manager := newProxyManager(policy)
	if err := manager.registerSandbox("sandbox-1", nil); err != nil {
		t.Fatalf("expected first sandbox registration to succeed: %v", err)
	}
	if err := manager.registerSandbox("sandbox-1", nil); err == nil {
		t.Fatal("expected duplicate sandbox registration to fail")
	}

	registeredPolicy, ok := manager.policyForSandbox("sandbox-1")
	if !ok {
		t.Fatal("expected registered sandbox policy lookup to succeed")
	}
	if registeredPolicy != policy {
		t.Fatal("expected default manager policy to be registered for sandbox")
	}

	manager.unregisterSandbox("sandbox-1")
	if _, ok := manager.policyForSandbox("sandbox-1"); ok {
		t.Fatal("expected sandbox policy lookup to fail after unregister")
	}
}

func TestProxyManagerCACertPEMReturnsParseableCertificateWhenMITMEnabled(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		MITM: MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 65536,
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	block, _ := pem.Decode(manager.CACertPEM())
	if block == nil {
		t.Fatal("expected CA PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse manager CA cert: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("expected manager MITM cert to be a CA")
	}
}

func TestProxyManagerMITMForwardsAllowedRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowed" {
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("X-Upstream", "ok")
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	policy := mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
		AllowPathPatterns: []string{`^/allowed$`},
	})
	manager := newProxyManager(policy)
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:    serverURL.Scheme,
		Authority: serverURL.Host,
		Host:      serverURL.Hostname(),
		Method:    http.MethodGet,
		Path:      "/allowed",
		Proto:     "HTTP/1.1",
	})

	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected MITM response: %#v", response)
	}
	if string(response.Body) != "upstream ok" {
		t.Fatalf("unexpected response body: %q", string(response.Body))
	}
	if got := response.Header.Get("X-Upstream"); got != "ok" {
		t.Fatalf("unexpected response header: %q", got)
	}
}

func TestProxyManagerMITMRejectsDeniedPath(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		DenyPathPatterns:  []string{`^/admin$`},
	})
	manager := newProxyManager(policy)
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme: "https",
		Host:   "example.com",
		Method: http.MethodGet,
		Path:   "/admin",
		Proto:  "HTTP/1.1",
	})

	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected denied MITM response: %#v", response)
	}
}

func TestProxyManagerMITMRejectsOversizedBody(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
	})
	manager := newProxyManager(policy)
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:       "https",
		Host:         "example.com",
		Method:       http.MethodPost,
		Path:         "/upload",
		Proto:        "HTTP/1.1",
		BodyTooLarge: true,
	})

	if response == nil || response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected oversized MITM response: %#v", response)
	}
}

func TestProxyManagerMITMRejectsHostAuthorityMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^allowed[.]example$`},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:    serverURL.Scheme,
		Authority: serverURL.Host,
		Host:      "allowed.example",
		Method:    http.MethodGet,
		Path:      "/",
		Proto:     "HTTP/1.1",
	})

	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected mismatch to be denied, got %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}
	if logger.entries[0].Result != "denied" {
		t.Fatalf("expected denied access result, got %q", logger.entries[0].Result)
	}
	if !strings.Contains(logger.entries[0].Error, "authority") {
		t.Fatalf("expected mismatch error to mention authority, got %q", logger.entries[0].Error)
	}
}

func TestHandleProxyRequestRecordsDeniedAccess(t *testing.T) {
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		DenyHostPatterns: []string{`^denied[.]test$`},
	}))
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodGet,
		URL:    "http://denied.test/blocked",
	})

	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected proxy response: %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "http" {
		t.Fatalf("expected http access kind, got %q", entry.Kind)
	}
	if entry.Allowed {
		t.Fatal("expected denied access to be disallowed")
	}
	if entry.Result != "denied" {
		t.Fatalf("expected denied result, got %q", entry.Result)
	}
	if entry.Method != http.MethodGet {
		t.Fatalf("expected GET method, got %q", entry.Method)
	}
	if entry.Path != "/blocked" {
		t.Fatalf("expected path /blocked, got %q", entry.Path)
	}
	if entry.Host != "denied.test" {
		t.Fatalf("expected host denied.test, got %q", entry.Host)
	}
	if entry.Port != 80 {
		t.Fatalf("expected port 80, got %d", entry.Port)
	}
	if entry.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", entry.StatusCode)
	}
	if entry.Error == "" {
		t.Fatal("expected error for denied request")
	}
}

func TestHandleProxyRequestRecordsUpstreamErrorAccess(t *testing.T) {
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	manager.transport = &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodGet,
		URL:    "http://upstream.test/resource",
		Header: make(http.Header),
	})

	if response == nil || response.Error == "" {
		t.Fatalf("expected upstream error response, got %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "http" {
		t.Fatalf("expected http access kind, got %q", entry.Kind)
	}
	if !entry.Allowed {
		t.Fatal("expected upstream error to be allowed")
	}
	if entry.Result != "upstream_error" {
		t.Fatalf("expected upstream_error result, got %q", entry.Result)
	}
	if entry.Method != http.MethodGet {
		t.Fatalf("expected GET method, got %q", entry.Method)
	}
	if entry.Path != "/resource" {
		t.Fatalf("expected path /resource, got %q", entry.Path)
	}
	if entry.Host != "upstream.test" {
		t.Fatalf("expected host upstream.test, got %q", entry.Host)
	}
	if entry.Port != 80 {
		t.Fatalf("expected port 80, got %d", entry.Port)
	}
	if entry.StatusCode != 0 {
		t.Fatalf("expected status code 0 for upstream error, got %d", entry.StatusCode)
	}
	if !strings.Contains(entry.Error, "dial failed") {
		t.Fatalf("expected upstream error to include dial failed, got %q", entry.Error)
	}
}

func TestHandleProxyRequestAcceptsOriginStyleURLFromTransparentIngress(t *testing.T) {
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method: %q", r.Method)
		}
		if r.URL.Path != "/allowed" {
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
		if r.URL.RawQuery != "source=transparent" {
			t.Fatalf("unexpected query: %q", r.URL.RawQuery)
		}
		gotHost = r.Host
		w.Header().Set("X-Upstream", "ok")
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1(:[0-9]+)?$`},
		AllowPathPatterns: []string{`^/allowed$`},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodGet,
		URL:    "http://" + serverURL.Host + "/allowed?source=transparent",
		Header: http.Header{"X-Test": []string{"present"}},
	})

	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected proxy response: %#v", response)
	}
	if string(response.Body) != "upstream ok" {
		t.Fatalf("unexpected response body: %q", string(response.Body))
	}
	if got := response.Header.Get("X-Upstream"); got != "ok" {
		t.Fatalf("unexpected upstream header: %q", got)
	}
	if gotHost != serverURL.Host {
		t.Fatalf("unexpected host forwarding: got %q want %q", gotHost, serverURL.Host)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "http" {
		t.Fatalf("expected http access kind, got %q", entry.Kind)
	}
	if !entry.Allowed {
		t.Fatal("expected request to be allowed")
	}
	if entry.Result != "allowed" {
		t.Fatalf("expected allowed result, got %q", entry.Result)
	}
	if entry.Path != "/allowed" {
		t.Fatalf("expected path /allowed, got %q", entry.Path)
	}
	if entry.Host != serverURL.Hostname() {
		t.Fatalf("expected host %q, got %q", serverURL.Hostname(), entry.Host)
	}
}

func TestHandleConnectRequestRecordsAllowedAccess(t *testing.T) {
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
		AllowHostPatterns: []string{`^example[.]com$`},
	}))
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleConnectRequest(t.Context(), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})

	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "connect" {
		t.Fatalf("expected connect access kind, got %q", entry.Kind)
	}
	if !entry.Allowed {
		t.Fatal("expected allowed connect access")
	}
	if entry.Result != "allowed" {
		t.Fatalf("expected allowed result, got %q", entry.Result)
	}
	if entry.Host != "example.com" {
		t.Fatalf("expected host example.com, got %q", entry.Host)
	}
	if entry.Port != 443 {
		t.Fatalf("expected port 443, got %d", entry.Port)
	}
	if entry.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", entry.StatusCode)
	}
}

func TestHandleConnectRequestRecordsDeniedAccess(t *testing.T) {
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
	}))
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleConnectRequest(t.Context(), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})

	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected connect response: %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "connect" {
		t.Fatalf("expected connect access kind, got %q", entry.Kind)
	}
	if entry.Allowed {
		t.Fatal("expected denied connect access")
	}
	if entry.Result != "denied" {
		t.Fatalf("expected denied result, got %q", entry.Result)
	}
	if entry.Host != "example.com" {
		t.Fatalf("expected host example.com, got %q", entry.Host)
	}
	if entry.Port != 443 {
		t.Fatalf("expected port 443, got %d", entry.Port)
	}
	if entry.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", entry.StatusCode)
	}
	if entry.Error == "" {
		t.Fatal("expected error for denied connect")
	}
}

func TestHandleMITMRequestRecordsAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mitm" {
			t.Fatalf("unexpected path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{serverURL.Port()},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	connectResponse := manager.handleConnectRequest(t.Context(), "sandbox-a", helperproto.ConnectRequest{
		Host: serverURL.Hostname(),
		Port: port,
	})
	if connectResponse == nil || connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", connectResponse)
	}

	mitmResponse := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:    serverURL.Scheme,
		Authority: serverURL.Host,
		Host:      serverURL.Hostname(),
		Method:    http.MethodGet,
		Path:      "/mitm",
		Proto:     "HTTP/1.1",
	})
	if mitmResponse == nil || mitmResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected MITM response: %#v", mitmResponse)
	}

	if len(logger.entries) != 2 {
		t.Fatalf("expected 2 access entries, got %d", len(logger.entries))
	}

	connectEntry := logger.entries[0]
	if connectEntry.Kind != "connect" {
		t.Fatalf("expected connect entry, got %q", connectEntry.Kind)
	}
	if connectEntry.Host != serverURL.Hostname() {
		t.Fatalf("expected connect host %q, got %q", serverURL.Hostname(), connectEntry.Host)
	}
	if connectEntry.Port != port {
		t.Fatalf("expected connect port %d, got %d", port, connectEntry.Port)
	}

	mitmEntry := logger.entries[1]
	if mitmEntry.Kind != "mitm" {
		t.Fatalf("expected mitm entry, got %q", mitmEntry.Kind)
	}
	if mitmEntry.Method != http.MethodGet {
		t.Fatalf("expected GET method, got %q", mitmEntry.Method)
	}
	if mitmEntry.Path != "/mitm" {
		t.Fatalf("expected mitm path /mitm, got %q", mitmEntry.Path)
	}
	if mitmEntry.Host != serverURL.Hostname() {
		t.Fatalf("expected mitm host %q, got %q", serverURL.Hostname(), mitmEntry.Host)
	}
	if mitmEntry.Port != port {
		t.Fatalf("expected mitm port %d, got %d", port, mitmEntry.Port)
	}
	if mitmEntry.Result != "allowed" {
		t.Fatalf("expected allowed mitm result, got %q", mitmEntry.Result)
	}
}

func TestHandleMITMRequestRejectsHostAuthorityMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^decrypted[.]test$`},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:    serverURL.Scheme,
		Authority: serverURL.Host,
		Host:      "decrypted.test",
		Method:    http.MethodGet,
		Path:      "/",
		Proto:     "HTTP/1.1",
	})
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected mismatch to be denied, got %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "mitm" {
		t.Fatalf("expected mitm entry, got %q", entry.Kind)
	}
	if entry.Host == "" {
		t.Fatal("expected denied entry host to be recorded")
	}
	if entry.Result != "denied" {
		t.Fatalf("expected denied entry result, got %q", entry.Result)
	}
	if !strings.Contains(entry.Error, "authority") {
		t.Fatalf("expected mismatch error to mention authority, got %q", entry.Error)
	}
}

func TestHandleMITMRequestRejectsHostAuthorityMismatchUsingAuthorityPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}

	logger := &stubAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^decrypted[.]test$`},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleMITMRequest(t.Context(), "sandbox-a", helperproto.MITMRequest{
		Scheme:    serverURL.Scheme,
		Authority: serverURL.Host,
		Host:      "decrypted.test",
		Method:    http.MethodGet,
		Path:      "/",
		Proto:     "HTTP/1.1",
	})
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected mismatch to be denied, got %#v", response)
	}
	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.Kind != "mitm" {
		t.Fatalf("expected mitm entry, got %q", entry.Kind)
	}
	if entry.Host == "" {
		t.Fatal("expected denied entry host to be recorded")
	}
	if entry.Port != port {
		t.Fatalf("expected port %d from authority, got %d", port, entry.Port)
	}
	if entry.Result != "denied" {
		t.Fatalf("expected denied entry result, got %q", entry.Result)
	}
}

func TestHandleProxyRequestRejectsOversizedRequestBody(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
	}))
	manager.requestBodyLimitBytes = 8
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodPost,
		URL:    "http://example.com/upload",
		Body:   bytes.Repeat([]byte("a"), 9),
	})

	if response == nil || response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized request to be rejected, got %#v", response)
	}
}

func TestProxyManagerRejectsOversizedResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("b"), 17))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
	}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.responseBodyLimitBytes = 16
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodGet,
		URL:    serverURL.String(),
		Header: make(http.Header),
	})

	if response == nil || response.Error == "" {
		t.Fatalf("expected oversized response body error, got %#v", response)
	}
	if !strings.Contains(response.Error, "response body exceeds") {
		t.Fatalf("expected body limit error, got %q", response.Error)
	}
}

func TestProxyManagerUsesDefaultBodyLimits(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}

	if manager.requestBodyLimitBytes != defaultMaxRequestBodyBytes {
		t.Fatalf("unexpected default request body limit: got %d want %d", manager.requestBodyLimitBytes, defaultMaxRequestBodyBytes)
	}
	if manager.responseBodyLimitBytes != defaultMaxResponseBodyBytes {
		t.Fatalf("unexpected default response body limit: got %d want %d", manager.responseBodyLimitBytes, defaultMaxResponseBodyBytes)
	}
}

func TestReadBoundedResponseRejectsOversizedBody(t *testing.T) {
	body, tooLarge, err := readBoundedResponse(io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 6))), 5)
	if err != nil {
		t.Fatalf("readBoundedResponse returned error: %v", err)
	}
	if !tooLarge {
		t.Fatal("expected oversized response body to be flagged")
	}
	if len(body) != 5 {
		t.Fatalf("expected truncated body length 5, got %d", len(body))
	}
}

// Keep assertions package-local for now; these tests become the safety net
// while functions move into smaller packages in later tasks.
func TestReadBoundedResponseFlagsOversize(t *testing.T) {
	body := io.NopCloser(strings.NewReader("abcdef"))
	got, tooLarge, err := readBoundedResponse(body, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" || !tooLarge {
		t.Fatalf("got %q tooLarge=%v", string(got), tooLarge)
	}
}

func TestValidateMITMHostAuthorityRejectsMismatch(t *testing.T) {
	if err := validateMITMHostAuthority("allowed.example", "127.0.0.1:443"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestLoggerFailureDoesNotBreakRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	logger := &panicAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	manager.transport = server.Client().Transport.(*http.Transport).Clone()
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("handleProxyRequest panicked: %v", recovered)
		}
	}()

	response := manager.handleProxyRequest(t.Context(), "sandbox-a", helperproto.ProxyRequest{
		Method: http.MethodGet,
		URL:    serverURL.String(),
		Header: make(http.Header),
	})

	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected proxy response: %#v", response)
	}
	if logger.calls != 1 {
		t.Fatalf("expected logger to be called once, got %d", logger.calls)
	}
}

func TestLoggerFailureDoesNotBreakRequestConnect(t *testing.T) {
	logger := &panicAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
		AllowHostPatterns: []string{`^example[.]com$`},
	}))
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("handleConnectRequest panicked: %v", recovered)
		}
	}()

	response := manager.handleConnectRequest(t.Context(), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})

	if response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected connect response: %#v", response)
	}
	if logger.calls != 1 {
		t.Fatalf("expected logger to be called once, got %d", logger.calls)
	}
}
