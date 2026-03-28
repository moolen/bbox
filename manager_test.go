package bbox

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
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
