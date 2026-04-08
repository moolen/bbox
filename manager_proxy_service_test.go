package bbox

import (
	"context"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestProxyServiceRejectsOversizedMITMBody(t *testing.T) {
	svc := newManagerProxyService(managerProxyConfig{maxRequestBodyBytes: 3})
	resp := svc.HandleMITMRequest(context.Background(), mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^example[.]com$`}},
		},
	}), "sandbox-a", helperproto.MITMRequest{
		Scheme:    "https",
		Authority: "example.com",
		Host:      "example.com",
		Method:    http.MethodPost,
		Path:      "/upload",
		Proto:     "HTTP/1.1",
		Body:      []byte("abcdef"),
	})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestConnectServiceRejectsDeniedRequest(t *testing.T) {
	svc := newManagerConnectService(nil, PolicyModeEnforce)
	resp := svc.HandleConnectRequest(context.Background(), mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^example[.]com$`}},
		},
	}), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestProxyServiceAllowsLargeMITMResponsesByDefault(t *testing.T) {
	const bodySize = 5 << 20

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), bodySize))
	}))
	defer server.Close()

	svc := newManagerProxyService(managerProxyConfig{
		transport:            server.Client().Transport.(*http.Transport),
		maxRequestBodyBytes:  effectiveRequestBodyLimit(ProxyOptions{}),
		maxResponseBodyBytes: effectiveResponseBodyLimit(ProxyOptions{}),
	})

	resp := svc.HandleMITMRequest(context.Background(), mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^127[.]0[.]0[.]1$`}},
		},
	}), "sandbox-a", helperproto.MITMRequest{
		Scheme:    "http",
		Authority: server.URL[len("http://"):],
		Host:      "127.0.0.1",
		Method:    http.MethodGet,
		Path:      "/layer",
		Proto:     "HTTP/1.1",
	})
	if resp.Error != "" {
		t.Fatalf("expected large MITM response to succeed, got error %q", resp.Error)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if len(resp.Body) != bodySize {
		t.Fatalf("expected body size %d, got %d", bodySize, len(resp.Body))
	}
}
