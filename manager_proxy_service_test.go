package bbox

import (
	"context"
	"net/http"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestProxyServiceRejectsOversizedMITMBody(t *testing.T) {
	svc := newManagerProxyService(managerProxyConfig{maxRequestBodyBytes: 3})
	resp := svc.HandleMITMRequest(context.Background(), mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
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
	svc := newManagerConnectService(nil)
	resp := svc.HandleConnectRequest(context.Background(), mustCompilePolicy(t, NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
	}), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
}
