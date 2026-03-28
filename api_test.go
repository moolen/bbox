package bbox

import (
	"strings"
	"testing"
)

func TestNewProxyManagerRejectsInvalidRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			AllowHostPatterns: []string{"["},
		},
	})
	if err == nil {
		t.Fatal("expected constructor to reject invalid policy regex")
	}
	if !strings.Contains(err.Error(), "allow host pattern") {
		t.Fatalf("expected allow host pattern context, got %q", err.Error())
	}
}

func TestNewProxyManagerRejectsInvalidDenyRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			DenyHostPatterns: []string{"["},
		},
	})
	if err == nil {
		t.Fatal("expected constructor to reject invalid deny regex")
	}
	if !strings.Contains(err.Error(), "deny host pattern") {
		t.Fatalf("expected deny host pattern context, got %q", err.Error())
	}
}

func TestNewProxyManagerAcceptsPolicyOptions(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			AllowHTTPMethods: []string{"GET"},
		},
	})
	if err != nil {
		t.Fatalf("expected AllowHTTPMethods policy option to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}

	manager, err = NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			AllowConnect: true,
		},
	})
	if err != nil {
		t.Fatalf("expected AllowConnect policy option to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewProxyManagerAcceptsValidPolicy(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			AllowHostPatterns: []string{`^example\.com$`},
			DenyHostPatterns:  []string{`^internal\.example\.com$`},
		},
	})
	if err != nil {
		t.Fatalf("expected valid policy to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewProxyManagerAcceptsListenAddr(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("expected listen address to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
	if manager.listenAddr != "127.0.0.1:0" {
		t.Fatalf("unexpected listen address: got %q", manager.listenAddr)
	}
}

func TestNewProxyManagerAcceptsMITMOptions(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		MITM: MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: 65536,
		},
	})
	if err != nil {
		t.Fatalf("expected MITM options to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewProxyManagerRejectsNegativeMITMBodyLimit(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		MITM: MITMOptions{
			Enabled:             true,
			MaxRequestBodyBytes: -1,
		},
	})
	if err == nil {
		t.Fatal("expected invalid MITM body limit to fail")
	}
}

func TestProxyManagerCACertPEM(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("expected manager to be created: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
	if got := manager.CACertPEM(); len(got) != 0 {
		t.Fatalf("expected empty CA PEM when MITM disabled, got %q", string(got))
	}
}
