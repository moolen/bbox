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
