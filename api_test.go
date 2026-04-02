package bbox

import (
	"strings"
	"testing"
)

func TestNewProxyManagerRejectsInvalidRuleHostRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			Rules: []PolicyRule{
				{HostPatterns: []string{"["}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected constructor to reject invalid policy regex")
	}
	if !strings.Contains(err.Error(), "host pattern") {
		t.Fatalf("expected host pattern context, got %q", err.Error())
	}
}

func TestNewProxyManagerRejectsInvalidRuleHeaderRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			Rules: []PolicyRule{
				{
					HeaderPatterns: map[string][]string{
						"X-Test": {"["},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected constructor to reject invalid header regex")
	}
	if !strings.Contains(err.Error(), "header") {
		t.Fatalf("expected header pattern context, got %q", err.Error())
	}
}

func TestNewProxyManagerAcceptsPolicyOptions(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			Rules: []PolicyRule{
				{HTTPMethods: []string{"GET"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("expected HTTPMethods policy option to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}

	manager, err = NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			Rules: []PolicyRule{
				{ConnectPorts: []string{"443"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("expected ConnectPorts policy option to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewProxyManagerAcceptsValidPolicy(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		NetworkPolicy: NetworkPolicy{
			Rules: []PolicyRule{
				{
					HostPatterns: []string{`^example\.com$`},
					HTTPMethods:  []string{"GET"},
				},
			},
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
		MaxRequestBodyBytes: 65536,
		MITM:                MITMOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("expected MITM options to be accepted: %v", err)
	}
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewProxyManagerRejectsNegativeRequestBodyLimit(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{
		MaxRequestBodyBytes: -1,
		MITM:                MITMOptions{Enabled: true},
	})
	if err == nil {
		t.Fatal("expected invalid request body limit to fail")
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

func TestNewProxyManagerDefaultsPolicyModeToEnforce(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	if manager.policyMode != PolicyModeEnforce {
		t.Fatalf("expected default policy mode enforce, got %q", manager.policyMode)
	}
}

func TestNewProxyManagerRejectsUnknownPolicyMode(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{PolicyMode: PolicyMode("broken")})
	if err == nil {
		t.Fatal("expected invalid policy mode to fail")
	}
}
