package bbox

import (
	"net/http"
	"testing"
)

func TestEvaluateHTTPRequestReturnsViolationReasons(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^example[.]com$`},
				HTTPMethods:  []string{http.MethodGet},
				PathPatterns: []string{`^/ok$`},
			},
		},
	})

	eval := policy.evaluateRequest(PolicyRequest{
		Method: http.MethodPost,
		Host:   "example.com",
		Path:   "/blocked",
	})

	if eval.Allowed {
		t.Fatal("expected evaluation to deny request")
	}
	if len(eval.Reasons) == 0 {
		t.Fatal("expected denial reasons")
	}
}

func TestEvaluateDNSRequestReturnsViolationReasons(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^allowed[.]example[.]com$`}},
		},
	})

	eval := policy.evaluateDNS("denied.example.com")

	if eval.Allowed {
		t.Fatal("expected DNS evaluation to deny hostname")
	}
	if len(eval.Reasons) == 0 {
		t.Fatal("expected denial reasons")
	}
}

func TestEvaluateDNSIgnoresCIDROnlyRules(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{IPCIDRs: []string{"127.0.0.0/8"}},
		},
	})

	eval := policy.evaluateDNS("127.0.0.1")

	if eval.Allowed {
		t.Fatal("expected DNS evaluation to deny when no hostname rule matches")
	}
	if len(eval.Reasons) == 0 {
		t.Fatal("expected denial reasons")
	}
}

func TestEvaluateConnectReturnsViolationReasons(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{ConnectPorts: []string{"443"}},
		},
	})

	eval := policy.evaluateConnect("example.com", 8443, false)

	if eval.Allowed {
		t.Fatal("expected CONNECT evaluation to deny port")
	}
	if len(eval.Reasons) == 0 {
		t.Fatal("expected denial reasons")
	}
}

func TestEvaluateConnectAllowsIPv6LiteralFromConnectTarget(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^::1$`},
				ConnectPorts: []string{"443"},
			},
		},
	})

	eval := policy.evaluate(http.MethodConnect, "[::1]:443", true)

	if !eval.Allowed {
		t.Fatalf("expected CONNECT IPv6 literal to be allowed, got reasons: %v", eval.Reasons)
	}
}
