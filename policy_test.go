package bbox

import (
	"net/http"
	"testing"
)

func TestCompilePolicySupportsRuleBasedCIDRAndHeaderRules(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		Rules: []PolicyRule{
			{
				IPCIDRs:        []string{"192.0.2.0/24"},
				HTTPMethods:    []string{http.MethodGet},
				HeaderPatterns: map[string][]string{"X-Trace": {`^trace-[0-9]+$`}},
			},
		},
	})
	if err != nil {
		t.Fatalf("compilePolicy() error = %v", err)
	}
	if policy == nil {
		t.Fatal("expected compiled policy")
	}
}

func TestPolicyCheckAllowsIPLiteralWithinMatchingRule(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{IPCIDRs: []string{"192.0.2.0/24"}},
		},
	})

	if err := policy.Check(http.MethodGet, "192.0.2.10", false); err != nil {
		t.Fatalf("expected CIDR-allowed IP literal to pass: %v", err)
	}
	if err := policy.Check(http.MethodGet, "198.51.100.10", false); err == nil {
		t.Fatal("expected IP literal outside CIDR allowlist to fail")
	}
}

func TestPolicyCheckDNSUsesHostRules(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{"^allowed\\.example\\.com$"}},
		},
	})

	if err := policy.CheckDNS("allowed.example.com."); err != nil {
		t.Fatalf("expected allowed DNS hostname to pass: %v", err)
	}
	if err := policy.CheckDNS("denied.example.com."); err == nil {
		t.Fatal("expected denied DNS hostname to fail")
	}
}

func TestCompiledPolicyDefaultsToDenyWhenNoRuleMatches(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`(^|[.])github[.]com$`}},
		},
	})

	if err := policy.Check(http.MethodGet, "api.github.com", false); err != nil {
		t.Fatalf("expected api.github.com to be allowed: %v", err)
	}
	if err := policy.Check(http.MethodGet, "example.com", false); err == nil {
		t.Fatal("expected example.com to be denied when no rule matches")
	}
}

func TestCompiledPolicyAllowsWhenAnyRuleMatches(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^api[.]github[.]com$`},
				HTTPMethods:  []string{http.MethodGet},
			},
			{
				HostPatterns: []string{`^foo[.]example[.]org$`},
				HTTPMethods:  []string{http.MethodPost},
			},
		},
	})

	if err := policy.Check(http.MethodGet, "api.github.com", false); err != nil {
		t.Fatalf("expected first rule to allow: %v", err)
	}
	if err := policy.Check(http.MethodPost, "foo.example.org", false); err != nil {
		t.Fatalf("expected second rule to allow: %v", err)
	}
	if err := policy.Check(http.MethodPost, "api.github.com", false); err == nil {
		t.Fatal("expected unmatched method+host combination to deny")
	}
}

func TestCompiledPolicyComposesConnectPortAndHostnameWithinSingleRule(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^example[.]com$`},
				ConnectPorts: []string{"443", "8443"},
			},
		},
	})

	if err := policy.Check(http.MethodConnect, "example.com:443", true); err != nil {
		t.Fatalf("expected CONNECT rule to allow matching host and port: %v", err)
	}
	if err := policy.Check(http.MethodConnect, "example.com:9443", true); err == nil {
		t.Fatal("expected CONNECT to unmatched port to be denied")
	}
	if err := policy.Check(http.MethodConnect, "other.example:443", true); err == nil {
		t.Fatal("expected CONNECT to unmatched host to be denied")
	}
}

func TestCompiledPolicyAllowsTransparentConnectWithoutConnectPortRule(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^secure[.]example[.]com$`}},
		},
	})

	if err := policy.CheckTransparentConnect("secure.example.com"); err != nil {
		t.Fatalf("expected transparent connect host check to pass: %v", err)
	}
}

func TestSplitConnectTargetRejectsMalformedAuthorities(t *testing.T) {
	cases := []string{
		"",
		"example.com",
		"example.com:notaport",
		"example.com:0",
		"::1:443",
		"[::1",
		"[::1]:0",
	}

	for _, input := range cases {
		if _, _, err := splitConnectTarget(input); err == nil {
			t.Fatalf("expected malformed CONNECT authority %q to be rejected", input)
		}
	}
}

func TestSplitConnectTargetAcceptsIPv6Target(t *testing.T) {
	host, port, err := splitConnectTarget("[2001:db8::1]:443")
	if err != nil {
		t.Fatalf("expected IPv6 CONNECT target to parse: %v", err)
	}
	if host != "2001:db8::1" {
		t.Fatalf("unexpected host: %q", host)
	}
	if port != 443 {
		t.Fatalf("unexpected port: %d", port)
	}
}

func TestCompilePolicyRejectsInvalidConnectPortSpec(t *testing.T) {
	_, err := compilePolicy(NetworkPolicy{
		Rules: []PolicyRule{
			{ConnectPorts: []string{"443-22"}},
		},
	})
	if err == nil {
		t.Fatal("expected invalid descending range to fail")
	}
}

func TestCompiledPolicyHandlesHostPortInputs(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`(^|[.])github[.]com$`}},
		},
	})

	if err := policy.Check(http.MethodGet, "api.github.com:443", false); err != nil {
		t.Fatalf("expected allowlist to match host:port by hostname, got: %v", err)
	}
}

func TestCompiledPolicyRejectsInvalidHostPort(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{})

	if err := policy.Check(http.MethodGet, "example.com:notaport", false); err == nil {
		t.Fatal("expected invalid host:port to be rejected")
	}
}

func TestCompiledPolicyRejectsMalformedColonInputs(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{})

	cases := []string{
		"api.github.com:443:extra",
		"::1",
		"[::1",
		"::1:443",
	}
	for _, input := range cases {
		if err := policy.Check(http.MethodGet, input, false); err == nil {
			t.Fatalf("expected malformed colon input %q to be rejected", input)
		}
	}
}

func TestCompiledPolicyTrimsBracketedIPv6Whitespace(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{`^::1$`}},
		},
	})

	if err := policy.Check(http.MethodGet, "[  ::1  ]", false); err != nil {
		t.Fatalf("expected bracketed IPv6 whitespace to normalize and match: %v", err)
	}
}

func TestCompiledPolicyAppliesPathHeaderAndBodyMatchersWithinRule(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^example[.]com$`},
				HTTPMethods:  []string{http.MethodPost},
				PathPatterns: []string{`^/submit$`},
				HeaderPatterns: map[string][]string{
					"X-Trace": {`^trace-[0-9]+$`},
				},
				BodyPatterns: []string{`^safe=`},
			},
		},
	})

	if err := policy.CheckRequest(PolicyRequest{
		Method: http.MethodPost,
		Host:   "example.com",
		Path:   "/submit",
		Header: http.Header{
			"X-Trace": []string{"trace-42"},
		},
		Body: []byte("safe=true"),
	}); err != nil {
		t.Fatalf("expected full rule match to pass: %v", err)
	}

	if err := policy.CheckRequest(PolicyRequest{
		Method: http.MethodPost,
		Host:   "example.com",
		Path:   "/submit",
		Header: http.Header{
			"X-Trace": []string{"bad"},
		},
		Body: []byte("safe=true"),
	}); err == nil {
		t.Fatal("expected unmatched header pattern to deny")
	}

	if err := policy.CheckRequest(PolicyRequest{
		Method: http.MethodPost,
		Host:   "example.com",
		Path:   "/submit",
		Header: http.Header{
			"X-Trace": []string{"trace-42"},
		},
		Body: []byte("unsafe=true"),
	}); err == nil {
		t.Fatal("expected unmatched body pattern to deny")
	}
}

func TestCompiledPolicyRejectsOversizedBodyWhenRuleNeedsBodyInspection(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{
				HostPatterns: []string{`^example[.]com$`},
				BodyPatterns: []string{`^safe=`},
			},
		},
	})

	err := policy.CheckRequest(PolicyRequest{
		Method:       http.MethodPost,
		Host:         "example.com",
		Path:         "/submit",
		BodyTooLarge: true,
	})
	if err == nil {
		t.Fatal("expected oversized body to fail")
	}
}
