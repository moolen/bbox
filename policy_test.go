package bbox

import "testing"

func TestCompiledPolicyHonorsDenyBeforeAllow(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`(^|[.])github[.]com$`},
		DenyHostPatterns:  []string{`^gist[.]github[.]com$`},
		AllowHTTPMethods:  []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "api.github.com", false); err != nil {
		t.Fatalf("expected api.github.com to be allowed: %v", err)
	}
	if err := policy.Check("GET", "gist.github.com", false); err == nil {
		t.Fatal("expected gist.github.com to be denied")
	}
}

func TestCompiledPolicyEnforcesMethodAllowlist(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHTTPMethods: []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "example.com", false); err != nil {
		t.Fatalf("expected GET to be allowed: %v", err)
	}
	if err := policy.Check("POST", "example.com", false); err == nil {
		t.Fatal("expected POST to be denied by method allowlist")
	}
}

func TestCompiledPolicyEnforcesConnectGate(t *testing.T) {
	disallowConnect, err := compilePolicy(NetworkPolicy{
		AllowHTTPMethods: []string{"GET"},
		AllowConnect:     false,
		AllowConnectPorts: []string{
			"443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := disallowConnect.Check("CONNECT", "example.com:443", true); err == nil {
		t.Fatal("expected CONNECT to be denied when AllowConnect is false")
	}

	allowConnect, err := compilePolicy(NetworkPolicy{
		AllowHTTPMethods: []string{"GET"},
		AllowConnect:     true,
		AllowConnectPorts: []string{
			"443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := allowConnect.Check("CONNECT", "example.com:443", true); err != nil {
		t.Fatalf("expected CONNECT to be allowed: %v", err)
	}
}

func TestCompiledPolicyDeniesConnectWhenNoConnectPortsConfigured(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowConnect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check("CONNECT", "example.com:443", true); err == nil {
		t.Fatal("expected CONNECT to be denied when AllowConnectPorts is empty")
	}
}

func TestCompiledPolicyComposesConnectPortWithHostnamePolicies(t *testing.T) {
	allowPolicy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`^allowed[.]example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := allowPolicy.Check("CONNECT", "blocked.example.com:443", true); err == nil {
		t.Fatal("expected CONNECT to be denied when hostname does not match allowlist")
	}

	denyPolicy, err := compilePolicy(NetworkPolicy{
		DenyHostPatterns:  []string{`^blocked[.]example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := denyPolicy.Check("CONNECT", "blocked.example.com:443", true); err == nil {
		t.Fatal("expected CONNECT to be denied by deny host pattern despite allowed port")
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

func TestCompilePolicyParsesAllowedConnectPorts(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443", "8443", "10000-10100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check("CONNECT", "example.com:443", true); err != nil {
		t.Fatalf("expected 443 to be allowed: %v", err)
	}
	if err := policy.Check("CONNECT", "example.com:10050", true); err != nil {
		t.Fatalf("expected range port to be allowed: %v", err)
	}
}

func TestCompilePolicyRejectsInvalidConnectPortSpec(t *testing.T) {
	_, err := compilePolicy(NetworkPolicy{
		AllowConnect:      true,
		AllowConnectPorts: []string{"443-22"},
	})
	if err == nil {
		t.Fatal("expected invalid descending range to fail")
	}
}

func TestCompiledPolicyDeniesConnectWithoutAllowedPortMatch(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowConnect:      true,
		AllowConnectPorts: []string{"443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check("CONNECT", "example.com:8443", true); err == nil {
		t.Fatal("expected CONNECT to unmatched port to be denied")
	}
}

func TestCompiledPolicyDefaultsDenyWhenAllowlistConfigured(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`(^|[.])github[.]com$`},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "api.github.com", false); err != nil {
		t.Fatalf("expected api.github.com to be allowed: %v", err)
	}
	if err := policy.Check("GET", "example.com", false); err == nil {
		t.Fatal("expected example.com to be denied when allowlist is configured")
	}
}

func TestCompiledPolicyHandlesHostPortInputs(t *testing.T) {
	allowPolicy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`(^|[.])github[.]com$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := allowPolicy.Check("GET", "api.github.com:443", false); err != nil {
		t.Fatalf("expected allowlist to match host:port by hostname, got: %v", err)
	}

	denyPolicy, err := compilePolicy(NetworkPolicy{
		DenyHostPatterns: []string{`^gist[.]github[.]com$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := denyPolicy.Check("GET", "gist.github.com:443", false); err == nil {
		t.Fatal("expected denylist to match host:port by hostname")
	}
}

func TestCompiledPolicyRejectsInvalidHostPort(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "example.com:notaport", false); err == nil {
		t.Fatal("expected invalid host:port to be rejected")
	}
}

func TestCompiledPolicyRejectsMalformedColonInputs(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"api.github.com:443:extra",
		"::1",
		"[::1",
		"::1:443",
	}
	for _, input := range cases {
		if err := policy.Check("GET", input, false); err == nil {
			t.Fatalf("expected malformed colon input %q to be rejected", input)
		}
	}
}

func TestCompiledPolicyTrimsBracketedIPv6Whitespace(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`^::1$`},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "[  ::1  ]", false); err != nil {
		t.Fatalf("expected bracketed IPv6 whitespace to normalize and match: %v", err)
	}
}
