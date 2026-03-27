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
		AllowHTTPMethods: []string{"CONNECT"},
		AllowConnect:     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := disallowConnect.Check("CONNECT", "example.com", true); err == nil {
		t.Fatal("expected CONNECT to be denied when AllowConnect is false")
	}

	allowConnect, err := compilePolicy(NetworkPolicy{
		AllowHTTPMethods: []string{"CONNECT"},
		AllowConnect:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := allowConnect.Check("CONNECT", "example.com", true); err != nil {
		t.Fatalf("expected CONNECT to be allowed: %v", err)
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
