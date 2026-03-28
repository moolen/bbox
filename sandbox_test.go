package bbox

import "testing"

func TestSandboxRunRejectsEmptyArgv(t *testing.T) {
	s := &Sandbox{}
	_, err := s.Run(nil, nil, RunOptions{})
	if err == nil {
		t.Fatal("expected empty argv to fail")
	}
}

func TestSandboxCloseDoesNotUnregisterExistingSandboxOnDuplicateStartupFailure(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	manager := newProxyManager(policy)
	original := &Sandbox{manager: manager, id: "dup"}
	if err := manager.registerSandbox("dup", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.attachSandbox("dup", original); err != nil {
		t.Fatal(err)
	}

	duplicate := &Sandbox{manager: manager, id: "dup"}
	if err := duplicate.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	registeredPolicy, ok := manager.policyForSandbox("dup")
	if !ok {
		t.Fatal("expected original sandbox registration to remain intact")
	}
	if registeredPolicy != policy {
		t.Fatal("expected original sandbox policy to remain registered")
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if manager.sandboxes["dup"] != original {
		t.Fatal("expected original sandbox entry to remain attached")
	}
}

func TestSandboxUsesHelperReportedProxyEnv(t *testing.T) {
	env := runEnvForProxyAddr("127.0.0.1:40123", []string{
		"FOO=bar",
		"HTTP_PROXY=http://stale",
		"HTTPS_PROXY=http://stale-secure",
	})

	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := splitEnv(entry)
		if !ok {
			t.Fatalf("invalid env entry %q", entry)
		}
		got[key] = value
	}

	if got["PATH"] != "/usr/bin" {
		t.Fatalf("unexpected PATH: got %q", got["PATH"])
	}
	if got["HTTP_PROXY"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected HTTP_PROXY: got %q", got["HTTP_PROXY"])
	}
	if got["http_proxy"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected http_proxy: got %q", got["http_proxy"])
	}
	if got["HTTPS_PROXY"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected HTTPS_PROXY: got %q", got["HTTPS_PROXY"])
	}
	if got["https_proxy"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected https_proxy: got %q", got["https_proxy"])
	}
	if got["FOO"] != "bar" {
		t.Fatalf("unexpected FOO: got %q", got["FOO"])
	}
}

func TestSandboxProxyAccessors(t *testing.T) {
	sandbox := &Sandbox{proxyAddr: "127.0.0.1:40123"}

	if got := sandbox.ProxyAddr(); got != "127.0.0.1:40123" {
		t.Fatalf("unexpected proxy addr: got %q", got)
	}
	if got := sandbox.ProxyURL(); got != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected proxy url: got %q", got)
	}
}

func TestNilSandboxProxyAccessorsReturnEmptyString(t *testing.T) {
	var sandbox *Sandbox

	if got := sandbox.ProxyAddr(); got != "" {
		t.Fatalf("expected empty proxy addr, got %q", got)
	}
	if got := sandbox.ProxyURL(); got != "" {
		t.Fatalf("expected empty proxy url, got %q", got)
	}
}
