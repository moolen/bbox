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
