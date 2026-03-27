package bbox

import "testing"

func TestProxyManagerRegistryLifecycle(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	manager := newProxyManager(policy)
	if err := manager.registerSandbox("sandbox-1", nil); err != nil {
		t.Fatalf("expected first sandbox registration to succeed: %v", err)
	}
	if err := manager.registerSandbox("sandbox-1", nil); err == nil {
		t.Fatal("expected duplicate sandbox registration to fail")
	}

	registeredPolicy, ok := manager.policyForSandbox("sandbox-1")
	if !ok {
		t.Fatal("expected registered sandbox policy lookup to succeed")
	}
	if registeredPolicy != policy {
		t.Fatal("expected default manager policy to be registered for sandbox")
	}

	manager.unregisterSandbox("sandbox-1")
	if _, ok := manager.policyForSandbox("sandbox-1"); ok {
		t.Fatal("expected sandbox policy lookup to fail after unregister")
	}
}
