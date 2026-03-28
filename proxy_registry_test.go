package bbox

import "testing"

func TestRegistryRejectsDuplicateSandboxID(t *testing.T) {
	r := newSandboxRegistry(nil)
	if err := r.Register("sandbox-a", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("sandbox-a", nil); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}
