package bbox

import "testing"

func TestValidateMountsRejectsOverlappingTargets(t *testing.T) {
	err := validateMounts([]Mount{
		{Source: "/tmp/one", Target: "/workspace", ReadOnly: true},
		{Source: "/tmp/two", Target: "/workspace", ReadOnly: false},
	})
	if err == nil {
		t.Fatal("expected overlapping mount targets to fail")
	}
}
