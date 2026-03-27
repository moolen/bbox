package bbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateMountsRejectsOverlappingTargets(t *testing.T) {
	sourceOne := filepath.Join(t.TempDir(), "one")
	sourceTwo := filepath.Join(t.TempDir(), "two")
	mustMkdirAll(t, sourceOne)
	mustMkdirAll(t, sourceTwo)

	err := validateMounts([]Mount{
		{Source: sourceOne, Target: "/workspace", ReadOnly: true},
		{Source: sourceTwo, Target: "/workspace", ReadOnly: false},
	})
	if err == nil {
		t.Fatal("expected overlapping mount targets to fail")
	}
}

func TestValidateMountsRejectsRootOverlap(t *testing.T) {
	sourceOne := filepath.Join(t.TempDir(), "one")
	sourceTwo := filepath.Join(t.TempDir(), "two")
	mustMkdirAll(t, sourceOne)
	mustMkdirAll(t, sourceTwo)

	err := validateMounts([]Mount{
		{Source: sourceOne, Target: "/", ReadOnly: true},
		{Source: sourceTwo, Target: "/workspace", ReadOnly: false},
	})
	if err == nil {
		t.Fatal("expected root mount target to overlap with subpaths")
	}
}

func TestValidateMountsRejectsReservedInternalTargets(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	for _, target := range []string{
		"/app",
		"/usr/local/bin",
		"/etc/custom",
		"/lib/modules",
		"/lib64/plugins",
		"/proc/self",
		"/dev/fd",
		"/tmp/work",
	} {
		err := validateMounts([]Mount{
			{Source: source, Target: target, ReadOnly: true},
		})
		if err == nil {
			t.Fatalf("expected reserved target %q to be rejected", target)
		}
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}
