package bbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeBinaryResolverPrefersPackagedBBox(t *testing.T) {
	exeDir := t.TempDir()
	exePath := filepath.Join(exeDir, "bbox")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	resolver := newRuntimeBinaryResolver()
	resolver.executablePath = func() (string, error) { return exePath, nil }

	got, err := resolver.RuntimeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got != exePath {
		t.Fatalf("got %q want %q", got, exePath)
	}
}
