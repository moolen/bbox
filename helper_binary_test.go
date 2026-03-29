package bbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageRootFindsModuleRoot(t *testing.T) {
	root, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
}

func TestHelperBinaryResolverCachesBuiltPath(t *testing.T) {
	moduleRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	buildDir := t.TempDir()
	helperPath := filepath.Join(buildDir, "bbox-helper")
	builds := 0

	resolver := newHelperBinaryResolver()
	resolver.packageRoot = func() (string, error) {
		return moduleRoot, nil
	}
	resolver.makeTempDir = func(dir, pattern string) (string, error) {
		return buildDir, nil
	}
	resolver.buildHelper = func(root, out string) error {
		builds++
		if root != moduleRoot {
			t.Fatalf("unexpected module root: got %q want %q", root, moduleRoot)
		}
		if out != helperPath {
			t.Fatalf("unexpected helper path: got %q want %q", out, helperPath)
		}
		return os.WriteFile(out, []byte("#!/bin/sh\n"), 0o755)
	}

	first, err := resolver.HelperBinary()
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.HelperBinary()
	if err != nil {
		t.Fatal(err)
	}

	if first != helperPath {
		t.Fatalf("unexpected first helper path: got %q want %q", first, helperPath)
	}
	if second != helperPath {
		t.Fatalf("unexpected second helper path: got %q want %q", second, helperPath)
	}
	if builds != 1 {
		t.Fatalf("expected exactly one build, got %d", builds)
	}
}
