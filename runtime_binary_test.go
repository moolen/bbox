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

func TestRuntimeBinaryResolverBuildsSiblingLauncherForSourceFallback(t *testing.T) {
	moduleRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	buildDir := t.TempDir()
	bboxPath := filepath.Join(buildDir, "bbox")
	launcherPath := filepath.Join(buildDir, "bbox-seccomp-launcher")

	bboxBuilds := 0
	launcherBuilds := 0

	resolver := newRuntimeBinaryResolver()
	resolver.executablePath = func() (string, error) { return "", nil }
	resolver.packageRoot = func() (string, error) { return moduleRoot, nil }
	resolver.makeTempDir = func(_, _ string) (string, error) { return buildDir, nil }
	resolver.buildBBox = func(root, out string) error {
		bboxBuilds++
		if root != moduleRoot {
			t.Fatalf("unexpected build root: got %q want %q", root, moduleRoot)
		}
		if out != bboxPath {
			t.Fatalf("unexpected bbox path: got %q want %q", out, bboxPath)
		}
		return os.WriteFile(out, []byte("#!/bin/sh\n"), 0o755)
	}
	resolver.buildLauncher = func(root, out string) error {
		launcherBuilds++
		if root != moduleRoot {
			t.Fatalf("unexpected build root: got %q want %q", root, moduleRoot)
		}
		if out != launcherPath {
			t.Fatalf("unexpected launcher path: got %q want %q", out, launcherPath)
		}
		return os.WriteFile(out, []byte("#!/bin/sh\n"), 0o755)
	}

	got, err := resolver.RuntimeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got != bboxPath {
		t.Fatalf("unexpected runtime binary path: got %q want %q", got, bboxPath)
	}
	if _, err := os.Stat(launcherPath); err != nil {
		t.Fatalf("expected sibling launcher at %q: %v", launcherPath, err)
	}
	if bboxBuilds != 1 {
		t.Fatalf("expected one bbox build, got %d", bboxBuilds)
	}
	if launcherBuilds != 1 {
		t.Fatalf("expected one launcher build, got %d", launcherBuilds)
	}
}
