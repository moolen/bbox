//go:build linux

package bbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareRuntimeMountsConvertsEmptyDirToBindMount(t *testing.T) {
	root := t.TempDir()

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
		},
	})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}
	if len(runtimeMounts) != 1 {
		t.Fatalf("expected 1 runtime mount, got %d", len(runtimeMounts))
	}

	got := runtimeMounts[0]
	wantSource := filepath.Join(root, runtimeEmptyDirBase, "0")
	if got.Type != MountTypeBind {
		t.Fatalf("expected runtime mount type %q, got %q", MountTypeBind, got.Type)
	}
	if got.Source != wantSource {
		t.Fatalf("unexpected runtime mount source: got %q want %q", got.Source, wantSource)
	}
	if got.Target != "/workspace/cache" {
		t.Fatalf("unexpected runtime mount target: got %q", got.Target)
	}
	if got.ReadOnly {
		t.Fatalf("expected materialized empty dir mount to be writable")
	}
}

func TestPrepareRuntimeMountsCreatesEmptyDirWithDefaultMode(t *testing.T) {
	root := t.TempDir()

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
		},
	})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}

	info, err := os.Stat(runtimeMounts[0].Source)
	if err != nil {
		t.Fatalf("stat materialized empty dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("unexpected default mode: got %o want %o", got, 0o755)
	}
}

func TestPrepareRuntimeMountsCreatesEmptyDirWithExplicitMode(t *testing.T) {
	root := t.TempDir()

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
			Mode:   0o700,
		},
	})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}

	info, err := os.Stat(runtimeMounts[0].Source)
	if err != nil {
		t.Fatalf("stat materialized empty dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("unexpected explicit mode: got %o want %o", got, 0o700)
	}
}

func TestPrepareRuntimeMountsLeavesBindMountsUnchanged(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)
	mount := Mount{
		Type:     MountTypeBind,
		Source:   source,
		Target:   "/workspace/src",
		ReadOnly: true,
	}

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{mount})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}
	if len(runtimeMounts) != 1 {
		t.Fatalf("expected 1 runtime mount, got %d", len(runtimeMounts))
	}
	if got := runtimeMounts[0]; got != mount {
		t.Fatalf("expected bind mount unchanged: got %+v want %+v", got, mount)
	}
}

func TestPrepareRuntimeMountsCreatesReservedTargetMountpointUnderRoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{{
		Type:     MountTypeBind,
		Source:   source,
		Target:   "/etc/alternatives",
		ReadOnly: true,
	}})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}
	if len(runtimeMounts) != 1 {
		t.Fatalf("expected 1 runtime mount, got %d", len(runtimeMounts))
	}

	mountpoint := filepath.Join(root, "etc", "alternatives")
	info, err := os.Stat(mountpoint)
	if err != nil {
		t.Fatalf("expected reserved target mountpoint at %q: %v", mountpoint, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected reserved target mountpoint %q to be a directory", mountpoint)
	}
}

func TestStagedRootCleanupRemovesMaterializedEmptyDirs(t *testing.T) {
	root := t.TempDir()

	runtimeMounts, err := prepareRuntimeMounts(root, []Mount{
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
		},
	})
	if err != nil {
		t.Fatalf("prepareRuntimeMounts returned error: %v", err)
	}
	materialized := runtimeMounts[0].Source
	if _, err := os.Stat(materialized); err != nil {
		t.Fatalf("expected materialized empty dir to exist before cleanup: %v", err)
	}

	if err := removeAllForceWritable(root); err != nil {
		t.Fatalf("remove staged root: %v", err)
	}
	if _, err := os.Stat(materialized); !os.IsNotExist(err) {
		t.Fatalf("expected materialized empty dir to be removed with staged root cleanup, got err=%v", err)
	}
}

func TestRemoveAllForceWritableRemovesReadOnlyTree(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "readonly", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nested, "file.txt")
	if err := os.WriteFile(path, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(nested), 0o555); err != nil {
		t.Fatal(err)
	}

	if err := removeAllForceWritable(root); err != nil {
		t.Fatalf("removeAllForceWritable() error = %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("expected %q to be removed, got err=%v", root, err)
	}
}
