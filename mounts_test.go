package bbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateMountsAcceptsBindMount(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	err := validateMounts([]Mount{
		{
			Type:     MountTypeBind,
			Source:   source,
			Target:   "/workspace",
			ReadOnly: true,
		},
	})
	if err != nil {
		t.Fatalf("expected bind mount to be valid: %v", err)
	}
}

func TestValidateMountsAcceptsEmptyDirMount(t *testing.T) {
	err := validateMounts([]Mount{
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
		},
	})
	if err != nil {
		t.Fatalf("expected empty_dir mount to be valid: %v", err)
	}
}

func TestValidateMountsRejectsBindMountWithoutSource(t *testing.T) {
	err := validateMounts([]Mount{
		{
			Type:   MountTypeBind,
			Target: "/workspace",
		},
	})
	if err == nil {
		t.Fatal("expected bind mount without source to be rejected")
	}
}

func TestValidateMountsRejectsEmptyDirWithSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	err := validateMounts([]Mount{
		{
			Type:   MountTypeEmptyDir,
			Source: source,
			Target: "/workspace",
		},
	})
	if err == nil {
		t.Fatal("expected empty_dir mount with source to be rejected")
	}
}

func TestValidateMountsRejectsBindMountWithMode(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	err := validateMounts([]Mount{
		{
			Type:   MountTypeBind,
			Source: source,
			Target: "/workspace",
			Mode:   0o755,
		},
	})
	if err == nil {
		t.Fatal("expected bind mount with mode to be rejected")
	}
}

func TestValidateMountsRejectsUnknownMountType(t *testing.T) {
	err := validateMounts([]Mount{
		{
			Type:   MountType("mystery"),
			Target: "/workspace",
		},
	})
	if err == nil {
		t.Fatal("expected unknown mount type to be rejected")
	}
}

func TestValidateMountsRejectsOverlappingTargetsAcrossTypes(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	mustMkdirAll(t, source)

	err := validateMounts([]Mount{
		{
			Type:   MountTypeBind,
			Source: source,
			Target: "/workspace",
		},
		{
			Type:   MountTypeEmptyDir,
			Target: "/workspace/cache",
		},
	})
	if err == nil {
		t.Fatal("expected overlapping targets across mount types to be rejected")
	}
}

func TestValidateMountsRejectsReservedTargetsForEmptyDir(t *testing.T) {
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
			{
				Type:   MountTypeEmptyDir,
				Target: target,
			},
		})
		if err == nil {
			t.Fatalf("expected reserved target %q to be rejected", target)
		}
	}
}

func TestBuildBwrapArgsUsesBindFlagsForTypedBindMounts(t *testing.T) {
	readOnlySource := filepath.Join(t.TempDir(), "ro")
	mustMkdirAll(t, readOnlySource)
	readWriteSource := filepath.Join(t.TempDir(), "rw")
	mustMkdirAll(t, readWriteSource)

	args := buildBwrapArgs(bwrapArgsConfig{
		root:            t.TempDir(),
		helperPath:      "/app/bbox",
		proxyListenAddr: "127.0.0.1:31111",
		bridgeFD:        3,
		mounts: []Mount{
			{
				Type:     MountTypeBind,
				Source:   readOnlySource,
				Target:   "/readonly",
				ReadOnly: true,
			},
			{
				Type:   MountTypeBind,
				Source: readWriteSource,
				Target: "/readwrite",
			},
			{
				Type:   MountTypeEmptyDir,
				Target: "/scratch",
			},
		},
	})

	if !containsArgSequence(args, []string{"--ro-bind", readOnlySource, "/readonly"}) {
		t.Fatalf("expected read-only bind mount args, got %v", args)
	}
	if !containsArgSequence(args, []string{"--bind", readWriteSource, "/readwrite"}) {
		t.Fatalf("expected read-write bind mount args, got %v", args)
	}
	if containsArgSequence(args, []string{"--bind", "", "/scratch"}) {
		t.Fatalf("expected non-bind mounts to be excluded from bwrap args, got %v", args)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}
