//go:build linux

package bbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/moolen/bbox/internal/sandboxroot"
)

const runtimeEmptyDirBase = ".bbox-empty-dirs"

func prepareRuntimeMounts(root string, mounts []Mount) ([]Mount, error) {
	runtimeMounts := make([]Mount, 0, len(mounts))

	for idx, mount := range mounts {
		switch mount.Type {
		case MountTypeBind:
			if err := materializeReservedMountTarget(root, mount); err != nil {
				return nil, err
			}
			runtimeMounts = append(runtimeMounts, mount)
		case MountTypeEmptyDir:
			mode := os.FileMode(mount.Mode)
			if mode == 0 {
				mode = 0o755
			}

			hostDir := filepath.Join(root, runtimeEmptyDirBase, strconv.Itoa(idx))
			if err := os.MkdirAll(hostDir, mode); err != nil {
				return nil, fmt.Errorf("create empty_dir mount %q: %w", mount.Target, err)
			}
			if err := os.Chmod(hostDir, mode); err != nil {
				return nil, fmt.Errorf("chmod empty_dir mount %q: %w", mount.Target, err)
			}

			runtimeMounts = append(runtimeMounts, Mount{
				Type:   MountTypeBind,
				Source: hostDir,
				Target: mount.Target,
			})
		default:
			return nil, fmt.Errorf("unsupported mount type %q", mount.Type)
		}
	}

	return runtimeMounts, nil
}

func materializeReservedMountTarget(root string, mount Mount) error {
	target := filepath.Clean(mount.Target)
	if !overlapsReservedSandboxTarget(target) {
		return nil
	}

	info, err := os.Stat(mount.Source)
	if err != nil {
		return fmt.Errorf("stat runtime mount source %q: %w", mount.Source, err)
	}

	dest, err := sandboxroot.SandboxPathInRoot(root, target)
	if err != nil {
		return fmt.Errorf("prepare runtime mount target %q: %w", mount.Target, err)
	}
	if info.IsDir() {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return fmt.Errorf("create runtime mount target %q: %w", mount.Target, err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create runtime mount target parent %q: %w", mount.Target, err)
	}
	file, err := os.OpenFile(dest, os.O_CREATE, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create runtime mount target %q: %w", mount.Target, err)
	}
	return file.Close()
}

func overlapsReservedSandboxTarget(target string) bool {
	for _, reservedTarget := range reservedSandboxTargets {
		if targetsOverlap(target, reservedTarget) {
			return true
		}
	}
	return false
}
