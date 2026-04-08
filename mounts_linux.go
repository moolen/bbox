//go:build linux

package bbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const runtimeEmptyDirBase = ".bbox-empty-dirs"

func prepareRuntimeMounts(root string, mounts []Mount) ([]Mount, error) {
	runtimeMounts := make([]Mount, 0, len(mounts))

	for idx, mount := range mounts {
		switch mount.Type {
		case MountTypeBind:
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
