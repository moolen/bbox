package bbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var reservedSandboxTargets = []string{
	"/app",
	"/usr",
	"/etc",
	"/lib",
	"/lib64",
	"/proc",
	"/dev",
	"/tmp",
}

func validateMounts(mounts []Mount) error {
	seen := make(map[string]Mount)
	for _, m := range mounts {
		if !filepath.IsAbs(m.Source) {
			return fmt.Errorf("mount source %q must be absolute", m.Source)
		}
		if _, err := os.Stat(m.Source); err != nil {
			return fmt.Errorf("mount source %q: %w", m.Source, err)
		}
		if !filepath.IsAbs(m.Target) {
			return fmt.Errorf("mount target %q must be absolute", m.Target)
		}

		target := filepath.Clean(m.Target)
		for _, reservedTarget := range reservedSandboxTargets {
			if targetsOverlap(target, reservedTarget) {
				return fmt.Errorf("mount target %q overlaps reserved sandbox path %q", m.Target, reservedTarget)
			}
		}
		if prev, ok := seen[target]; ok {
			return fmt.Errorf("mount target %q conflicts with %q", m.Target, prev.Source)
		}
		for existingTarget, prev := range seen {
			if targetsOverlap(existingTarget, target) {
				return fmt.Errorf("mount target %q overlaps with %q from %q", m.Target, existingTarget, prev.Source)
			}
		}
		seen[target] = m
	}
	return nil
}

func targetsOverlap(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if a == b {
		return true
	}
	if a == "/" || b == "/" {
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func buildBwrapArgs(root string, helperPath string, mounts []Mount) []string {
	args := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-net",
		"--die-with-parent",
		"--new-session",
		"--clearenv",
		"--setenv", "PATH", "/usr/bin",
		"--setenv", "HTTP_PROXY", proxyURL(),
		"--setenv", "http_proxy", proxyURL(),
	}

	for _, dir := range []string{"app", "usr", "etc", "lib", "lib64"} {
		hostDir := filepath.Join(root, dir)
		if info, err := os.Stat(hostDir); err == nil && info.IsDir() {
			args = append(args, "--ro-bind", hostDir, "/"+dir)
		}
	}

	for _, mount := range mounts {
		flag := "--bind"
		if mount.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, mount.Source, filepath.Clean(mount.Target))
	}

	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/tmp",
		"--",
		helperPath,
		"child-proxy",
	)

	return args
}
