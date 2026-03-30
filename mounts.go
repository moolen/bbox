package bbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

type bwrapArgsConfig struct {
	root                string
	helperPath          string
	proxyListenAddr     string
	mitm                MITMOptions
	maxRequestBodyBytes int64
	mounts              []Mount
	trafficMode         TrafficMode
	bridgeFD            int
	seccompFD           int
}

func buildBwrapArgs(cfg bwrapArgsConfig) []string {
	normalizedMode := normalizeTrafficMode(cfg.trafficMode)
	args := []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-net",
		"--die-with-parent",
		"--new-session",
		"--clearenv",
		"--setenv", "PATH", "/usr/bin",
	}
	if cfg.seccompFD >= 0 {
		args = append(args, "--seccomp", strconv.Itoa(cfg.seccompFD))
	}

	for _, dir := range []string{"app", "usr", "etc", "lib", "lib64"} {
		hostDir := filepath.Join(cfg.root, dir)
		if info, err := os.Stat(hostDir); err == nil && info.IsDir() {
			args = append(args, "--ro-bind", hostDir, "/"+dir)
		}
	}

	for _, mount := range cfg.mounts {
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
		cfg.helperPath,
		"internal-helper",
		"--bridge-fd", strconv.Itoa(cfg.bridgeFD),
		"--proxy-addr", cfg.proxyListenAddr,
		"--traffic-mode", string(normalizedMode),
		"--mitm-enabled="+fmt.Sprintf("%t", cfg.mitm.Enabled),
		"--max-request-body-bytes", fmt.Sprintf("%d", cfg.maxRequestBodyBytes),
		"child-proxy",
	)

	return args
}
