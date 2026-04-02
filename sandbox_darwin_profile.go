package bbox

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type darwinProfileConfig struct {
	WorkDir          string
	AllowedExecPaths []string
	ProxyAddrs       []string
}

var darwinSystemReadPaths = []string{
	"/System",
	"/Library",
	"/usr",
	"/bin",
	"/sbin",
	"/dev",
	"/etc",
	"/private/etc",
	"/var/db",
	"/private/var/db",
	"/var/folders",
	"/private/var/folders",
	"/tmp",
	"/private/tmp",
}

func generateDarwinSeatbeltProfile(cfg darwinProfileConfig) (string, error) {
	workDir := strings.TrimSpace(cfg.WorkDir)
	if workDir == "" || !filepath.IsAbs(workDir) {
		return "", fmt.Errorf("darwin sandbox workdir %q must be absolute", cfg.WorkDir)
	}

	execPaths, err := normalizeDarwinExecPaths(cfg.AllowedExecPaths)
	if err != nil {
		return "", err
	}
	ports, err := normalizeDarwinProxyPorts(cfg.ProxyAddrs)
	if err != nil {
		return "", err
	}

	rules := make([]string, 0, 64)
	addRule := func(lines ...string) {
		rules = append(rules, lines...)
	}

	addRule(
		"(version 1)",
		"(deny default)",
		"",
		"; Process",
		"(allow process-fork)",
		"(allow process-info*)",
		"(allow signal (target same-sandbox))",
		"",
		"; Basic runtime services",
		"(allow user-preference-read)",
		"(allow ipc-posix-shm)",
		"(allow ipc-posix-sem)",
		"(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
		"(allow mach-lookup",
		`  (global-name "com.apple.system.logger")`,
		`  (global-name "com.apple.SystemConfiguration.configd")`,
		`  (global-name "com.apple.trustd.agent")`,
		`  (global-name "com.apple.securityd.xpc")`,
		`  (global-name "com.apple.system.opendirectoryd.libinfo")`,
		`  (global-name "com.apple.system.opendirectoryd.membership"))`,
		"(allow sysctl-read)",
		"",
		"; File reads",
		"(allow file-read-metadata)",
		`(allow file-read-data (literal "/"))`,
	)

	for _, path := range darwinSystemReadPaths {
		addRule(
			"(allow file-read*",
			fmt.Sprintf("  (subpath %q))", path),
		)
	}

	for _, path := range expandDarwinPathVariants([]string{workDir}) {
		addRule(
			"(allow file-read*",
			fmt.Sprintf("  (subpath %q))", path),
		)
		addRule(
			"(allow file-write*",
			fmt.Sprintf("  (subpath %q))", path),
		)
	}

	for _, path := range expandDarwinPathVariants(execPaths) {
		addRule(
			"(allow process-exec",
			fmt.Sprintf("  (literal %q))", path),
		)
		addRule(
			"(allow file-read*",
			fmt.Sprintf("  (literal %q))", path),
		)
		for _, ancestor := range darwinAncestorDirs(path) {
			addRule(
				"(allow file-read-metadata",
				fmt.Sprintf("  (literal %q))", ancestor),
			)
		}
	}

	addRule("", "; Network")
	for _, port := range ports {
		addRule(fmt.Sprintf(`(allow network-outbound (remote ip "localhost:%d"))`, port))
	}

	return strings.Join(rules, "\n") + "\n", nil
}

func normalizeDarwinExecPaths(paths []string) ([]string, error) {
	normalized := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("darwin sandbox executable %q must be absolute", path)
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		normalized = append(normalized, path)
	}
	slices.Sort(normalized)
	return normalized, nil
}

func normalizeDarwinProxyPorts(addrs []string) ([]int, error) {
	ports := make([]int, 0, len(addrs))
	seen := make(map[int]struct{}, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse darwin proxy addr %q: %w", addr, err)
		}
		if !isDarwinLoopbackHost(host) {
			return nil, fmt.Errorf("darwin proxy addr %q must use loopback host", addr)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("darwin proxy addr %q has invalid port", addr)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports, nil
}

func isDarwinLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func expandDarwinPathVariants(paths []string) []string {
	expanded := make([]string, 0, len(paths)*2)
	seen := make(map[string]struct{}, len(paths)*2)
	for _, path := range paths {
		for _, candidate := range []string{filepath.Clean(path), darwinMirrorTmpPath(path)} {
			if candidate == "" {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			expanded = append(expanded, candidate)
		}
	}
	return expanded
}

func darwinMirrorTmpPath(path string) string {
	switch {
	case path == "/tmp":
		return "/private/tmp"
	case path == "/private/tmp":
		return "/tmp"
	case strings.HasPrefix(path, "/tmp/"):
		return "/private" + path
	case strings.HasPrefix(path, "/private/tmp/"):
		return strings.TrimPrefix(path, "/private")
	default:
		return ""
	}
}

func darwinAncestorDirs(path string) []string {
	ancestors := make([]string, 0, 8)
	current := filepath.Clean(filepath.Dir(path))
	for current != "/" && current != "." {
		ancestors = append(ancestors, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	ancestors = append(ancestors, "/")
	slices.Sort(ancestors)
	return slices.Compact(ancestors)
}
