package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const (
	curlBinary       = "/usr/bin/curl"
	curlTarget       = "http://example.com"
	proxyBind        = "127.0.0.1:31111"
	sandboxAppBinary = "/app/bwrap-go"
)

func parseLddOutput(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if parts := strings.SplitN(line, "=>", 2); len(parts) == 2 {
			path := strings.Fields(strings.TrimSpace(parts[1]))
			if len(path) > 0 && strings.HasPrefix(path[0], "/") {
				paths = append(paths, path[0])
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "/") {
			paths = append(paths, fields[0])
		}
	}
	return paths
}

func stageSandboxRoot() (string, error) {
	root, err := os.MkdirTemp("", "bwrap-go-root-")
	if err != nil {
		return "", fmt.Errorf("create sandbox root: %w", err)
	}

	requiredFiles, err := runtimeFilesForSandbox()
	if err != nil {
		return "", err
	}
	for _, hostPath := range requiredFiles {
		if err := copyFileIntoRoot(root, hostPath); err != nil {
			return "", err
		}
	}
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	if err := copyFileToPath(root, executablePath, sandboxAppBinary); err != nil {
		return "", err
	}

	if err := writeSandboxConfig(root); err != nil {
		return "", err
	}

	return root, nil
}

func runtimeFilesForSandbox() ([]string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}

	binaries := []string{curlBinary, executablePath}
	var files []string
	for _, binary := range binaries {
		files = append(files, binary)

		runtimeFiles, err := runtimeFilesForBinary(binary)
		if err != nil {
			return nil, err
		}
		files = append(files, runtimeFiles...)
	}

	for _, extra := range []string{
		"/lib64/ld-linux-x86-64.so.2",
		"/usr/lib/libnss_files.so.2",
	} {
		if _, err := os.Stat(extra); err == nil {
			files = append(files, extra)
		}
	}

	slices.Sort(files)
	return slices.Compact(files), nil
}

func runtimeFilesForBinary(binaryPath string) ([]string, error) {
	output, err := exec.Command("ldd", binaryPath).CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "not a dynamic executable") {
			return nil, nil
		}
		return nil, fmt.Errorf("ldd %s: %w: %s", binaryPath, err, strings.TrimSpace(string(output)))
	}
	return parseLddOutput(string(output)), nil
}

func writeSandboxConfig(root string) error {
	files := map[string]string{
		"/etc/hosts":         "127.0.0.1 localhost\n::1 localhost\n",
		"/etc/nsswitch.conf": "hosts: files\n",
	}
	for path, content := range files {
		dest := filepath.Join(root, filepath.Clean(path))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dest, err)
		}
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
	}
	return nil
}

func copyFileIntoRoot(root, hostPath string) error {
	return copyFileToPath(root, hostPath, hostPath)
}

func copyFileToPath(root, hostPath, sandboxPath string) error {
	info, err := os.Stat(hostPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", hostPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", hostPath)
	}

	src, err := os.Open(hostPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", hostPath, err)
	}
	defer src.Close()

	dest := filepath.Join(root, filepath.Clean(sandboxPath))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}

	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer dst.Close()

	if _, err := dst.ReadFrom(src); err != nil {
		return fmt.Errorf("copy %s to %s: %w", hostPath, dest, err)
	}
	return nil
}

func buildBwrapArgs(root string) []string {
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

	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/tmp",
		"--",
		sandboxAppBinary,
		"child-proxy",
	)

	return args
}
