package bbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

const (
	defaultSandboxBBoxPath           = "/app/bbox"
	defaultSandboxPayloadSeccompPath = "/app/bbox-payload-seccomp.bpf"
)

var mitmTrustBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
}

func resolveBinary(nameOrPath string) (string, error) {
	if nameOrPath == "" {
		return "", fmt.Errorf("binary path is required")
	}

	if strings.Contains(nameOrPath, string(filepath.Separator)) {
		absPath, err := filepath.Abs(nameOrPath)
		if err != nil {
			return "", fmt.Errorf("resolve absolute binary path %q: %w", nameOrPath, err)
		}
		if _, err := os.Stat(absPath); err != nil {
			return "", fmt.Errorf("binary %q: %w", absPath, err)
		}
		return absPath, nil
	}

	resolved, err := exec.LookPath(nameOrPath)
	if err != nil {
		return "", fmt.Errorf("resolve binary %q: %w", nameOrPath, err)
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve absolute binary path %q: %w", resolved, err)
	}
	return absPath, nil
}

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

func filesForCommand(commandPath string) ([]string, error) {
	return filesForCommandRecursive(commandPath, map[string]struct{}{})
}

func filesForCommandRecursive(commandPath string, seen map[string]struct{}) ([]string, error) {
	commandPath = filepath.Clean(commandPath)
	if _, ok := seen[commandPath]; ok {
		return nil, nil
	}
	seen[commandPath] = struct{}{}

	files := []string{commandPath}

	runtimeFiles, err := runtimeFilesForBinary(commandPath)
	if err != nil {
		return nil, err
	}
	files = append(files, runtimeFiles...)

	interpreters, err := scriptInterpreterChain(commandPath)
	if err != nil {
		return nil, err
	}
	for _, interpreter := range interpreters {
		interpreterFiles, err := filesForCommandRecursive(interpreter, seen)
		if err != nil {
			return nil, err
		}
		files = append(files, interpreterFiles...)
	}

	return files, nil
}

func scriptInterpreterChain(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read potential script %q: %w", path, err)
	}

	line, _, _ := strings.Cut(string(content), "\n")
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return nil, nil
	}

	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return nil, fmt.Errorf("script %q has an empty shebang", path)
	}

	interpreter := fields[0]
	if !filepath.IsAbs(interpreter) {
		return nil, fmt.Errorf("script %q uses non-absolute shebang interpreter %q", path, interpreter)
	}

	chain := []string{interpreter}
	if filepath.Base(interpreter) == "env" {
		if target, ok := envShebangTarget(fields[1:]); ok {
			resolved, err := resolveBinary(target)
			if err != nil {
				return nil, fmt.Errorf("resolve env shebang target %q for %q: %w", target, path, err)
			}
			chain = append(chain, resolved)
		}
	}

	return chain, nil
}

func envShebangTarget(args []string) (string, bool) {
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, true
	}
	return "", false
}

func stageSandboxRoot(opts SandboxOptions, runtimeBinary string, mitmCAPEM []byte, mode TrafficMode) (root string, err error) {
	root, err = os.MkdirTemp("", "bwrap-go-root-")
	if err != nil {
		return "", fmt.Errorf("create sandbox root: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()

	bboxHostPath, err := resolveBinary(runtimeBinary)
	if err != nil {
		return "", err
	}

	var files []string
	for _, requested := range opts.Binaries {
		binaryPath, err := resolveBinary(requested)
		if err != nil {
			return "", err
		}
		commandFiles, err := filesForCommand(binaryPath)
		if err != nil {
			return "", err
		}
		files = append(files, commandFiles...)
	}

	bboxRuntimeFiles, err := filesForCommand(bboxHostPath)
	if err != nil {
		return "", err
	}
	files = append(files, bboxRuntimeFiles...)

	extras := []string{
		"/lib64/ld-linux-x86-64.so.2",
	}
	if path, ok := firstExistingPath(nssModuleCandidatePaths("libnss_files.so.2")); ok {
		extras = append(extras, path)
		deps, err := runtimeFilesForBinary(path)
		if err != nil {
			return "", err
		}
		files = append(files, deps...)
	}
	if path, ok := firstExistingPath(nssModuleCandidatePaths("libnss_dns.so.2")); ok {
		extras = append(extras, path)
		deps, err := runtimeFilesForBinary(path)
		if err != nil {
			return "", err
		}
		files = append(files, deps...)
	}
	for _, extra := range extras {
		if _, err := os.Stat(extra); err == nil {
			files = append(files, extra)
		}
	}

	slices.Sort(files)
	for _, hostPath := range slices.Compact(files) {
		if err := copyFileIntoRoot(root, hostPath); err != nil {
			return "", err
		}
	}

	if err := copyFileToPath(root, bboxHostPath, defaultSandboxBBoxPath); err != nil {
		return "", err
	}

	if err := writeSandboxConfig(root, mitmCAPEM, mode); err != nil {
		return "", err
	}

	return root, nil
}

func writeSandboxConfig(root string, mitmCAPEM []byte, mode TrafficMode) error {
	nsswitchContent := "hosts: files dns\n"
	files := map[string]string{
		"/etc/hosts":         "127.0.0.1 localhost\n::1 localhost\n",
		"/etc/nsswitch.conf": nsswitchContent,
	}
	content, err := transparentResolvConfContent()
	if err != nil {
		return err
	}
	files["/etc/resolv.conf"] = content
	if len(mitmCAPEM) > 0 {
		for _, path := range mitmTrustBundlePaths {
			files[path] = string(mitmCAPEM)
		}
	}
	for path, content := range files {
		dest, err := sandboxPathInRoot(root, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dest, err)
		}
		if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
	}
	return nil
}

func stageTransparentPayloadSeccompProgram(root string, opts SeccompOptions) (string, error) {
	program, err := compileSeccompProgram(opts)
	if err != nil {
		return "", err
	}
	if len(program) == 0 {
		return "", nil
	}

	dest, err := sandboxPathInRoot(root, defaultSandboxPayloadSeccompPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	if err := os.WriteFile(dest, program, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", dest, err)
	}
	return defaultSandboxPayloadSeccompPath, nil
}

func transparentResolvConfContent() (string, error) {
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read host resolv.conf: %w", err)
	}

	var nameservers []string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "nameserver ") {
			nameservers = append(nameservers, trimmed)
		}
	}
	if len(nameservers) == 0 {
		return "", fmt.Errorf("host resolv.conf does not contain nameserver entries")
	}

	return strings.Join(nameservers, "\n") + "\n", nil
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

	dest, err := sandboxPathInRoot(root, sandboxPath)
	if err != nil {
		return err
	}
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

func sandboxPathInRoot(root, sandboxPath string) (string, error) {
	cleanRoot := filepath.Clean(root)
	if cleanRoot == "." || cleanRoot == "" {
		return "", fmt.Errorf("staging root is required")
	}

	cleanSandboxPath := filepath.Clean(sandboxPath)
	cleanSandboxPath = strings.TrimPrefix(cleanSandboxPath, string(filepath.Separator))
	dest := filepath.Join(cleanRoot, cleanSandboxPath)

	rel, err := filepath.Rel(cleanRoot, dest)
	if err != nil {
		return "", fmt.Errorf("map sandbox path %q into %q: %w", sandboxPath, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sandbox path %q escapes staging root", sandboxPath)
	}

	return dest, nil
}

func nssModuleCandidatePaths(module string) []string {
	var candidates []string
	baseDirs := []string{"/usr/lib", "/lib", "/usr/lib64", "/lib64"}
	for _, dir := range baseDirs {
		candidates = append(candidates, filepath.Join(dir, module))
	}
	for _, root := range []string{"/usr/lib", "/lib"} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		var multiarch []string
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, "-linux-gnu") {
				multiarch = append(multiarch, filepath.Join(root, name))
			}
		}
		slices.Sort(multiarch)
		for _, dir := range multiarch {
			candidates = append(candidates, filepath.Join(dir, module))
		}
	}
	return candidates
}

func firstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
