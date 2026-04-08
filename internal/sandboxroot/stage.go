package sandboxroot

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const DefaultSandboxBBoxPath = "/app/bbox"

var mitmTrustBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/cert.pem",
}

type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)

type StageOptions struct {
	Binaries    []string
	DockerBuild DockerBuildOptions
}

type StageResult struct {
	Root    string
	Builder *BuilderTooling
}

func Stage(opts StageOptions, runtimeBinary string, mitmCAPEM []byte, mode TrafficMode) (result StageResult, err error) {
	root, err := os.MkdirTemp("", "bwrap-go-root-")
	if err != nil {
		return StageResult{}, fmt.Errorf("create sandbox root: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()

	bboxHostPath, err := ResolveBinary(runtimeBinary)
	if err != nil {
		return StageResult{}, err
	}
	builder, err := ResolveDockerBuildSupport(opts.DockerBuild)
	if err != nil {
		return StageResult{}, err
	}

	var files []string
	for _, requested := range opts.Binaries {
		binaryPath, err := ResolveBinary(requested)
		if err != nil {
			return StageResult{}, err
		}
		commandFiles, err := FilesForCommand(binaryPath)
		if err != nil {
			return StageResult{}, err
		}
		files = append(files, commandFiles...)
	}
	if builder != nil {
		for _, hostPath := range []string{
			builder.BuildkitdPath,
			builder.BuildctlPath,
			builder.RuncPath,
		} {
			commandFiles, err := FilesForCommand(hostPath)
			if err != nil {
				return StageResult{}, err
			}
			files = append(files, commandFiles...)
		}
		shellFiles, err := FilesForCommand("/bin/sh")
		if err != nil {
			return StageResult{}, err
		}
		files = append(files, shellFiles...)
	}

	bboxRuntimeFiles, err := FilesForCommand(bboxHostPath)
	if err != nil {
		return StageResult{}, err
	}
	files = append(files, bboxRuntimeFiles...)

	extras := []string{
		"/lib64/ld-linux-x86-64.so.2",
	}
	if path, ok := FirstExistingPath(NSSModuleCandidatePaths("libnss_files.so.2")); ok {
		extras = append(extras, path)
		deps, err := RuntimeFilesForBinary(path)
		if err != nil {
			return StageResult{}, err
		}
		files = append(files, deps...)
	}
	if path, ok := FirstExistingPath(NSSModuleCandidatePaths("libnss_dns.so.2")); ok {
		extras = append(extras, path)
		deps, err := RuntimeFilesForBinary(path)
		if err != nil {
			return StageResult{}, err
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
		if err := CopyFileIntoRoot(root, hostPath); err != nil {
			return StageResult{}, err
		}
	}

	if err := CopyFileToPath(root, bboxHostPath, DefaultSandboxBBoxPath); err != nil {
		return StageResult{}, err
	}
	if builder != nil {
		for sandboxPath, hostPath := range map[string]string{
			DefaultSandboxBuildkitdPath: builder.BuildkitdPath,
			DefaultSandboxBuildctlPath:  builder.BuildctlPath,
			DefaultSandboxRuncPath:      builder.RuncPath,
		} {
			if err := CopyFileToPath(root, hostPath, sandboxPath); err != nil {
				return StageResult{}, err
			}
		}
		if err := WriteDockerBuildShim(root); err != nil {
			return StageResult{}, err
		}
	}

	if err := WriteSandboxConfig(root, mitmCAPEM, mode); err != nil {
		return StageResult{}, err
	}

	return StageResult{
		Root:    root,
		Builder: builder,
	}, nil
}

func WriteDockerBuildShim(root string) error {
	content := "#!/bin/sh\nexec /app/bbox internal-docker-build \"$@\"\n"
	path, err := SandboxPathInRoot(root, DefaultSandboxDockerShimPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create docker shim dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write docker shim: %w", err)
	}
	return nil
}

func WriteSandboxConfig(root string, mitmCAPEM []byte, mode TrafficMode) error {
	_ = mode

	nsswitchContent := "hosts: files dns\n"
	files := map[string]string{
		"/etc/hosts":         "127.0.0.1 localhost\n::1 localhost\n",
		"/etc/nsswitch.conf": nsswitchContent,
	}
	content, err := TransparentResolvConfContent()
	if err != nil {
		return err
	}
	files["/etc/resolv.conf"] = content
	trustBundle, err := HostTrustBundleContent()
	if err != nil {
		return err
	}
	if len(mitmCAPEM) > 0 {
		trustBundle = AppendTrustBundlePEM(trustBundle, mitmCAPEM)
	}
	for _, path := range mitmTrustBundlePaths {
		files[path] = string(trustBundle)
	}
	for path, content := range files {
		dest, err := SandboxPathInRoot(root, path)
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

func HostTrustBundleContent() ([]byte, error) {
	path, ok := FirstExistingPath(mitmTrustBundlePaths)
	if !ok {
		return nil, fmt.Errorf("no host trust bundle found in %v", mitmTrustBundlePaths)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host trust bundle %q: %w", path, err)
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("host trust bundle %q is empty", path)
	}
	return content, nil
}

func AppendTrustBundlePEM(base []byte, extra []byte) []byte {
	combined := append([]byte(nil), base...)
	if len(combined) > 0 && combined[len(combined)-1] != '\n' {
		combined = append(combined, '\n')
	}
	combined = append(combined, extra...)
	return combined
}

func TransparentResolvConfContent() (string, error) {
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

func CopyFileIntoRoot(root string, hostPath string) error {
	return CopyFileToPath(root, hostPath, hostPath)
}

func CopyFileToPath(root string, hostPath string, sandboxPath string) error {
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

	dest, err := SandboxPathInRoot(root, sandboxPath)
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

func SandboxPathInRoot(root string, sandboxPath string) (string, error) {
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

func NSSModuleCandidatePaths(module string) []string {
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

func FirstExistingPath(paths []string) (string, bool) {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
