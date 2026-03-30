package bbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var packageRootRuntimeCaller = runtime.Caller
var packageRootGetwd = os.Getwd
var helperBinaryExecutablePath = os.Executable

const (
	helperBinaryName          = "bbox-helper"
	seccompLauncherBinaryName = "bbox-seccomp-launcher"
)

type helperBinaryResolver struct {
	once sync.Once

	executablePath func() (string, error)
	packageRoot    func() (string, error)
	makeTempDir    func(string, string) (string, error)
	buildHelper    func(string, string) error
	buildLauncher  func(string, string) error
	removeAll      func(string) error

	path string
	dir  string
	err  error
}

func newHelperBinaryResolver() *helperBinaryResolver {
	return &helperBinaryResolver{
		executablePath: helperBinaryExecutablePath,
		packageRoot:    packageRoot,
		makeTempDir:    os.MkdirTemp,
		buildHelper:    buildHelperBinary,
		buildLauncher:  buildSeccompLauncherBinary,
		removeAll:      os.RemoveAll,
	}
}

func (r *helperBinaryResolver) HelperBinary() (string, error) {
	if r == nil {
		return "", fmt.Errorf("helper binary resolver is required")
	}

	r.once.Do(func() {
		if helperPath, ok := r.packagedHelperBinary(); ok {
			r.path = helperPath
			return
		}

		moduleRoot, err := r.packageRoot()
		if err != nil {
			r.err = err
			return
		}

		buildDir, err := r.makeTempDir("", "bbox-helper-build-")
		if err != nil {
			r.err = fmt.Errorf("create helper build dir: %w", err)
			return
		}

		helperPath := filepath.Join(buildDir, helperBinaryName)
		if err := r.buildHelper(moduleRoot, helperPath); err != nil {
			_ = r.removeAll(buildDir)
			r.err = err
			return
		}
		launcherPath := filepath.Join(buildDir, seccompLauncherBinaryName)
		if err := r.buildLauncher(moduleRoot, launcherPath); err != nil {
			_ = r.removeAll(buildDir)
			r.err = err
			return
		}

		r.dir = buildDir
		r.path = helperPath
	})

	if r.err != nil {
		return "", r.err
	}
	if r.path == "" {
		return "", fmt.Errorf("helper binary path is empty")
	}
	return r.path, nil
}

func (r *helperBinaryResolver) Cleanup() error {
	if r == nil || r.dir == "" {
		return nil
	}
	return r.removeAll(r.dir)
}

func (r *helperBinaryResolver) packagedHelperBinary() (string, bool) {
	if r == nil || r.executablePath == nil {
		return "", false
	}

	exePath, err := r.executablePath()
	if err != nil || strings.TrimSpace(exePath) == "" {
		return "", false
	}

	exePath = filepath.Clean(exePath)
	helperPath := filepath.Join(filepath.Dir(exePath), helperBinaryName)
	launcherPath := filepath.Join(filepath.Dir(exePath), seccompLauncherBinaryName)
	if !regularFileExists(helperPath) || !regularFileExists(launcherPath) {
		return "", false
	}
	return helperPath, true
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func packageRoot() (string, error) {
	if _, file, _, ok := packageRootRuntimeCaller(0); ok {
		if root, found := findPackageRoot(filepath.Dir(file)); found {
			return root, nil
		}
	}

	cwd, err := packageRootGetwd()
	if err != nil {
		return "", fmt.Errorf("determine package root: %w", err)
	}
	if root, found := findPackageRoot(cwd); found {
		return root, nil
	}

	return "", fmt.Errorf("locate package root from working directory %q", cwd)
}

func findPackageRoot(start string) (string, bool) {
	if start == "" {
		return "", false
	}

	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}

	for {
		if isPackageRoot(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func isPackageRoot(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "bbox-helper", "main.go")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "bbox-seccomp-launcher", "main.c")); err != nil {
		return false
	}
	return true
}

func buildHelperBinary(moduleRoot, helperPath string) error {
	cmd := exec.Command("go", "build", "-o", helperPath, "./cmd/bbox-helper")
	cmd.Dir = moduleRoot

	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	msg := strings.TrimSpace(string(output))
	if msg != "" {
		return fmt.Errorf("build helper binary: %w: %s", err, msg)
	}
	return fmt.Errorf("build helper binary: %w", err)
}

func buildSeccompLauncherBinary(moduleRoot, launcherPath string) error {
	compiler := strings.TrimSpace(os.Getenv("CC"))
	if compiler == "" {
		compiler = "cc"
	}

	cmd := exec.Command(compiler, "-O2", "-o", launcherPath, "./cmd/bbox-seccomp-launcher/main.c")
	cmd.Dir = moduleRoot

	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	msg := strings.TrimSpace(string(output))
	if msg != "" {
		return fmt.Errorf("build seccomp launcher binary: %w: %s", err, msg)
	}
	return fmt.Errorf("build seccomp launcher binary: %w", err)
}
