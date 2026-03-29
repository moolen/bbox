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

type helperBinaryResolver struct {
	once sync.Once

	packageRoot func() (string, error)
	makeTempDir func(string, string) (string, error)
	buildHelper func(string, string) error
	removeAll   func(string) error

	path string
	dir  string
	err  error
}

func newHelperBinaryResolver() *helperBinaryResolver {
	return &helperBinaryResolver{
		packageRoot: packageRoot,
		makeTempDir: os.MkdirTemp,
		buildHelper: buildHelperBinary,
		removeAll:   os.RemoveAll,
	}
}

func (r *helperBinaryResolver) HelperBinary() (string, error) {
	if r == nil {
		return "", fmt.Errorf("helper binary resolver is required")
	}

	r.once.Do(func() {
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

		helperPath := filepath.Join(buildDir, "bbox-helper")
		if err := r.buildHelper(moduleRoot, helperPath); err != nil {
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
