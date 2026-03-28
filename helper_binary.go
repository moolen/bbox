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
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("determine package root: runtime caller unavailable")
	}

	root := filepath.Dir(file)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("locate package root from %q: %w", root, err)
	}
	return root, nil
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
