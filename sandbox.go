package bbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	proxyBind = "127.0.0.1:31111"
)

type Sandbox struct {
	manager *ProxyManager
	id      string
	root    string
	client  *helperClient
	cmd     *exec.Cmd
	done    chan error

	baseEnv []string
	workDir string

	helperStderr *lockedBuffer
	registered   bool

	closeOnce sync.Once
	closeErr  error
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func proxyURL() string {
	return "http://" + proxyBind
}

func (m *ProxyManager) NewSandbox(ctx context.Context, opts SandboxOptions) (_ *Sandbox, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateSandboxOptions(opts); err != nil {
		return nil, err
	}

	policy, err := compilePolicy(opts.Policy)
	if err != nil {
		return nil, err
	}

	helperBinary, err := m.helperBinary()
	if err != nil {
		return nil, err
	}

	root, err := stageSandboxRoot(opts, helperBinary)
	if err != nil {
		return nil, err
	}

	parentBridge, childBridge, err := openBridgePair()
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}

	helperStderr := &lockedBuffer{}
	cmd := exec.Command("bwrap", buildBwrapArgs(root, defaultSandboxHelperPath, opts.Mounts)...)
	cmd.Stderr = helperStderr
	cmd.Stdout = helperStderr
	cmd.ExtraFiles = []*os.File{childBridge}

	if err := cmd.Start(); err != nil {
		_ = childBridge.Close()
		_ = parentBridge.Close()
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("start bwrap helper: %w", err)
	}
	_ = childBridge.Close()

	sandboxID := m.nextSandboxName(opts.Name)
	client := newHelperClient(m, sandboxID, parentBridge)
	sandbox := &Sandbox{
		manager:      m,
		id:           sandboxID,
		root:         root,
		client:       client,
		cmd:          cmd,
		done:         make(chan error, 1),
		baseEnv:      mergeEnv(defaultRunEnv(), opts.Env),
		workDir:      opts.WorkDir,
		helperStderr: helperStderr,
	}

	go func() {
		sandbox.done <- cmd.Wait()
	}()

	if err := client.Start(ctx); err != nil {
		sandbox.closeErr = nil
		_ = sandbox.Close()
		return nil, fmt.Errorf("start sandbox helper: %w%s", err, sandbox.helperErrorSuffix())
	}

	if err := m.registerSandbox(sandboxID, policy); err != nil {
		sandbox.closeErr = nil
		_ = sandbox.Close()
		return nil, err
	}
	sandbox.registered = true
	if err := m.attachSandbox(sandboxID, sandbox); err != nil {
		sandbox.closeErr = nil
		_ = sandbox.Close()
		return nil, err
	}

	return sandbox, nil
}

func (s *Sandbox) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if len(argv) == 0 {
		return nil, errors.New("argv must not be empty")
	}
	if s == nil || s.client == nil {
		return nil, errors.New("sandbox is not running")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runOpts := RunOptions{
		Env:     mergeEnv(s.baseEnv, opts.Env),
		WorkDir: opts.WorkDir,
	}
	if runOpts.WorkDir == "" {
		runOpts.WorkDir = s.workDir
	}

	return s.client.Run(ctx, argv, runOpts)
}

func (s *Sandbox) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		var closeErr error

		if s.cmd != nil && s.cmd.Process != nil {
			if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
				closeErr = errors.Join(closeErr, fmt.Errorf("signal sandbox helper: %w", err))
			}
		}
		if s.client != nil {
			if err := s.client.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close sandbox bridge: %w", err))
			}
		}
		if s.done != nil {
			waitErr := waitWithTimeout(s.done, 5*time.Second)
			if waitErr != nil {
				if s.cmd != nil && s.cmd.Process != nil {
					_ = s.cmd.Process.Kill()
				}
				waitErr = waitWithTimeout(s.done, 5*time.Second)
			}
			if normalized := normalizeHelperExit(waitErr); normalized != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("wait for sandbox helper: %w%s", normalized, s.helperErrorSuffix()))
			}
		}

		if s.manager != nil && s.registered {
			s.manager.unregisterSandbox(s.id)
			s.registered = false
		}
		if s.root != "" {
			if err := os.RemoveAll(s.root); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("remove staged root %q: %w", s.root, err))
			}
		}

		s.closeErr = closeErr
	})

	return s.closeErr
}

func validateSandboxOptions(opts SandboxOptions) error {
	if err := validateMounts(opts.Mounts); err != nil {
		return err
	}
	if opts.WorkDir != "" && !filepath.IsAbs(opts.WorkDir) {
		return fmt.Errorf("sandbox workdir %q must be absolute", opts.WorkDir)
	}
	return nil
}

func openBridgePair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create sandbox bridge socketpair: %w", err)
	}

	parent := os.NewFile(uintptr(fds[0]), "bbox-bridge-parent")
	child := os.NewFile(uintptr(fds[1]), "bbox-bridge-child")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		}
		if child != nil {
			_ = child.Close()
		}
		return nil, nil, errors.New("wrap sandbox bridge socketpair")
	}
	return parent, child, nil
}

func defaultRunEnv() []string {
	return []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=" + proxyURL(),
		"http_proxy=" + proxyURL(),
	}
}

func mergeEnv(groups ...[]string) []string {
	var merged []string
	indexByKey := make(map[string]int)

	for _, group := range groups {
		for _, entry := range group {
			if entry == "" {
				continue
			}

			key := entry
			if split := strings.IndexByte(entry, '='); split >= 0 {
				key = entry[:split]
			}

			if idx, ok := indexByKey[key]; ok {
				merged[idx] = entry
				continue
			}

			indexByKey[key] = len(merged)
			merged = append(merged, entry)
		}
	}

	return merged
}

func waitWithTimeout(done <-chan error, timeout time.Duration) error {
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errors.New("timeout waiting for sandbox helper exit")
	}
}

func normalizeHelperExit(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() && (status.Signal() == syscall.SIGTERM || status.Signal() == syscall.SIGKILL) {
				return nil
			}
		}
	}
	return err
}

func (s *Sandbox) helperErrorSuffix() string {
	if s == nil || s.helperStderr == nil {
		return ""
	}

	stderr := strings.TrimSpace(s.helperStderr.String())
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
