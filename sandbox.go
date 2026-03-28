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

// Sandbox is a long-lived bubblewrap helper plus its staged filesystem root and
// per-sandbox runtime configuration.
type Sandbox struct {
	manager *ProxyManager
	id      string
	root    string
	client  *helperClient
	cmd     *exec.Cmd
	done    chan error

	trafficMode TrafficMode
	proxyAddr   string
	baseEnv     []string
	workDir     string

	helperLogMu     sync.Mutex
	helperLogFile   *os.File
	helperLogPath   string
	helperLogCached string
	registered      bool

	closeOnce sync.Once
	closeErr  error
}

func proxyURL(addr string) string {
	return "http://" + addr
}

// NewSandbox stages the requested binaries, starts a helper inside bubblewrap,
// and registers the sandbox with the manager's host-side policy engine.
func (m *ProxyManager) NewSandbox(ctx context.Context, opts SandboxOptions) (_ *Sandbox, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateSandboxOptions(opts, m.mitm.Enabled); err != nil {
		return nil, err
	}
	mode := normalizeTrafficMode(opts.TrafficMode)

	policy, err := compilePolicy(opts.Policy)
	if err != nil {
		return nil, err
	}

	helperBinary, err := m.helperBinary()
	if err != nil {
		return nil, err
	}

	root, err := stageSandboxRoot(opts, helperBinary, m.CACertPEM(), mode)
	if err != nil {
		return nil, err
	}

	parentBridge, childBridge, err := openBridgePair()
	if err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}

	helperLog, err := os.CreateTemp("", "bbox-helper-log-")
	if err != nil {
		_ = childBridge.Close()
		_ = parentBridge.Close()
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("create helper log file: %w", err)
	}

	cmd := exec.Command("bwrap", buildBwrapArgs(root, defaultSandboxHelperPath, m.listenAddr, m.mitm, opts.Mounts, mode)...)
	cmd.Stderr = helperLog
	cmd.Stdout = helperLog
	cmd.ExtraFiles = []*os.File{childBridge}

	if err := cmd.Start(); err != nil {
		_ = helperLog.Close()
		_ = os.Remove(helperLog.Name())
		_ = childBridge.Close()
		_ = parentBridge.Close()
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("start bwrap helper: %w", err)
	}
	_ = childBridge.Close()

	sandboxID := m.nextSandboxName(opts.Name)
	client := newHelperClient(m, sandboxID, parentBridge)
	sandbox := &Sandbox{
		manager:       m,
		id:            sandboxID,
		root:          root,
		client:        client,
		cmd:           cmd,
		done:          make(chan error, 1),
		trafficMode:   mode,
		workDir:       opts.WorkDir,
		helperLogFile: helperLog,
		helperLogPath: helperLog.Name(),
	}

	go func() {
		sandbox.done <- cmd.Wait()
	}()

	proxyAddr, err := client.Start(ctx)
	if err != nil {
		sandbox.closeErr = nil
		_ = sandbox.Close()
		return nil, fmt.Errorf("start sandbox helper: %w%s", err, sandbox.helperErrorSuffix())
	}
	if mode == TrafficModeProxy {
		sandbox.proxyAddr = proxyAddr
	}
	sandbox.baseEnv = runEnvForTrafficMode(mode, proxyAddr, opts.Env)

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

// Run executes argv inside the sandbox and returns its exit code and captured
// output.
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

// ProxyAddr returns the effective sandbox-local proxy listen address reported
// by the helper.
func (s *Sandbox) ProxyAddr() string {
	if s == nil {
		return ""
	}
	if normalizeTrafficMode(s.trafficMode) != TrafficModeProxy {
		return ""
	}
	return s.proxyAddr
}

// ProxyURL returns the helper's sandbox-local proxy endpoint as an HTTP URL.
func (s *Sandbox) ProxyURL() string {
	if s == nil || s.ProxyAddr() == "" {
		return ""
	}
	return proxyURL(s.proxyAddr)
}

// AccessedDomains returns a snapshot of the sandbox access audit state.
func (s *Sandbox) AccessedDomains() []AccessedDomain {
	if s == nil || s.manager == nil {
		return []AccessedDomain{}
	}
	return s.manager.accessedDomainsSnapshot(s.id)
}

// Close stops the sandbox helper, unregisters the sandbox, and removes the
// staged root filesystem.
func (s *Sandbox) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		var closeErr error

		if s.client != nil {
			if err := s.client.Close(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close sandbox bridge: %w", err))
			}
		}
		if s.done != nil {
			waitErr := waitWithTimeout(s.done, sandboxPID(s.cmd), 5*time.Second)
			if waitErr != nil {
				if s.cmd != nil && s.cmd.Process != nil {
					if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
						closeErr = errors.Join(closeErr, fmt.Errorf("signal sandbox helper: %w", err))
					}
				}
				waitErr = waitWithTimeout(s.done, sandboxPID(s.cmd), 2*time.Second)
			}
			if waitErr != nil {
				if s.cmd != nil && s.cmd.Process != nil {
					if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						closeErr = errors.Join(closeErr, fmt.Errorf("kill sandbox helper: %w", err))
					}
				}
				waitErr = waitWithTimeout(s.done, sandboxPID(s.cmd), 2*time.Second)
			}
			if normalized := normalizeHelperExit(waitErr); normalized != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("wait for sandbox helper: %w%s", normalized, s.helperErrorSuffix()))
			}
		}
		s.cacheAndRemoveHelperLog()

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

func validateSandboxOptions(opts SandboxOptions, mitmEnabled bool) error {
	if err := validateMounts(opts.Mounts); err != nil {
		return err
	}
	if opts.WorkDir != "" && !filepath.IsAbs(opts.WorkDir) {
		return fmt.Errorf("sandbox workdir %q must be absolute", opts.WorkDir)
	}
	mode := normalizeTrafficMode(opts.TrafficMode)
	switch mode {
	case TrafficModeProxy, TrafficModeTransparent:
	default:
		return fmt.Errorf("sandbox traffic mode %q is not supported", opts.TrafficMode)
	}
	if mode == TrafficModeTransparent && !mitmEnabled {
		return errors.New("transparent traffic mode requires MITM to be enabled")
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

func runEnvForProxyAddr(proxyAddr string, extraEnv []string) []string {
	return mergeEnv(
		filterReservedEnv(extraEnv),
		[]string{
			"PATH=/usr/bin",
			"HTTP_PROXY=" + proxyURL(proxyAddr),
			"http_proxy=" + proxyURL(proxyAddr),
			"HTTPS_PROXY=" + proxyURL(proxyAddr),
			"https_proxy=" + proxyURL(proxyAddr),
		},
	)
}

func normalizeTrafficMode(mode TrafficMode) TrafficMode {
	normalized := TrafficMode(strings.ToLower(strings.TrimSpace(string(mode))))
	if normalized == "" {
		return TrafficModeProxy
	}
	return normalized
}

func runEnvForTrafficMode(mode TrafficMode, proxyAddr string, extraEnv []string) []string {
	normalized := normalizeTrafficMode(mode)
	switch normalized {
	case TrafficModeTransparent:
		return mergeEnv(
			filterReservedEnv(extraEnv),
			[]string{
				"PATH=/usr/bin",
			},
		)
	case TrafficModeProxy:
		return runEnvForProxyAddr(proxyAddr, extraEnv)
	default:
		panic(fmt.Sprintf("unhandled traffic mode %q", normalized))
	}
}

func filterReservedEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnv(entry)
		if !ok {
			continue
		}
		switch key {
		case "PATH", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy":
			continue
		default:
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func splitEnv(entry string) (key string, value string, ok bool) {
	split := strings.IndexByte(entry, '=')
	if split < 0 {
		return "", "", false
	}
	return entry[:split], entry[split+1:], true
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

func waitWithTimeout(done <-chan error, pid int, timeout time.Duration) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case err := <-done:
			return err
		case <-timer.C:
			return errors.New("timeout waiting for sandbox helper exit")
		case <-ticker.C:
			if processExited(pid) {
				return nil
			}
		}
	}
}

func sandboxPID(cmd *exec.Cmd) int {
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}

func processExited(pid int) bool {
	if pid <= 0 {
		return true
	}

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	stat, err := os.ReadFile(statPath)
	if err == nil {
		// /proc/<pid>/stat encodes the process state as the first token after the
		// executable name, which itself is wrapped in parentheses and may contain spaces.
		if end := bytes.LastIndexByte(stat, ')'); end >= 0 && end+2 < len(stat) {
			return stat[end+2] == 'Z'
		}
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	err = syscall.Kill(pid, 0)
	return err == syscall.ESRCH
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
	if s == nil {
		return ""
	}

	stderr := strings.TrimSpace(s.helperLogContents())
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}

func (s *Sandbox) helperLogContents() string {
	if s == nil {
		return ""
	}

	s.helperLogMu.Lock()
	defer s.helperLogMu.Unlock()

	if s.helperLogCached != "" {
		return s.helperLogCached
	}
	if s.helperLogPath == "" {
		return ""
	}

	data, err := os.ReadFile(s.helperLogPath)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}

func (s *Sandbox) cacheAndRemoveHelperLog() {
	if s == nil {
		return
	}

	s.helperLogMu.Lock()
	defer s.helperLogMu.Unlock()

	if s.helperLogFile != nil {
		_ = s.helperLogFile.Close()
		s.helperLogFile = nil
	}
	if s.helperLogPath == "" {
		return
	}

	data, err := os.ReadFile(s.helperLogPath)
	if err == nil {
		s.helperLogCached = string(bytes.TrimSpace(data))
	}
	_ = os.Remove(s.helperLogPath)
	s.helperLogPath = ""
}
