//go:build linux

package bbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type linuxSandboxRuntime struct {
	client *helperClient
	cmd    *exec.Cmd
	done   chan error

	helperLogMu     sync.Mutex
	helperLogFile   *os.File
	helperLogPath   string
	helperLogCached string
	proxyAddr       string
}

func (m *ProxyManager) newLinuxSandboxRuntime(ctx context.Context, sandboxID string, opts SandboxOptions, mode TrafficMode, dockerMount *dockerSocketMount) (*sandboxRuntimeBootstrap, error) {
	runtimeBinary, err := m.runtimeBinary()
	if err != nil {
		return nil, err
	}

	root, err := stageSandboxRoot(opts, runtimeBinary, m.CACertPEM(), mode)
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

	var (
		payloadSeccompBPFPath string
		seccompProgram        *preparedSeccompProgram
	)
	if mode == TrafficModeTransparent {
		payloadSeccompBPFPath, err = stageTransparentPayloadSeccompProgram(root, opts.Seccomp)
	} else {
		seccompProgram, err = prepareSeccompProgram(opts.Seccomp)
	}
	if err != nil {
		if seccompProgram != nil {
			_ = seccompProgram.Close()
		}
		_ = helperLog.Close()
		_ = os.Remove(helperLog.Name())
		_ = childBridge.Close()
		_ = parentBridge.Close()
		_ = os.RemoveAll(root)
		return nil, err
	}

	bridgeFD := 3
	seccompFD := -1
	extraFiles := []*os.File{childBridge}
	if seccompProgram != nil {
		seccompFD = bridgeFD + len(extraFiles)
		extraFiles = append(extraFiles, seccompProgram.file)
	}

	cmd := exec.Command("bwrap", buildBwrapArgs(bwrapArgsConfig{
		root:                  root,
		helperPath:            defaultSandboxBBoxPath,
		proxyListenAddr:       m.listenAddr,
		mitm:                  m.mitm,
		unshareUser:           os.Geteuid() != 0,
		maxRequestBodyBytes:   m.requestBodyLimitBytes,
		mounts:                opts.Mounts,
		dockerSocketMount:     dockerMount,
		trafficMode:           mode,
		payloadSeccompBPFPath: payloadSeccompBPFPath,
		bridgeFD:              bridgeFD,
		seccompFD:             seccompFD,
	})...)
	cmd.Stderr = helperLog
	cmd.Stdout = helperLog
	cmd.ExtraFiles = extraFiles

	if err := cmd.Start(); err != nil {
		if seccompProgram != nil {
			_ = seccompProgram.Close()
		}
		_ = helperLog.Close()
		_ = os.Remove(helperLog.Name())
		_ = childBridge.Close()
		_ = parentBridge.Close()
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("start bwrap helper: %w", err)
	}
	if seccompProgram != nil {
		_ = seccompProgram.Close()
	}
	_ = childBridge.Close()

	runtime := &linuxSandboxRuntime{
		client:        newHelperClient(m, sandboxID, parentBridge),
		cmd:           cmd,
		done:          make(chan error, 1),
		helperLogFile: helperLog,
		helperLogPath: helperLog.Name(),
	}
	go func() {
		runtime.done <- cmd.Wait()
	}()

	proxyAddr, err := runtime.client.Start(ctx)
	if err != nil {
		_ = runtime.Close()
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("start sandbox helper: %w%s", err, runtime.helperErrorSuffix())
	}
	if mode == TrafficModeProxy {
		runtime.proxyAddr = proxyAddr
	}

	return &sandboxRuntimeBootstrap{
		runtime: runtime,
		root:    root,
	}, nil
}

func (r *linuxSandboxRuntime) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if r == nil || r.client == nil {
		return nil, errors.New("sandbox is not running")
	}
	return r.client.Run(ctx, argv, opts)
}

func (r *linuxSandboxRuntime) Close() error {
	if r == nil {
		return nil
	}

	var closeErr error

	if r.client != nil {
		if err := r.client.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close sandbox bridge: %w", err))
		}
	}
	if r.done != nil {
		waitErr := waitWithTimeout(r.done, sandboxPID(r.cmd), 5*time.Second)
		if waitErr != nil {
			if r.cmd != nil && r.cmd.Process != nil {
				if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
					closeErr = errors.Join(closeErr, fmt.Errorf("signal sandbox helper: %w", err))
				}
			}
			waitErr = waitWithTimeout(r.done, sandboxPID(r.cmd), 2*time.Second)
		}
		if waitErr != nil {
			if r.cmd != nil && r.cmd.Process != nil {
				if err := r.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					closeErr = errors.Join(closeErr, fmt.Errorf("kill sandbox helper: %w", err))
				}
			}
			waitErr = waitWithTimeout(r.done, sandboxPID(r.cmd), 2*time.Second)
		}
		if normalized := normalizeHelperExit(waitErr); normalized != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("wait for sandbox helper: %w%s", normalized, r.helperErrorSuffix()))
		}
	}
	r.cacheAndRemoveHelperLog()
	return closeErr
}

func (r *linuxSandboxRuntime) ProxyAddr() string {
	if r == nil {
		return ""
	}
	return r.proxyAddr
}

func (r *linuxSandboxRuntime) doneChan() <-chan error {
	if r == nil {
		return nil
	}
	return r.done
}

func (r *linuxSandboxRuntime) processState() *os.ProcessState {
	if r == nil || r.cmd == nil {
		return nil
	}
	return r.cmd.ProcessState
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

func (r *linuxSandboxRuntime) helperErrorSuffix() string {
	if r == nil {
		return ""
	}

	stderr := strings.TrimSpace(r.helperLogContents())
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}

func (r *linuxSandboxRuntime) helperLogContents() string {
	if r == nil {
		return ""
	}

	r.helperLogMu.Lock()
	defer r.helperLogMu.Unlock()

	if r.helperLogCached != "" {
		return r.helperLogCached
	}
	if r.helperLogPath == "" {
		return ""
	}

	data, err := os.ReadFile(r.helperLogPath)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}

func (r *linuxSandboxRuntime) cacheAndRemoveHelperLog() {
	if r == nil {
		return
	}

	r.helperLogMu.Lock()
	defer r.helperLogMu.Unlock()

	if r.helperLogFile != nil {
		_ = r.helperLogFile.Close()
		r.helperLogFile = nil
	}
	if r.helperLogPath == "" {
		return
	}

	data, err := os.ReadFile(r.helperLogPath)
	if err == nil {
		r.helperLogCached = string(bytes.TrimSpace(data))
	}
	_ = os.Remove(r.helperLogPath)
	r.helperLogPath = ""
}
