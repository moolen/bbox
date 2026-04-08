package bbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moolen/bbox/internal/helperproto"
	hrexec "github.com/moolen/bbox/internal/helperruntime/exec"
)

type darwinSandboxRuntime struct {
	client helperControl
	cmd    *exec.Cmd
	done   chan error

	helperLogMu     sync.Mutex
	helperLogFile   *os.File
	helperLogPath   string
	helperLogCached string
	proxyAddr       string
	binaries        []string
	workDir         string
}

var darwinExecCommandContext = exec.CommandContext

func (m *ProxyManager) newDarwinSandboxRuntime(ctx context.Context, sandboxID string, opts SandboxOptions, _ TrafficMode, _ *dockerSocketMount) (*sandboxRuntimeBootstrap, error) {
	runtimeBinary, err := m.runtimeBinary()
	if err != nil {
		return nil, err
	}

	parentBridge, childBridge, err := openBridgePair()
	if err != nil {
		return nil, err
	}

	helperLog, err := os.CreateTemp("", "bbox-darwin-helper-log-")
	if err != nil {
		_ = childBridge.Close()
		_ = parentBridge.Close()
		return nil, fmt.Errorf("create darwin helper log file: %w", err)
	}

	args := []string{
		"internal-helper",
		"--bridge-fd", "3",
		"--proxy-addr", m.listenAddr,
		"--traffic-mode", "proxy",
		"--max-request-body-bytes", strconv.FormatInt(m.requestBodyLimitBytes, 10),
	}
	if m.mitm.Enabled {
		args = append(args, "--mitm-enabled=true")
	}

	cmd := exec.Command(runtimeBinary, args...)
	cmd.Stderr = helperLog
	cmd.Stdout = helperLog
	cmd.ExtraFiles = []*os.File{childBridge}
	if err := cmd.Start(); err != nil {
		_ = helperLog.Close()
		_ = os.Remove(helperLog.Name())
		_ = childBridge.Close()
		_ = parentBridge.Close()
		return nil, fmt.Errorf("start darwin proxy helper: %w", err)
	}
	_ = childBridge.Close()

	runtime := &darwinSandboxRuntime{
		client:        newHelperClient(m, sandboxID, parentBridge),
		cmd:           cmd,
		done:          make(chan error, 1),
		helperLogFile: helperLog,
		helperLogPath: helperLog.Name(),
		binaries:      append([]string(nil), opts.Binaries...),
		workDir:       opts.WorkDir,
	}
	go func() {
		runtime.done <- cmd.Wait()
	}()

	proxyAddr, err := runtime.client.Start(ctx)
	if err != nil {
		_ = runtime.Close()
		return nil, fmt.Errorf("start darwin proxy helper: %w%s", err, runtime.helperErrorSuffix())
	}
	runtime.proxyAddr = proxyAddr

	return &sandboxRuntimeBootstrap{
		runtime: runtime,
	}, nil
}

func (r *darwinSandboxRuntime) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if r == nil {
		return nil, errors.New("sandbox is not running")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(argv) == 0 {
		return nil, errors.New("argv must not be empty")
	}

	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		workDir = r.workDir
	}
	if workDir == "" {
		workDir = "/"
	}

	commandPath, err := resolveDarwinExecutable(argv[0], opts.Env, workDir)
	if err != nil {
		return nil, err
	}

	allowedExecPaths := make([]string, 0, len(r.binaries)+1)
	for _, path := range append(append([]string(nil), r.binaries...), commandPath) {
		resolved, resolveErr := resolveDarwinExecutable(path, opts.Env, workDir)
		if resolveErr != nil {
			return nil, resolveErr
		}
		allowedExecPaths = append(allowedExecPaths, resolved)
	}

	profile, err := generateDarwinSeatbeltProfile(darwinProfileConfig{
		WorkDir:          workDir,
		AllowedExecPaths: allowedExecPaths,
		ProxyAddrs:       []string{r.proxyAddr},
	})
	if err != nil {
		return nil, err
	}

	cmd := darwinExecCommandContext(ctx, "sandbox-exec", append([]string{"-p", profile, commandPath}, argv[1:]...)...)
	cmd.Env = sanitizeDarwinEnv(opts.Env)
	cmd.Dir = workDir

	return runDarwinCommand(cmd, opts)
}

func (r *darwinSandboxRuntime) Close() error {
	if r == nil {
		return nil
	}

	var closeErr error

	if r.client != nil {
		if err := r.client.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close darwin proxy bridge: %w", err))
		}
	}
	if r.done != nil {
		waitErr := waitForProcessExit(r.done, 5*time.Second)
		if waitErr != nil && r.cmd != nil && r.cmd.Process != nil {
			if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
				closeErr = errors.Join(closeErr, fmt.Errorf("signal darwin proxy helper: %w", err))
			}
			waitErr = waitForProcessExit(r.done, 2*time.Second)
		}
		if waitErr != nil && r.cmd != nil && r.cmd.Process != nil {
			if err := r.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				closeErr = errors.Join(closeErr, fmt.Errorf("kill darwin proxy helper: %w", err))
			}
			waitErr = waitForProcessExit(r.done, 2*time.Second)
		}
		if normalized := normalizeDarwinHelperExit(waitErr); normalized != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("wait for darwin proxy helper: %w%s", normalized, r.helperErrorSuffix()))
		}
	}
	r.cacheAndRemoveHelperLog()

	return closeErr
}

func (r *darwinSandboxRuntime) ProxyAddr() string {
	if r == nil {
		return ""
	}
	return r.proxyAddr
}

func runDarwinCommand(cmd *exec.Cmd, opts RunOptions) (*RunResult, error) {
	interactive := opts.Interactive || opts.Stdin != nil || opts.Stdout != nil || opts.Stderr != nil || opts.Terminal || opts.Resize != nil

	var initialSize *helperproto.TerminalSize
	if opts.TerminalSize.Rows > 0 || opts.TerminalSize.Cols > 0 {
		initialSize = &helperproto.TerminalSize{
			Rows: opts.TerminalSize.Rows,
			Cols: opts.TerminalSize.Cols,
		}
	}

	session, streams, err := hrexec.StartSession(cmd, helperproto.ExecRequest{
		Interactive: interactive,
		Terminal:    opts.Terminal,
		InitialSize: initialSize,
	})
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if interactive {
		if opts.Stdin != nil {
			go pumpDarwinInput(session, opts.Stdin)
		}
		if opts.Resize != nil {
			go pumpDarwinResize(session, opts.Resize)
		}
	}

	stdoutWriter := io.Writer(io.Discard)
	stderrWriter := io.Writer(io.Discard)
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	stdoutWriter = io.MultiWriter(&stdoutBuf)
	stderrWriter = io.MultiWriter(&stderrBuf)
	if opts.Stdout != nil {
		stdoutWriter = io.MultiWriter(&stdoutBuf, opts.Stdout)
	}
	if opts.Stderr != nil {
		stderrWriter = io.MultiWriter(&stderrBuf, opts.Stderr)
	}

	var wg sync.WaitGroup
	copyErrCh := make(chan error, len(streams))
	for _, stream := range streams {
		stream := stream
		dst := stdoutWriter
		if stream.Stream == helperproto.StreamStderr {
			dst = stderrWriter
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := io.Copy(dst, stream.Reader); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
				copyErrCh <- err
			}
		}()
	}

	wg.Wait()
	close(copyErrCh)
	for err := range copyErrCh {
		if err != nil {
			return nil, err
		}
	}
	waitErr := cmd.Wait()

	result := &RunResult{
		Stdout: append([]byte(nil), stdoutBuf.Bytes()...),
		Stderr: append([]byte(nil), stderrBuf.Bytes()...),
	}
	if waitErr == nil {
		result.ExitCode = 0
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}

	result.ExitCode = -1
	result.Stderr = append(result.Stderr, []byte(waitErr.Error())...)
	return result, waitErr
}

func pumpDarwinInput(session *hrexec.Session, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			hrexec.HandleInput(session, helperproto.ExecInput{
				Data: append([]byte(nil), buf[:n]...),
			})
		}
		if errors.Is(err, io.EOF) {
			hrexec.HandleInput(session, helperproto.ExecInput{EOF: true})
			return
		}
		if err != nil {
			return
		}
	}
}

func pumpDarwinResize(session *hrexec.Session, sizes <-chan TerminalSize) {
	for size := range sizes {
		if size.Rows == 0 && size.Cols == 0 {
			continue
		}
		hrexec.HandleInput(session, helperproto.ExecInput{
			Resize: &helperproto.TerminalSize{
				Rows: size.Rows,
				Cols: size.Cols,
			},
		})
	}
}

func resolveDarwinExecutable(nameOrPath string, env []string, workDir string) (string, error) {
	nameOrPath = strings.TrimSpace(nameOrPath)
	if nameOrPath == "" {
		return "", errors.New("darwin executable path is required")
	}
	if strings.Contains(nameOrPath, string(filepath.Separator)) {
		if filepath.IsAbs(nameOrPath) {
			return filepath.Clean(nameOrPath), nil
		}
		return filepath.Clean(filepath.Join(workDir, nameOrPath)), nil
	}

	pathValue, _ := lastEnvValue(env, "PATH")
	if resolved, err := exec.LookPath(nameOrPath); err == nil && pathValue == "" {
		return filepath.Clean(resolved), nil
	}

	for _, dir := range filepath.SplitList(pathValue) {
		if strings.TrimSpace(dir) == "" {
			dir = workDir
		}
		candidate := filepath.Join(dir, nameOrPath)
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return filepath.Clean(candidate), nil
	}

	return "", fmt.Errorf("resolve darwin executable %q in PATH %q: executable not found", nameOrPath, pathValue)
}

func waitForProcessExit(done <-chan error, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errors.New("timeout waiting for darwin proxy helper exit")
	}
}

func normalizeDarwinHelperExit(err error) error {
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

func (r *darwinSandboxRuntime) helperErrorSuffix() string {
	if r == nil {
		return ""
	}

	stderr := strings.TrimSpace(r.helperLogContents())
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}

func (r *darwinSandboxRuntime) helperLogContents() string {
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

func (r *darwinSandboxRuntime) cacheAndRemoveHelperLog() {
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
