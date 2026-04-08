package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/moolen/bbox"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	cliIsTerminal   = func(fd int) bool { return term.IsTerminal(fd) }
	cliMakeRaw      = term.MakeRaw
	cliGetSize      = term.GetSize
	cliSignalNotify = signal.Notify
	cliSignalStop   = signal.Stop
	cliPlatform     = runtime.GOOS
)

func executeRootCommand(cmd *cobra.Command, args []string, deps commandDeps, opts cliOptions) error {
	if cmd.Flags().ArgsLenAtDash() < 0 || len(args) == 0 {
		return fmt.Errorf("payload command required after --")
	}

	cwd, err := deps.getwd()
	if err != nil {
		return fmt.Errorf("resolve current working directory: %w", err)
	}

	opts.flagOverrides = deriveFlagOverrides(cmd, opts)
	if cmd.Flags().Changed("max-request-body-bytes") {
		opts.maxBodySizeSet = true
	}
	if cmd.Flags().Changed("clear-env") {
		opts.clearEnvSet = true
	}

	cfg, err := buildConfig(opts, args, cwd, deps.environ())
	if err != nil {
		return err
	}
	cfg.stdout = deps.stdout
	cfg.stderr = deps.stderr
	if cfg.printPolicy {
		if err := printPolicy(deps.stdout, cfg); err != nil {
			return err
		}
	}
	return deps.run(cfg)
}

func deriveFlagOverrides(cmd *cobra.Command, opts cliOptions) cliFlagOverrides {
	overrides := cliFlagOverrides{}
	if cmd.Flags().Changed("traffic-mode") {
		overrides.TrafficMode = &opts.trafficMode
	}
	if cmd.Flags().Changed("policy-mode") {
		overrides.PolicyMode = &opts.policyMode
	}
	if cmd.Flags().Changed("report-policy-violations") {
		overrides.ReportPolicy = &opts.reportPolicy
	}
	if cmd.Flags().Changed("report-access-summary") {
		overrides.ReportAccessSummary = &opts.reportAccess
	}
	if cmd.Flags().Changed("report-request-summary") {
		overrides.ReportRequestSummary = &opts.reportRequests
	}
	if cmd.Flags().Changed("access-log") {
		overrides.AccessLog = &opts.accessLog
	}
	return overrides
}

func printPolicy(w io.Writer, cfg runConfig) error {
	if w == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Manager bbox.ProxyOptions   `json:"manager"`
		Sandbox bbox.SandboxOptions `json:"sandbox"`
		Argv    []string            `json:"argv"`
	}{
		Manager: cfg.manager,
		Sandbox: cfg.sandbox,
		Argv:    cfg.argv,
	})
}

func runSandbox(cfg runConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stdout := cfg.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	accessLogger := newCLIAccessLogger(stdout, cfg.accessLogMode == "json")
	cfg.manager.AccessLogger = accessLogger

	if err := validateRunConfigPlatform(cfg); err != nil {
		return err
	}

	manager, err := bbox.NewProxyManager(cfg.manager)
	if err != nil {
		return err
	}
	defer manager.Close()

	sandbox, err := manager.NewSandbox(ctx, cfg.sandbox)
	if err != nil {
		return err
	}
	defer sandbox.Close()

	runOpts, interactive, cleanup, err := buildCLIProcessRunOptions(os.Stdin, stdout, stderr)
	if err != nil {
		return err
	}
	var cleanupOnce sync.Once
	cleanupRun := func() {
		cleanupOnce.Do(cleanup)
	}
	defer cleanupRun()

	var result *bbox.RunResult
	if interactive {
		result, err = sandbox.RunInteractive(ctx, cfg.argv, runOpts)
	} else {
		result, err = sandbox.Run(ctx, cfg.argv, runOpts)
	}
	if err != nil {
		return err
	}
	if !interactive {
		if err := writeBufferedRunResult(stdout, stderr, result); err != nil {
			return err
		}
	}
	if err := finalizeRunOutput(cleanupRun, stderr, accessLogger, sandbox.AccessSummary(), cfg.reporting); err != nil {
		return err
	}
	if result != nil && result.ExitCode != 0 {
		return exitCodeError{code: result.ExitCode}
	}
	return nil
}

func validateRunConfigPlatform(cfg runConfig) error {
	if cliPlatform != "darwin" {
		return nil
	}
	if cfg.sandbox.TrafficMode == bbox.TrafficModeTransparent {
		return fmt.Errorf("transparent traffic mode is not supported on darwin")
	}
	for _, mount := range cfg.sandbox.Mounts {
		if mount.ReadOnly {
			return fmt.Errorf("mount_ro is not supported on darwin")
		}
		return fmt.Errorf("mount_rw is not supported on darwin")
	}
	return nil
}

func buildCLIProcessRunOptions(stdin *os.File, stdout, stderr io.Writer) (bbox.RunOptions, bool, func(), error) {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	fd := int(stdin.Fd())
	if !cliIsTerminal(fd) {
		return bbox.RunOptions{Stdin: stdin}, false, func() {}, nil
	}

	opts := bbox.RunOptions{
		Interactive: true,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	state, err := cliMakeRaw(fd)
	if err != nil {
		return bbox.RunOptions{}, false, nil, fmt.Errorf("configure terminal: %w", err)
	}

	width, height, err := cliGetSize(fd)
	if err != nil || width <= 0 || height <= 0 {
		width = 80
		height = 24
	}
	opts.Terminal = true
	opts.TerminalSize = bbox.TerminalSize{Rows: uint16(height), Cols: uint16(width)}

	resizeCh := make(chan bbox.TerminalSize, 1)
	done := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	cliSignalNotify(sigCh, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigCh:
				width, height, err := cliGetSize(fd)
				if err != nil || width <= 0 || height <= 0 {
					continue
				}
				size := bbox.TerminalSize{Rows: uint16(height), Cols: uint16(width)}
				select {
				case resizeCh <- size:
				default:
				}
			}
		}
	}()
	opts.Resize = resizeCh

	cleanup := func() {
		close(done)
		cliSignalStop(sigCh)
		close(sigCh)
		_ = term.Restore(fd, state)
	}
	return opts, true, cleanup, nil
}

func writeBufferedRunResult(stdout, stderr io.Writer, result *bbox.RunResult) error {
	if result == nil {
		return nil
	}
	if stdout != nil && len(result.Stdout) > 0 {
		if _, err := stdout.Write(result.Stdout); err != nil {
			return fmt.Errorf("write buffered stdout: %w", err)
		}
	}
	if stderr != nil && len(result.Stderr) > 0 {
		if _, err := stderr.Write(result.Stderr); err != nil {
			return fmt.Errorf("write buffered stderr: %w", err)
		}
	}
	return nil
}
