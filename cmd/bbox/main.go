package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/moolen/bbox"
	"github.com/moolen/bbox/internal/helperentrypoint"
	"github.com/moolen/bbox/internal/launcherentrypoint"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type cliOptions struct {
	name                string
	workDir             string
	binaries            []string
	mountRO             []string
	mountRW             []string
	env                 []string
	clearEnv            bool
	clearEnvSet         bool
	trafficMode         string
	maxRequestBodyBytes int64
	maxBodySizeSet      bool
	printPolicy         bool
	reportPolicy        bool
	reportAccess        bool
	reportRequests      bool
	accessLog           string
	audit               bool
	flagOverrides       cliFlagOverrides
}

type runConfig struct {
	manager       bbox.ProxyOptions
	sandbox       bbox.SandboxOptions
	argv          []string
	printPolicy   bool
	reporting     bbox.ReportingOptions
	accessLogMode string
	stdout        io.Writer
	stderr        io.Writer
}

type commandDeps struct {
	stdout  io.Writer
	stderr  io.Writer
	getwd   func() (string, error)
	environ func() []string
	run     func(runConfig) error
}

var (
	cliIsTerminal   = func(fd int) bool { return term.IsTerminal(fd) }
	cliMakeRaw      = term.MakeRaw
	cliGetSize      = term.GetSize
	cliSignalNotify = signal.Notify
	cliSignalStop   = signal.Stop
	cliPlatform     = runtime.GOOS
)

type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("process exited with code %d", e.code)
}

func main() {
	err := dispatch(os.Args[1:], commandDeps{
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		getwd:   os.Getwd,
		environ: os.Environ,
		run:     runSandbox,
	}, helperentrypoint.Run, launcherentrypoint.Run)
	if err != nil {
		var exitErr exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dispatch(args []string, deps commandDeps, runHelper func([]string) error, runLauncher func([]string) error) error {
	if runHelper != nil && len(args) > 0 && args[0] == "internal-helper" {
		return runHelper(args[1:])
	}
	if runLauncher != nil && len(args) > 0 && args[0] == "internal-launcher" {
		return runLauncher(args[1:])
	}

	cmd := newRootCommand(deps)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func newRootCommand(deps commandDeps) *cobra.Command {
	if deps.stdout == nil {
		deps.stdout = io.Discard
	}
	if deps.stderr == nil {
		deps.stderr = io.Discard
	}
	if deps.getwd == nil {
		deps.getwd = os.Getwd
	}
	if deps.environ == nil {
		deps.environ = os.Environ
	}
	if deps.run == nil {
		deps.run = runSandbox
	}

	var opts cliOptions

	cmd := &cobra.Command{
		Use:           "bbox [flags] -- command [args...]",
		Short:         "Run a command inside a bbox sandbox",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().ArgsLenAtDash() < 0 || len(args) == 0 {
				return fmt.Errorf("payload command required after --")
			}

			cwd, err := deps.getwd()
			if err != nil {
				return fmt.Errorf("resolve current working directory: %w", err)
			}

			opts.flagOverrides = cliFlagOverrides{}
			if cmd.Flags().Changed("traffic-mode") {
				opts.flagOverrides.TrafficMode = &opts.trafficMode
			}
			if cmd.Flags().Changed("max-request-body-bytes") {
				opts.maxBodySizeSet = true
			}
			if cmd.Flags().Changed("clear-env") {
				opts.clearEnvSet = true
			}
			if cmd.Flags().Changed("report-policy-violations") {
				opts.flagOverrides.ReportPolicy = &opts.reportPolicy
			}
			if cmd.Flags().Changed("report-access-summary") {
				opts.flagOverrides.ReportAccessSummary = &opts.reportAccess
			}
			if cmd.Flags().Changed("report-request-summary") {
				opts.flagOverrides.ReportRequestSummary = &opts.reportRequests
			}
			if cmd.Flags().Changed("access-log") {
				opts.flagOverrides.AccessLog = &opts.accessLog
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
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.name, "name", "", "sandbox name")
	flags.StringVar(&opts.workDir, "workdir", "", "working directory inside the sandbox")
	flags.StringArrayVar(&opts.binaries, "bin", nil, "extra binary to stage into the sandbox")
	flags.StringArrayVar(&opts.mountRO, "mount-ro", nil, "read-only bind mount in src:dst form")
	flags.StringArrayVar(&opts.mountRW, "mount-rw", nil, "read-write bind mount in src:dst form")
	flags.StringArrayVar(&opts.env, "env", nil, "environment entry in KEY=VALUE form")
	flags.BoolVar(&opts.clearEnv, "clear-env", false, "do not inherit the host environment")
	flags.StringVar(&opts.trafficMode, "traffic-mode", "proxy", "traffic mode: proxy or transparent")
	flags.Int64Var(&opts.maxRequestBodyBytes, "max-request-body-bytes", 64<<10, "maximum request body inspection size for MITM")
	flags.BoolVar(&opts.printPolicy, "print-policy", false, "print the effective policy before execution")

	flags.BoolVar(&opts.reportPolicy, "report-policy-violations", true, "render a policy-violations summary after execution")
	flags.BoolVar(&opts.reportAccess, "report-access-summary", true, "render a host access summary after execution")
	flags.BoolVar(&opts.reportRequests, "report-request-summary", true, "render a request summary after execution")
	flags.StringVar(&opts.accessLog, "access-log", "json", "access log mode: json or off")
	flags.BoolVar(&opts.audit, "audit", false, "force audit reporting summaries on")

	return cmd
}

func buildConfig(opts cliOptions, payload []string, cwd string, environ []string) (runConfig, error) {
	if len(payload) == 0 {
		return runConfig{}, fmt.Errorf("payload command required after --")
	}

	absCWD, err := filepath.Abs(cwd)
	if err != nil {
		return runConfig{}, fmt.Errorf("resolve current working directory: %w", err)
	}

	defaults := defaultCLIFileConfig()
	defaults.MaxRequestBodyBytes = 64 << 10
	defaults.hasMaxRequestBodyBytes = true

	var fileCfg cliFileConfig
	configPath, err := findConfigFile(absCWD)
	if err != nil {
		return runConfig{}, err
	}
	if configPath != "" {
		loaded, err := loadCLIFileConfig(configPath)
		if err != nil {
			return runConfig{}, err
		}
		fileCfg = loaded
	}

	runtimeLayer := cliFileConfig{}
	if strings.TrimSpace(opts.name) != "" {
		runtimeLayer.Name = opts.name
		runtimeLayer.hasName = true
	}
	if strings.TrimSpace(opts.workDir) != "" {
		runtimeLayer.WorkDir = opts.workDir
		runtimeLayer.hasWorkDir = true
	}
	if len(opts.binaries) > 0 {
		runtimeLayer.Bin = append([]string(nil), opts.binaries...)
		runtimeLayer.hasBin = true
	}
	if len(opts.mountRO) > 0 {
		runtimeLayer.MountRO = append([]string(nil), opts.mountRO...)
		runtimeLayer.hasMountRO = true
	}
	if len(opts.mountRW) > 0 {
		runtimeLayer.MountRW = append([]string(nil), opts.mountRW...)
		runtimeLayer.hasMountRW = true
	}
	if len(opts.env) > 0 {
		runtimeLayer.Env = append([]string(nil), opts.env...)
		runtimeLayer.hasEnv = true
	}
	if opts.clearEnvSet {
		runtimeLayer.ClearEnv = opts.clearEnv
		runtimeLayer.hasClearEnv = true
	}
	if opts.maxBodySizeSet {
		runtimeLayer.MaxRequestBodyBytes = opts.maxRequestBodyBytes
		runtimeLayer.hasMaxRequestBodyBytes = true
	}

	mergedCfg := mergeCLIConfig(defaults, fileCfg, opts.flagOverrides, opts.audit)
	mergedCfg = mergeCLIConfigLayer(mergedCfg, runtimeLayer)

	workDir := strings.TrimSpace(mergedCfg.WorkDir)
	if workDir == "" {
		workDir = absCWD
	} else if !filepath.IsAbs(workDir) {
		workDir = filepath.Join(absCWD, workDir)
	}

	mounts := make([]bbox.Mount, 0, 1+len(mergedCfg.MountRO)+len(mergedCfg.MountRW))
	if cliPlatform != "darwin" && !hasMount(absCWD, absCWD, append(mergedCfg.MountRO, mergedCfg.MountRW...)) {
		mounts = append(mounts, bbox.Mount{
			Source:   absCWD,
			Target:   absCWD,
			ReadOnly: false,
		})
	}

	for _, spec := range mergedCfg.MountRO {
		mount, err := parseMountSpec(spec, true)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, mount)
	}
	for _, spec := range mergedCfg.MountRW {
		mount, err := parseMountSpec(spec, false)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, mount)
	}

	trafficMode := bbox.TrafficMode(strings.ToLower(strings.TrimSpace(mergedCfg.TrafficMode)))
	if trafficMode == "" {
		trafficMode = bbox.TrafficModeProxy
	}
	if trafficMode != bbox.TrafficModeProxy && trafficMode != bbox.TrafficModeTransparent {
		return runConfig{}, fmt.Errorf("unsupported traffic mode %q", mergedCfg.TrafficMode)
	}

	envEntries, err := buildSandboxEnv(cliOptions{
		clearEnv: mergedCfg.ClearEnv,
		env:      mergedCfg.Env,
	}, environ)
	if err != nil {
		return runConfig{}, err
	}
	if cliPlatform != "darwin" {
		pathMounts, err := pathAvailabilityMounts(envEntries, absCWD, mounts)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, pathMounts...)
	}

	binaries := make([]string, 0, 1+len(mergedCfg.Bin))
	binaries, err = resolveRequestedBinaries(append([]string{payload[0]}, mergedCfg.Bin...), envEntries, absCWD)
	if err != nil {
		return runConfig{}, err
	}

	policyMode := bbox.PolicyModeAudit
	reporting := bbox.ReportingOptions{
		PolicyViolations: mergedCfg.ReportPolicyViolations,
		AccessSummary:    mergedCfg.ReportAccessSummary,
		RequestSummary:   mergedCfg.ReportRequestSummary,
	}
	accessLogMode, err := normalizeAccessLogMode(mergedCfg.AccessLog)
	if err != nil {
		return runConfig{}, err
	}

	return runConfig{
		manager: bbox.ProxyOptions{
			MaxRequestBodyBytes: mergedCfg.MaxRequestBodyBytes,
			MITM:                bbox.MITMOptions{Enabled: trafficMode == bbox.TrafficModeTransparent},
			PolicyMode:          policyMode,
			Reporting:           reporting,
		},
		sandbox: bbox.SandboxOptions{
			Name:        strings.TrimSpace(mergedCfg.Name),
			Binaries:    binaries,
			Mounts:      mounts,
			Env:         envEntries,
			TrafficMode: trafficMode,
			Policy:      buildNetworkPolicy(mergedCfg.Policy),
			WorkDir:     workDir,
		},
		argv:          append([]string(nil), payload...),
		printPolicy:   opts.printPolicy,
		reporting:     reporting,
		accessLogMode: accessLogMode,
	}, nil
}

func normalizeAccessLogMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "json"
	}
	switch mode {
	case "json", "off":
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported access log mode %q", mode)
	}
}

func buildSandboxEnv(opts cliOptions, environ []string) ([]string, error) {
	var envEntries []string
	if !opts.clearEnv {
		envEntries = append(envEntries, environ...)
	}
	for _, entry := range opts.env {
		if _, _, ok := strings.Cut(entry, "="); !ok {
			return nil, fmt.Errorf("invalid env spec %q, want KEY=VALUE", entry)
		}
		envEntries = append(envEntries, entry)
	}
	return envEntries, nil
}

func resolveRequestedBinaries(requested []string, envEntries []string, cwd string) ([]string, error) {
	pathValue, hasPATH := lastEnvValue(envEntries, "PATH")
	binaries := make([]string, 0, len(requested))
	for _, binary := range requested {
		resolved := binary
		var err error
		if hasPATH || strings.Contains(binary, string(filepath.Separator)) {
			resolved, err = resolveBinaryForPATH(binary, pathValue, cwd)
			if err != nil {
				return nil, err
			}
		}
		if !contains(binaries, resolved) {
			binaries = append(binaries, resolved)
		}
	}
	return binaries, nil
}

func resolveBinaryForPATH(nameOrPath string, pathValue string, cwd string) (string, error) {
	if strings.TrimSpace(nameOrPath) == "" {
		return "", fmt.Errorf("binary path is required")
	}
	if strings.Contains(nameOrPath, string(filepath.Separator)) {
		absPath, err := absPathFromCWD(nameOrPath, cwd)
		if err != nil {
			return "", fmt.Errorf("resolve absolute binary path %q: %w", nameOrPath, err)
		}
		if _, err := os.Stat(absPath); err != nil {
			return "", fmt.Errorf("binary %q: %w", absPath, err)
		}
		return absPath, nil
	}

	for _, dir := range splitPATH(pathValue, cwd) {
		candidate := filepath.Join(dir, nameOrPath)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("resolve binary %q in PATH %q: executable not found", nameOrPath, pathValue)
}

func splitPATH(pathValue string, cwd string) []string {
	if strings.TrimSpace(pathValue) == "" {
		return nil
	}
	parts := strings.Split(pathValue, string(os.PathListSeparator))
	dirs := make([]string, 0, len(parts))
	for _, part := range parts {
		dir, err := normalizePATHDir(part, cwd)
		if err != nil {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

func normalizePATHDir(dir string, cwd string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return absPathFromCWD(".", cwd)
	}
	return absPathFromCWD(dir, cwd)
}

func absPathFromCWD(path string, cwd string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	base := cwd
	if strings.TrimSpace(base) == "" {
		var err error
		base, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	return filepath.Clean(filepath.Join(base, path)), nil
}

func lastEnvValue(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		entryKey, value, ok := strings.Cut(env[i], "=")
		if !ok {
			continue
		}
		if entryKey == key {
			return value, true
		}
	}
	return "", false
}

func pathAvailabilityMounts(envEntries []string, cwd string, existing []bbox.Mount) ([]bbox.Mount, error) {
	pathValue, ok := lastEnvValue(envEntries, "PATH")
	if !ok {
		return nil, nil
	}
	mounts := make([]bbox.Mount, 0)
	for _, dir := range splitPATH(pathValue, cwd) {
		mount, ok, err := pathMountForDir(dir)
		if err != nil {
			return nil, err
		}
		if !ok || mountOverlapsAny(mount, append(existing, mounts...)) {
			continue
		}
		if !containsMountSpec(mounts, mount) {
			mounts = append(mounts, mount)
		}
	}
	return mounts, nil
}

func pathMountForDir(dir string) (bbox.Mount, bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return bbox.Mount{}, false, nil
		}
		return bbox.Mount{}, false, fmt.Errorf("stat PATH dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return bbox.Mount{}, false, nil
	}

	target := dir
	resolved := dir
	if eval, err := filepath.EvalSymlinks(dir); err == nil && strings.TrimSpace(eval) != "" {
		resolved = filepath.Clean(eval)
	}
	target = pathMountTarget(dir, resolved)

	info, err = os.Stat(target)
	if err != nil {
		return bbox.Mount{}, false, fmt.Errorf("stat PATH mount root %q: %w", target, err)
	}
	if !info.IsDir() {
		return bbox.Mount{}, false, nil
	}

	return bbox.Mount{
		Source:   target,
		Target:   target,
		ReadOnly: true,
	}, true, nil
}

func pathMountTarget(dir string, resolved string) string {
	switch {
	case resolved == "/usr" || strings.HasPrefix(resolved, "/usr/"):
		return "/usr"
	case filepath.Base(dir) == "bin" || filepath.Base(dir) == "sbin":
		parent := filepath.Dir(dir)
		if parent != string(filepath.Separator) && parent != "." {
			return parent
		}
	}
	return dir
}

func mountOverlapsAny(want bbox.Mount, existing []bbox.Mount) bool {
	for _, mount := range existing {
		if mountTargetsOverlap(mount.Target, want.Target) {
			return true
		}
	}
	return false
}

func containsMountSpec(values []bbox.Mount, want bbox.Mount) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mountTargetsOverlap(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if a == b {
		return true
	}
	if a == "/" || b == "/" {
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func parseMountSpec(spec string, readOnly bool) (bbox.Mount, error) {
	source, target, ok := strings.Cut(spec, ":")
	source = strings.TrimSpace(source)
	target = strings.TrimSpace(target)
	if !ok || source == "" || target == "" {
		return bbox.Mount{}, fmt.Errorf("invalid mount spec %q, want src:dst", spec)
	}
	if !filepath.IsAbs(source) || !filepath.IsAbs(target) {
		return bbox.Mount{}, fmt.Errorf("mount spec %q requires absolute src and dst", spec)
	}
	return bbox.Mount{
		Source:   source,
		Target:   target,
		ReadOnly: readOnly,
	}, nil
}

func hasMount(source, target string, specs []string) bool {
	wantSource := filepath.Clean(source)
	wantTarget := filepath.Clean(target)
	for _, spec := range specs {
		src, dst, ok := strings.Cut(spec, ":")
		if !ok {
			continue
		}
		if filepath.Clean(strings.TrimSpace(src)) == wantSource && filepath.Clean(strings.TrimSpace(dst)) == wantTarget {
			return true
		}
	}
	return false
}

func normalizeHTTPMethods(values []string) []string {
	methods := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		methods = append(methods, value)
	}
	if len(methods) == 0 {
		return nil
	}
	return methods
}

func buildNetworkPolicy(cfg cliPolicyConfig) bbox.NetworkPolicy {
	rules := make([]bbox.PolicyRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rules = append(rules, bbox.PolicyRule{
			HostPatterns:   cloneStringSlice(rule.HostPatterns),
			IPCIDRs:        cloneStringSlice(rule.IPCIDRs),
			HTTPMethods:    normalizeHTTPMethods(rule.HTTPMethods),
			ConnectPorts:   cloneStringSlice(rule.ConnectPorts),
			PathPatterns:   cloneStringSlice(rule.PathPatterns),
			HeaderPatterns: cloneStringSliceMap(rule.HeaderPatterns),
			BodyPatterns:   cloneStringSlice(rule.BodyPatterns),
		})
	}
	return bbox.NetworkPolicy{Rules: rules}
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
