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
	trafficMode         string
	trafficModeSet      bool
	maxRequestBodyBytes int64
	maxBodySizeSet      bool
	printPolicy         bool
	reportPolicy        bool
	reportAccess        bool
	reportRequests      bool
	accessLog           string
	audit               bool
	policyMode          string
	flagOverrides       cliFlagOverrides
}

type runConfig struct {
	manager       bbox.ProxyOptions
	sandbox       bbox.SandboxOptions
	argv          []string
	printPolicy   bool
	policyMode    bbox.PolicyMode
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
				opts.trafficModeSet = true
				opts.flagOverrides.TrafficMode = &opts.trafficMode
			}
			if cmd.Flags().Changed("max-request-body-bytes") {
				opts.maxBodySizeSet = true
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

	flags.BoolVar(&opts.reportPolicy, "report-policy-violations", false, "render a policy-violations summary after execution")
	flags.BoolVar(&opts.reportAccess, "report-access-summary", false, "render a host access summary after execution")
	flags.BoolVar(&opts.reportRequests, "report-request-summary", false, "render a request summary after execution")
	flags.StringVar(&opts.accessLog, "access-log", "json", "access log mode: json or off")
	flags.BoolVar(&opts.audit, "audit", false, "shorthand for --policy-mode audit plus summary reporting")

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
	if opts.clearEnv {
		runtimeLayer.ClearEnv = true
		runtimeLayer.hasClearEnv = true
	}
	if opts.maxBodySizeSet {
		runtimeLayer.MaxRequestBodyBytes = opts.maxRequestBodyBytes
		runtimeLayer.hasMaxRequestBodyBytes = true
	}

	flagOverrides := opts.flagOverrides
	if flagOverrides.TrafficMode == nil && strings.TrimSpace(opts.trafficMode) != "" {
		flagOverrides.TrafficMode = &opts.trafficMode
	}
	if flagOverrides.ReportPolicy == nil && opts.reportPolicy {
		flagOverrides.ReportPolicy = &opts.reportPolicy
	}
	if flagOverrides.ReportAccessSummary == nil && opts.reportAccess {
		flagOverrides.ReportAccessSummary = &opts.reportAccess
	}
	if flagOverrides.ReportRequestSummary == nil && opts.reportRequests {
		flagOverrides.ReportRequestSummary = &opts.reportRequests
	}
	if flagOverrides.AccessLog == nil && strings.TrimSpace(opts.accessLog) != "" {
		flagOverrides.AccessLog = &opts.accessLog
	}

	mergedCfg := mergeCLIConfig(defaults, fileCfg, flagOverrides, opts.audit)
	mergedCfg = mergeCLIConfigLayer(mergedCfg, runtimeLayer)

	workDir := strings.TrimSpace(mergedCfg.WorkDir)
	if workDir == "" {
		workDir = absCWD
	} else if !filepath.IsAbs(workDir) {
		workDir = filepath.Join(absCWD, workDir)
	}

	mounts := make([]bbox.Mount, 0, 1+len(mergedCfg.MountRO)+len(mergedCfg.MountRW))
	if !hasMount(absCWD, absCWD, append(mergedCfg.MountRO, mergedCfg.MountRW...)) {
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

	binaries := make([]string, 0, 1+len(mergedCfg.Bin))
	binaries = append(binaries, payload[0])
	for _, binary := range mergedCfg.Bin {
		if !contains(binaries, binary) {
			binaries = append(binaries, binary)
		}
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
			MITM:                bbox.MITMOptions{Enabled: true},
			PolicyMode:          policyMode,
			Reporting:           reporting,
		},
		sandbox: bbox.SandboxOptions{
			Name:        strings.TrimSpace(mergedCfg.Name),
			Binaries:    binaries,
			Mounts:      mounts,
			Env:         envEntries,
			TrafficMode: trafficMode,
			Policy: bbox.NetworkPolicy{
				AllowHostPatterns:   append([]string(nil), mergedCfg.Policy.AllowHostPatterns...),
				DenyHostPatterns:    append([]string(nil), mergedCfg.Policy.DenyHostPatterns...),
				AllowIPCIDRs:        append([]string(nil), mergedCfg.Policy.AllowIPCIDRs...),
				DenyIPCIDRs:         append([]string(nil), mergedCfg.Policy.DenyIPCIDRs...),
				AllowHTTPMethods:    normalizeHTTPMethods(mergedCfg.Policy.AllowHTTPMethods),
				AllowConnect:        mergedCfg.Policy.AllowConnect,
				AllowConnectPorts:   append([]string(nil), mergedCfg.Policy.AllowConnectPorts...),
				AllowPathPatterns:   append([]string(nil), mergedCfg.Policy.AllowPathPatterns...),
				DenyPathPatterns:    append([]string(nil), mergedCfg.Policy.DenyPathPatterns...),
				AllowHeaderPatterns: cloneStringSliceMap(mergedCfg.Policy.AllowHeaderPatterns),
				DenyHeaderPatterns:  cloneStringSliceMap(mergedCfg.Policy.DenyHeaderPatterns),
				AllowBodyPatterns:   append([]string(nil), mergedCfg.Policy.AllowBodyPatterns...),
				DenyBodyPatterns:    append([]string(nil), mergedCfg.Policy.DenyBodyPatterns...),
			},
			WorkDir: workDir,
		},
		argv:          append([]string(nil), payload...),
		printPolicy:   opts.printPolicy,
		policyMode:    policyMode,
		reporting:     reporting,
		accessLogMode: accessLogMode,
	}, nil
}

func effectivePolicyMode(opts cliOptions) (bbox.PolicyMode, error) {
	if opts.audit {
		return bbox.PolicyModeAudit, nil
	}

	mode := bbox.PolicyMode(strings.ToLower(strings.TrimSpace(opts.policyMode)))
	switch mode {
	case "":
		return bbox.PolicyModeEnforce, nil
	case bbox.PolicyModeEnforce, bbox.PolicyModeAudit:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported policy mode %q", opts.policyMode)
	}
}

func effectiveReportingOptions(opts cliOptions) bbox.ReportingOptions {
	reporting := bbox.ReportingOptions{
		PolicyViolations: opts.reportPolicy,
		AccessSummary:    opts.reportAccess,
		RequestSummary:   opts.reportRequests,
	}
	if opts.audit {
		reporting.PolicyViolations = true
		reporting.AccessSummary = true
		reporting.RequestSummary = true
	}
	return reporting
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

func buildDomainPatterns(values []string, filePath string) ([]string, error) {
	entries := append([]string(nil), values...)
	if strings.TrimSpace(filePath) != "" {
		fileEntries, err := readDomainListFile(filePath)
		if err != nil {
			return nil, err
		}
		entries = append(entries, fileEntries...)
	}

	patterns := make([]string, 0, len(entries))
	for _, entry := range entries {
		pattern, err := domainPatternFromEntry(entry)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func readDomainListFile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowed domains file %q: %w", path, err)
	}

	var entries []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries, nil
}

func domainPatternFromEntry(entry string) (string, error) {
	entry = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(entry, ".")))
	if entry == "" {
		return "", fmt.Errorf("domain entry cannot be empty")
	}

	if strings.HasPrefix(entry, "*.") {
		suffix := strings.TrimPrefix(entry, "*.")
		if !isValidDomainLiteral(suffix) {
			return "", fmt.Errorf("invalid wildcard domain %q", entry)
		}
		return "^([^.]+[.])+" + escapeDomainLiteral(suffix) + "$", nil
	}

	if strings.Contains(entry, "*") || !isValidDomainLiteral(entry) {
		return "", fmt.Errorf("invalid domain %q", entry)
	}

	return "^" + escapeDomainLiteral(entry) + "$", nil
}

func isValidDomainLiteral(value string) bool {
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, ch := range part {
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= '0' && ch <= '9':
			case ch == '-':
			default:
				return false
			}
		}
	}
	return true
}

func escapeDomainLiteral(value string) string {
	return strings.ReplaceAll(value, ".", "[.]")
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
	return methods
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

	runOpts, cleanup, err := buildInteractiveRunOptions(stdout, stderr)
	if err != nil {
		return err
	}
	var cleanupOnce sync.Once
	cleanupRun := func() {
		cleanupOnce.Do(cleanup)
	}
	defer cleanupRun()

	result, err := sandbox.RunInteractive(ctx, cfg.argv, runOpts)
	if err != nil {
		return err
	}
	if err := finalizeRunOutput(cleanupRun, stderr, accessLogger, sandbox.AccessSummary(), cfg.reporting); err != nil {
		return err
	}
	if result != nil && result.ExitCode != 0 {
		return exitCodeError{code: result.ExitCode}
	}
	return nil
}

func buildInteractiveRunOptions(stdout, stderr io.Writer) (bbox.RunOptions, func(), error) {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	opts := bbox.RunOptions{
		Interactive: true,
		Stdin:       os.Stdin,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return opts, func() {}, nil
	}

	state, err := term.MakeRaw(fd)
	if err != nil {
		return bbox.RunOptions{}, nil, fmt.Errorf("configure terminal: %w", err)
	}

	width, height, err := term.GetSize(fd)
	if err != nil || width <= 0 || height <= 0 {
		width = 80
		height = 24
	}
	opts.Terminal = true
	opts.TerminalSize = bbox.TerminalSize{Rows: uint16(height), Cols: uint16(width)}

	resizeCh := make(chan bbox.TerminalSize, 1)
	done := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigCh:
				width, height, err := term.GetSize(fd)
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
		signal.Stop(sigCh)
		close(sigCh)
		_ = term.Restore(fd, state)
	}
	return opts, cleanup, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
