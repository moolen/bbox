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
	"syscall"

	"github.com/moolen/bbox"
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
	mitm                bool
	maxRequestBodyBytes int64
	printPolicy         bool
	allowedDomains      []string
	allowedDomainsFile  string
	denyDomains         []string
	allowHTTPMethods    []string
	allowConnect        bool
	allowConnectPorts   []string
	allowPaths          []string
	denyPaths           []string
}

type runConfig struct {
	manager     bbox.ProxyOptions
	sandbox     bbox.SandboxOptions
	argv        []string
	printPolicy bool
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
	cmd := newRootCommand(commandDeps{
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		getwd:   os.Getwd,
		environ: os.Environ,
		run:     runSandbox,
	})
	if err := cmd.Execute(); err != nil {
		var exitErr exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

			cfg, err := buildConfig(opts, args, cwd, deps.environ())
			if err != nil {
				return err
			}
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
	flags.BoolVar(&opts.mitm, "mitm", false, "enable MITM support")
	flags.Int64Var(&opts.maxRequestBodyBytes, "max-request-body-bytes", 64<<10, "maximum request body inspection size for MITM")
	flags.BoolVar(&opts.printPolicy, "print-policy", false, "print the effective policy before execution")

	flags.StringArrayVar(&opts.allowedDomains, "allowed-domain", nil, "allowed domain or wildcard entry")
	flags.StringVar(&opts.allowedDomainsFile, "allowed-domains-file", "", "file containing allowed domains or wildcards")
	flags.StringArrayVar(&opts.denyDomains, "deny-domain", nil, "denied domain or wildcard entry")
	flags.StringArrayVar(&opts.allowHTTPMethods, "allow-http-method", nil, "allowed HTTP method")
	flags.BoolVar(&opts.allowConnect, "allow-connect", true, "allow HTTPS CONNECT tunneling")
	flags.StringArrayVar(&opts.allowConnectPorts, "allow-connect-port", nil, "allowed CONNECT destination port or range")
	flags.StringArrayVar(&opts.allowPaths, "allow-path", nil, "allowed request path regex")
	flags.StringArrayVar(&opts.denyPaths, "deny-path", nil, "denied request path regex")

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

	workDir := strings.TrimSpace(opts.workDir)
	if workDir == "" {
		workDir = absCWD
	} else if !filepath.IsAbs(workDir) {
		workDir = filepath.Join(absCWD, workDir)
	}

	mounts := make([]bbox.Mount, 0, 1+len(opts.mountRO)+len(opts.mountRW))
	if !hasMount(absCWD, absCWD, append(opts.mountRO, opts.mountRW...)) {
		mounts = append(mounts, bbox.Mount{
			Source:   absCWD,
			Target:   absCWD,
			ReadOnly: false,
		})
	}

	for _, spec := range opts.mountRO {
		mount, err := parseMountSpec(spec, true)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, mount)
	}
	for _, spec := range opts.mountRW {
		mount, err := parseMountSpec(spec, false)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, mount)
	}

	trafficMode := bbox.TrafficMode(strings.ToLower(strings.TrimSpace(opts.trafficMode)))
	if trafficMode == "" {
		trafficMode = bbox.TrafficModeProxy
	}
	if trafficMode != bbox.TrafficModeProxy && trafficMode != bbox.TrafficModeTransparent {
		return runConfig{}, fmt.Errorf("unsupported traffic mode %q", opts.trafficMode)
	}
	if trafficMode == bbox.TrafficModeTransparent && !opts.mitm {
		return runConfig{}, fmt.Errorf("transparent mode requires --mitm")
	}

	allowPatterns, err := buildDomainPatterns(opts.allowedDomains, opts.allowedDomainsFile)
	if err != nil {
		return runConfig{}, err
	}
	denyPatterns, err := buildDomainPatterns(opts.denyDomains, "")
	if err != nil {
		return runConfig{}, err
	}

	envEntries, err := buildSandboxEnv(opts, environ)
	if err != nil {
		return runConfig{}, err
	}

	connectPorts := append([]string(nil), opts.allowConnectPorts...)
	if len(connectPorts) == 0 {
		connectPorts = []string{"443"}
	}

	binaries := make([]string, 0, 1+len(opts.binaries))
	binaries = append(binaries, payload[0])
	for _, binary := range opts.binaries {
		if !contains(binaries, binary) {
			binaries = append(binaries, binary)
		}
	}

	return runConfig{
		manager: bbox.ProxyOptions{
			MaxRequestBodyBytes: opts.maxRequestBodyBytes,
			MITM:                bbox.MITMOptions{Enabled: opts.mitm},
		},
		sandbox: bbox.SandboxOptions{
			Name:        strings.TrimSpace(opts.name),
			Binaries:    binaries,
			Mounts:      mounts,
			Env:         envEntries,
			TrafficMode: trafficMode,
			Policy: bbox.NetworkPolicy{
				AllowHostPatterns: allowPatterns,
				DenyHostPatterns:  denyPatterns,
				AllowHTTPMethods:  normalizeHTTPMethods(opts.allowHTTPMethods),
				AllowConnect:      opts.allowConnect,
				AllowConnectPorts: connectPorts,
				AllowPathPatterns: append([]string(nil), opts.allowPaths...),
				DenyPathPatterns:  append([]string(nil), opts.denyPaths...),
			},
			WorkDir: workDir,
		},
		argv:        append([]string(nil), payload...),
		printPolicy: opts.printPolicy,
	}, nil
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

	runOpts, cleanup, err := buildInteractiveRunOptions()
	if err != nil {
		return err
	}
	defer cleanup()

	result, err := sandbox.RunInteractive(ctx, cfg.argv, runOpts)
	if err != nil {
		return err
	}
	if result != nil && result.ExitCode != 0 {
		return exitCodeError{code: result.ExitCode}
	}
	return nil
}

func buildInteractiveRunOptions() (bbox.RunOptions, func(), error) {
	opts := bbox.RunOptions{
		Interactive: true,
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
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
