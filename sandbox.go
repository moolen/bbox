package bbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Sandbox is a long-lived bubblewrap helper plus its staged filesystem root and
// per-sandbox runtime configuration.
type Sandbox struct {
	manager *ProxyManager
	id      string
	root    string
	runtime sandboxRuntime

	trafficMode TrafficMode
	policyMode  PolicyMode
	reporting   ReportingOptions
	proxyAddr   string
	baseEnv     []string
	workDir     string

	registered bool

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
	effectivePolicyMode := m.policyMode
	if opts.PolicyMode != "" {
		effectivePolicyMode = opts.PolicyMode
	}
	policyMode, err := normalizePolicyMode(effectivePolicyMode)
	if err != nil {
		return nil, err
	}
	reporting := m.reporting
	if opts.Reporting != (ReportingOptions{}) {
		reporting = opts.Reporting
	}

	policy, err := compilePolicy(opts.Policy)
	if err != nil {
		return nil, err
	}

	sandboxID := m.nextSandboxName(opts.Name)
	setup, err := m.newSandboxRuntime(ctx, sandboxID, opts, mode)
	if err != nil {
		return nil, err
	}
	sandbox := &Sandbox{
		manager:     m,
		id:          sandboxID,
		root:        setup.root,
		runtime:     setup.runtime,
		trafficMode: mode,
		policyMode:  policyMode,
		reporting:   reporting,
		workDir:     opts.WorkDir,
	}
	proxyAddr := ""
	if mode == TrafficModeProxy {
		proxyAddr = setup.runtime.ProxyAddr()
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
	return s.run(ctx, argv, opts, false)
}

// RunInteractive executes argv inside the sandbox with live stdio forwarding.
func (s *Sandbox) RunInteractive(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	return s.run(ctx, argv, opts, true)
}

func (s *Sandbox) run(ctx context.Context, argv []string, opts RunOptions, interactive bool) (*RunResult, error) {
	if len(argv) == 0 {
		return nil, errors.New("argv must not be empty")
	}
	if s == nil || s.runtime == nil {
		return nil, errors.New("sandbox is not running")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runOpts := RunOptions{
		Env:          mergeEnv(s.baseEnv, opts.Env),
		WorkDir:      opts.WorkDir,
		Interactive:  opts.Interactive || interactive,
		Stdin:        opts.Stdin,
		Stdout:       opts.Stdout,
		Stderr:       opts.Stderr,
		Terminal:     opts.Terminal,
		TerminalSize: opts.TerminalSize,
		Resize:       opts.Resize,
	}
	if runOpts.WorkDir == "" {
		runOpts.WorkDir = s.workDir
	}

	return s.runtime.Run(ctx, argv, runOpts)
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
	if s.runtime != nil && s.runtime.ProxyAddr() != "" {
		return s.runtime.ProxyAddr()
	}
	return s.proxyAddr
}

// ProxyURL returns the helper's sandbox-local proxy endpoint as an HTTP URL.
func (s *Sandbox) ProxyURL() string {
	addr := s.ProxyAddr()
	if s == nil || addr == "" {
		return ""
	}
	return proxyURL(addr)
}

func (s *Sandbox) helperLogContents() string {
	if s == nil || s.runtime == nil {
		return ""
	}
	if runtime, ok := s.runtime.(interface{ helperLogContents() string }); ok {
		return runtime.helperLogContents()
	}
	return ""
}

func (s *Sandbox) runtimeDone() <-chan error {
	if s == nil || s.runtime == nil {
		return nil
	}
	if runtime, ok := s.runtime.(interface{ doneChan() <-chan error }); ok {
		return runtime.doneChan()
	}
	return nil
}

func (s *Sandbox) runtimeProcessState() *os.ProcessState {
	if s == nil || s.runtime == nil {
		return nil
	}
	if runtime, ok := s.runtime.(interface{ processState() *os.ProcessState }); ok {
		return runtime.processState()
	}
	return nil
}

// AccessedDomains returns a snapshot of the sandbox access audit state.
func (s *Sandbox) AccessedDomains() []AccessedDomain {
	if s == nil || s.manager == nil {
		return []AccessedDomain{}
	}
	return s.manager.accessedDomainsSnapshot(s.id)
}

// AccessSummary returns a richer access audit snapshot.
func (s *Sandbox) AccessSummary() AccessSummary {
	if s == nil || s.manager == nil {
		return AccessSummary{
			Hosts:    []AccessedHostSummary{},
			Requests: []RequestAggregate{},
		}
	}
	return s.manager.accessSummarySnapshot(s.id)
}

// Close stops the sandbox helper, unregisters the sandbox, and removes the
// staged root filesystem.
func (s *Sandbox) Close() error {
	if s == nil {
		return nil
	}

	s.closeOnce.Do(func() {
		var closeErr error

		if s.runtime != nil {
			closeErr = errors.Join(closeErr, s.runtime.Close())
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

func validateSandboxOptions(opts SandboxOptions, mitmEnabled bool) error {
	if opts.WorkDir != "" && !filepath.IsAbs(opts.WorkDir) {
		return fmt.Errorf("sandbox workdir %q must be absolute", opts.WorkDir)
	}
	mode := normalizeTrafficMode(opts.TrafficMode)
	switch mode {
	case TrafficModeProxy, TrafficModeTransparent:
	default:
		return fmt.Errorf("sandbox traffic mode %q is not supported", opts.TrafficMode)
	}
	if _, err := normalizePolicyMode(opts.PolicyMode); err != nil {
		return err
	}
	if sandboxPlatform == "darwin" {
		if mode == TrafficModeTransparent {
			return errUnsupportedPlatformFeature("darwin", "transparent traffic mode")
		}
		for _, mount := range opts.Mounts {
			if mount.ReadOnly {
				return errUnsupportedPlatformFeature("darwin", "mount_ro")
			}
			return errUnsupportedPlatformFeature("darwin", "mount_rw")
		}
		if !isZeroSeccompOptions(opts.Seccomp) {
			return errUnsupportedPlatformFeature("darwin", "seccomp")
		}
		return nil
	}
	if err := validateMounts(opts.Mounts); err != nil {
		return err
	}
	if mode == TrafficModeTransparent && !mitmEnabled {
		return errors.New("transparent traffic mode requires MITM to be enabled")
	}
	if err := validateSeccompOptions(opts.Seccomp); err != nil {
		return err
	}
	return nil
}

func errUnsupportedPlatformFeature(platform string, feature string) error {
	return fmt.Errorf("%s is not supported on %s", feature, platform)
}

func isZeroSeccompOptions(opts SeccompOptions) bool {
	return !opts.Disabled && opts.Profile == "" && len(opts.Rules) == 0
}

func runEnvForProxyAddr(proxyAddr string, extraEnv []string) []string {
	pathValue := defaultRunEnvPath
	if value, ok := lastEnvValue(extraEnv, "PATH"); ok {
		pathValue = value
	}
	return mergeEnv(
		filterReservedEnv(extraEnv),
		[]string{
			"PATH=" + pathValue,
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
		pathValue := defaultRunEnvPath
		if value, ok := lastEnvValue(extraEnv, "PATH"); ok {
			pathValue = value
		}
		return mergeEnv(
			filterReservedEnv(extraEnv),
			[]string{
				"PATH=" + pathValue,
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

const defaultRunEnvPath = "/usr/bin"

func lastEnvValue(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		entryKey, value, ok := splitEnv(env[i])
		if !ok {
			continue
		}
		if entryKey == key {
			return value, true
		}
	}
	return "", false
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
