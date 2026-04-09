package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moolen/bbox"
	"github.com/moolen/bbox/internal/sandboxroot"
)

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

func buildRunConfig(effective effectiveCLIConfig, payload []string, cwd string, environ []string) (runConfig, error) {
	if len(payload) == 0 {
		return runConfig{}, fmt.Errorf("payload command required after --")
	}

	absCWD, err := filepath.Abs(cwd)
	if err != nil {
		return runConfig{}, fmt.Errorf("resolve current working directory: %w", err)
	}

	explicitMounts := make([]bbox.Mount, 0, len(effective.Mounts))
	for _, configuredMount := range effective.Mounts {
		mount, err := toBBoxMount(configuredMount)
		if err != nil {
			return runConfig{}, err
		}
		explicitMounts = append(explicitMounts, mount)
	}

	mounts := make([]bbox.Mount, 0, 1+len(explicitMounts))
	if cliPlatform != "darwin" && !hasMount(absCWD, absCWD, explicitMounts) {
		mounts = append(mounts, bbox.Mount{
			Type:     bbox.MountTypeBind,
			Source:   absCWD,
			Target:   absCWD,
			ReadOnly: true,
		})
	}
	mounts = append(mounts, explicitMounts...)

	trafficMode := bbox.TrafficMode(strings.ToLower(strings.TrimSpace(effective.TrafficMode)))
	if trafficMode == "" {
		trafficMode = bbox.TrafficModeProxy
	}
	if trafficMode != bbox.TrafficModeProxy && trafficMode != bbox.TrafficModeTransparent {
		return runConfig{}, fmt.Errorf("unsupported traffic mode %q", effective.TrafficMode)
	}
	policyMode, err := normalizeCLIPolicyMode(effective.PolicyMode)
	if err != nil {
		return runConfig{}, err
	}

	envEntries, err := buildSandboxEnv(effective, environ)
	if err != nil {
		return runConfig{}, err
	}
	envEntries = withDockerBuildPATHEnv(envEntries, effective.DockerBuild.Enabled)
	if cliPlatform != "darwin" {
		pathMounts, err := pathAvailabilityMounts(envEntries, absCWD, mounts, effective.DockerBuild.Enabled)
		if err != nil {
			return runConfig{}, err
		}
		mounts = append(mounts, pathMounts...)
	}

	dockerBuild := buildDockerBuildOptions(effective.DockerBuild)
	binaries := make([]string, 0, 1+len(effective.Binaries))
	binaries, err = resolveRequestedBinaries(append([]string{payload[0]}, effective.Binaries...), envEntries, absCWD, dockerBuild)
	if err != nil {
		return runConfig{}, err
	}

	accessLogMode, err := normalizeAccessLogMode(effective.AccessLog)
	if err != nil {
		return runConfig{}, err
	}

	return runConfig{
		manager: bbox.ProxyOptions{
			MaxRequestBodyBytes: effective.MaxRequestBodyBytes,
			MITM:                bbox.MITMOptions{Enabled: trafficMode == bbox.TrafficModeTransparent},
			PolicyMode:          policyMode,
			Reporting:           effective.Reporting,
			DockerSocket:        buildDockerSocketOptions(effective.DockerSocket),
		},
		sandbox: bbox.SandboxOptions{
			Name:         strings.TrimSpace(effective.Name),
			Binaries:     binaries,
			Mounts:       mounts,
			Env:          envEntries,
			TrafficMode:  trafficMode,
			Policy:       buildNetworkPolicy(effective.Policy),
			WorkDir:      effective.WorkDir,
			DockerSocket: buildDockerSocketOptions(effective.DockerSocket),
			DockerBuild:  dockerBuild,
		},
		argv:          append([]string(nil), payload...),
		reporting:     effective.Reporting,
		accessLogMode: accessLogMode,
	}, nil
}

func normalizeCLIPolicyMode(mode string) (bbox.PolicyMode, error) {
	switch bbox.PolicyMode(strings.ToLower(strings.TrimSpace(mode))) {
	case "", bbox.PolicyModeEnforce:
		return bbox.PolicyModeEnforce, nil
	case bbox.PolicyModeAudit:
		return bbox.PolicyModeAudit, nil
	default:
		return "", fmt.Errorf("unsupported policy mode %q", mode)
	}
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

func buildSandboxEnv(effective effectiveCLIConfig, environ []string) ([]string, error) {
	var envEntries []string
	if !effective.ClearEnv {
		envEntries = append(envEntries, environ...)
	}
	for _, entry := range effective.Env {
		if _, _, ok := strings.Cut(entry, "="); !ok {
			return nil, fmt.Errorf("invalid env spec %q, want KEY=VALUE", entry)
		}
		envEntries = append(envEntries, entry)
	}
	return envEntries, nil
}

func withDockerBuildPATHEnv(envEntries []string, dockerBuildEnabled bool) []string {
	if !dockerBuildEnabled {
		return envEntries
	}

	pathValue := "/usr/bin"
	if value, ok := lastEnvValue(envEntries, "PATH"); ok {
		pathValue = value
	}
	pathValue = sandboxroot.PrependPATHDir(pathValue, sandboxroot.DefaultSandboxBinDir)
	return append(envEntries, "PATH="+pathValue)
}

func resolveRequestedBinaries(requested []string, envEntries []string, cwd string, dockerBuild bbox.DockerBuildOptions) ([]string, error) {
	pathValue, hasPATH := lastEnvValue(envEntries, "PATH")
	binaries := make([]string, 0, len(requested))
	for _, binary := range requested {
		if dockerBuild.Enabled && binary == "docker" {
			continue
		}
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

func pathAvailabilityMounts(envEntries []string, cwd string, existing []bbox.Mount, dockerBuildEnabled bool) ([]bbox.Mount, error) {
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
		Type:     bbox.MountTypeBind,
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

func hasMount(source, target string, mounts []bbox.Mount) bool {
	wantSource := filepath.Clean(source)
	wantTarget := filepath.Clean(target)
	for _, mount := range mounts {
		if mount.Type != bbox.MountTypeBind {
			continue
		}
		if filepath.Clean(strings.TrimSpace(mount.Source)) == wantSource &&
			filepath.Clean(strings.TrimSpace(mount.Target)) == wantTarget {
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

func buildDockerSocketOptions(cfg cliDockerSocketConfig) bbox.DockerSocketOptions {
	rules := make([]bbox.DockerSocketRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		next := bbox.DockerSocketRule{
			Action:     bbox.DockerRuleAction(strings.ToLower(strings.TrimSpace(rule.Action))),
			Operations: normalizeDockerOperations(rule.Operations),
		}
		if rule.HTTP != nil {
			next.HTTP = &bbox.DockerHTTPMatch{
				Methods:      normalizeHTTPMethods(rule.HTTP.Methods),
				PathPatterns: cloneStringSlice(rule.HTTP.PathPatterns),
			}
		}
		if rule.Build != nil {
			next.Build = &bbox.DockerBuildMatch{
				Context:         bbox.DockerBuildContextMatch(strings.ToLower(strings.TrimSpace(rule.Build.Context))),
				DockerfilePaths: cloneStringSlice(rule.Build.DockerfilePaths),
			}
		}
		rules = append(rules, next)
	}

	return bbox.DockerSocketOptions{
		Enabled:          cfg.Enabled,
		MountPath:        strings.TrimSpace(cfg.MountPath),
		TargetSocketPath: strings.TrimSpace(cfg.TargetSocketPath),
		Policy: bbox.DockerSocketPolicy{
			DefaultAction: bbox.DockerRuleAction(strings.ToLower(strings.TrimSpace(cfg.DefaultAction))),
			Rules:         rules,
		},
	}
}

func buildDockerBuildOptions(cfg cliDockerBuildConfig) bbox.DockerBuildOptions {
	return bbox.DockerBuildOptions{
		Enabled:       cfg.Enabled,
		BuildkitdPath: strings.TrimSpace(cfg.BuildkitdPath),
		BuildctlPath:  strings.TrimSpace(cfg.BuildctlPath),
		RuncPath:      strings.TrimSpace(cfg.RuncPath),
		PodmanPath:    strings.TrimSpace(cfg.PodmanPath),
		NewuidmapPath: strings.TrimSpace(cfg.NewuidmapPath),
		NewgidmapPath: strings.TrimSpace(cfg.NewgidmapPath),
	}
}

func normalizeDockerOperations(values []string) []bbox.DockerOperation {
	ops := make([]bbox.DockerOperation, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		ops = append(ops, bbox.DockerOperation(value))
	}
	if len(ops) == 0 {
		return nil
	}
	return ops
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
