package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type cliPolicyRuleConfig struct {
	HostPatterns   []string            `yaml:"host_patterns"`
	IPCIDRs        []string            `yaml:"ip_cidrs"`
	HTTPMethods    []string            `yaml:"http_methods"`
	ConnectPorts   []string            `yaml:"connect_ports"`
	PathPatterns   []string            `yaml:"path_patterns"`
	HeaderPatterns map[string][]string `yaml:"header_patterns"`
	BodyPatterns   []string            `yaml:"body_patterns"`
}

type cliPolicyConfig struct {
	Rules    []cliPolicyRuleConfig `yaml:"rules"`
	hasRules bool                  `yaml:"-"`
}

type cliDockerSocketHTTPConfig struct {
	Methods      []string `yaml:"methods"`
	PathPatterns []string `yaml:"path_patterns"`
}

type cliDockerSocketBuildConfig struct {
	Context         string   `yaml:"context"`
	DockerfilePaths []string `yaml:"dockerfile_paths"`
}

type cliDockerSocketRuleConfig struct {
	Action     string                      `yaml:"action"`
	Operations []string                    `yaml:"operations"`
	HTTP       *cliDockerSocketHTTPConfig  `yaml:"http"`
	Build      *cliDockerSocketBuildConfig `yaml:"build"`
}

type cliDockerSocketConfig struct {
	Enabled          bool                        `yaml:"enabled"`
	MountPath        string                      `yaml:"mount_path"`
	TargetSocketPath string                      `yaml:"target_socket_path"`
	DefaultAction    string                      `yaml:"default_action"`
	Rules            []cliDockerSocketRuleConfig `yaml:"rules"`
	hasEnabled       bool                        `yaml:"-"`
	hasMountPath     bool                        `yaml:"-"`
	hasTargetPath    bool                        `yaml:"-"`
	hasDefaultAction bool                        `yaml:"-"`
	hasRules         bool                        `yaml:"-"`
}

type cliDockerBuildConfig struct {
	Enabled       bool   `yaml:"enabled"`
	BuildkitdPath string `yaml:"buildkitd_path"`
	BuildctlPath  string `yaml:"buildctl_path"`
	RuncPath      string `yaml:"runc_path"`
	PodmanPath    string `yaml:"podman_path"`
	NewuidmapPath string `yaml:"newuidmap_path"`
	NewgidmapPath string `yaml:"newgidmap_path"`
	hasEnabled    bool   `yaml:"-"`
	hasBuildkitd  bool   `yaml:"-"`
	hasBuildctl   bool   `yaml:"-"`
	hasRunc       bool   `yaml:"-"`
	hasPodman     bool   `yaml:"-"`
	hasNewuidmap  bool   `yaml:"-"`
	hasNewgidmap  bool   `yaml:"-"`
}

type cliFileConfig struct {
	Name                      string                `yaml:"name"`
	WorkDir                   string                `yaml:"workdir"`
	Bin                       []string              `yaml:"bin"`
	MountRO                   []string              `yaml:"mount_ro"`
	MountRW                   []string              `yaml:"mount_rw"`
	Env                       []string              `yaml:"env"`
	ClearEnv                  bool                  `yaml:"clear_env"`
	TrafficMode               string                `yaml:"traffic_mode"`
	MaxRequestBodyBytes       int64                 `yaml:"max_request_body_bytes"`
	AccessLog                 string                `yaml:"access_log"`
	ReportPolicyViolations    bool                  `yaml:"report_policy_violations"`
	ReportAccessSummary       bool                  `yaml:"report_access_summary"`
	ReportRequestSummary      bool                  `yaml:"report_request_summary"`
	Policy                    cliPolicyConfig       `yaml:"policy"`
	DockerSocket              cliDockerSocketConfig `yaml:"docker_socket"`
	DockerBuild               cliDockerBuildConfig  `yaml:"docker_build"`
	hasName                   bool                  `yaml:"-"`
	hasWorkDir                bool                  `yaml:"-"`
	hasBin                    bool                  `yaml:"-"`
	hasMountRO                bool                  `yaml:"-"`
	hasMountRW                bool                  `yaml:"-"`
	hasEnv                    bool                  `yaml:"-"`
	hasClearEnv               bool                  `yaml:"-"`
	hasTrafficMode            bool                  `yaml:"-"`
	hasMaxRequestBodyBytes    bool                  `yaml:"-"`
	hasAccessLog              bool                  `yaml:"-"`
	hasReportPolicyViolations bool                  `yaml:"-"`
	hasReportAccessSummary    bool                  `yaml:"-"`
	hasReportRequestSummary   bool                  `yaml:"-"`
}

type rawCLIPolicyConfig struct {
	Rules *[]cliPolicyRuleConfig `yaml:"rules"`
}

type rawCLIDockerSocketHTTPConfig struct {
	Methods      *[]string `yaml:"methods"`
	PathPatterns *[]string `yaml:"path_patterns"`
}

type rawCLIDockerSocketBuildConfig struct {
	Context         *string   `yaml:"context"`
	DockerfilePaths *[]string `yaml:"dockerfile_paths"`
}

type rawCLIDockerSocketRuleConfig struct {
	Action     *string                        `yaml:"action"`
	Operations *[]string                      `yaml:"operations"`
	HTTP       *rawCLIDockerSocketHTTPConfig  `yaml:"http"`
	Build      *rawCLIDockerSocketBuildConfig `yaml:"build"`
}

type rawCLIDockerSocketConfig struct {
	Enabled          *bool                           `yaml:"enabled"`
	MountPath        *string                         `yaml:"mount_path"`
	TargetSocketPath *string                         `yaml:"target_socket_path"`
	DefaultAction    *string                         `yaml:"default_action"`
	Rules            *[]rawCLIDockerSocketRuleConfig `yaml:"rules"`
}

type rawCLIDockerBuildConfig struct {
	Enabled       *bool   `yaml:"enabled"`
	BuildkitdPath *string `yaml:"buildkitd_path"`
	BuildctlPath  *string `yaml:"buildctl_path"`
	RuncPath      *string `yaml:"runc_path"`
	PodmanPath    *string `yaml:"podman_path"`
	NewuidmapPath *string `yaml:"newuidmap_path"`
	NewgidmapPath *string `yaml:"newgidmap_path"`
}

type rawCLIFileConfig struct {
	Name                   *string                   `yaml:"name"`
	WorkDir                *string                   `yaml:"workdir"`
	Bin                    *[]string                 `yaml:"bin"`
	MountRO                *[]string                 `yaml:"mount_ro"`
	MountRW                *[]string                 `yaml:"mount_rw"`
	Env                    *[]string                 `yaml:"env"`
	ClearEnv               *bool                     `yaml:"clear_env"`
	TrafficMode            *string                   `yaml:"traffic_mode"`
	MaxRequestBodyBytes    *int64                    `yaml:"max_request_body_bytes"`
	AccessLog              *string                   `yaml:"access_log"`
	ReportPolicyViolations *bool                     `yaml:"report_policy_violations"`
	ReportAccessSummary    *bool                     `yaml:"report_access_summary"`
	ReportRequestSummary   *bool                     `yaml:"report_request_summary"`
	Policy                 *rawCLIPolicyConfig       `yaml:"policy"`
	DockerSocket           *rawCLIDockerSocketConfig `yaml:"docker_socket"`
	DockerBuild            *rawCLIDockerBuildConfig  `yaml:"docker_build"`
}

type cliFlagOverrides struct {
	TrafficMode          *string
	ReportPolicy         *bool
	ReportAccessSummary  *bool
	ReportRequestSummary *bool
	AccessLog            *string
}

func findConfigFile(startDir string) (string, error) {
	current, err := filepath.Abs(startDir)
	if err != nil {
		return "", fmt.Errorf("resolve config search directory %q: %w", startDir, err)
	}

	for {
		candidate := filepath.Join(current, "bbox.yaml")
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("stat config file %q: %w", candidate, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", nil
		}
		current = parent
	}
}

func loadCLIFileConfig(path string) (cliFileConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return cliFileConfig{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	var raw rawCLIFileConfig
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		if err == io.EOF {
			return cliFileConfig{}, nil
		}
		return cliFileConfig{}, fmt.Errorf("decode config file %q: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cliFileConfig{}, fmt.Errorf("decode config file %q: multiple YAML documents are not supported", path)
	}

	cfg := toCLIFileConfig(raw)
	resolveCLIFileConfigPaths(&cfg, filepath.Dir(path))
	return cfg, nil
}

func toCLIFileConfig(raw rawCLIFileConfig) cliFileConfig {
	var cfg cliFileConfig
	if raw.Name != nil {
		cfg.Name = *raw.Name
		cfg.hasName = true
	}
	if raw.WorkDir != nil {
		cfg.WorkDir = *raw.WorkDir
		cfg.hasWorkDir = true
	}
	if raw.Bin != nil {
		cfg.Bin = cloneStringSlice(*raw.Bin)
		cfg.hasBin = true
	}
	if raw.MountRO != nil {
		cfg.MountRO = cloneStringSlice(*raw.MountRO)
		cfg.hasMountRO = true
	}
	if raw.MountRW != nil {
		cfg.MountRW = cloneStringSlice(*raw.MountRW)
		cfg.hasMountRW = true
	}
	if raw.Env != nil {
		cfg.Env = cloneStringSlice(*raw.Env)
		cfg.hasEnv = true
	}
	if raw.ClearEnv != nil {
		cfg.ClearEnv = *raw.ClearEnv
		cfg.hasClearEnv = true
	}
	if raw.TrafficMode != nil {
		cfg.TrafficMode = *raw.TrafficMode
		cfg.hasTrafficMode = true
	}
	if raw.MaxRequestBodyBytes != nil {
		cfg.MaxRequestBodyBytes = *raw.MaxRequestBodyBytes
		cfg.hasMaxRequestBodyBytes = true
	}
	if raw.AccessLog != nil {
		cfg.AccessLog = *raw.AccessLog
		cfg.hasAccessLog = true
	}
	if raw.ReportPolicyViolations != nil {
		cfg.ReportPolicyViolations = *raw.ReportPolicyViolations
		cfg.hasReportPolicyViolations = true
	}
	if raw.ReportAccessSummary != nil {
		cfg.ReportAccessSummary = *raw.ReportAccessSummary
		cfg.hasReportAccessSummary = true
	}
	if raw.ReportRequestSummary != nil {
		cfg.ReportRequestSummary = *raw.ReportRequestSummary
		cfg.hasReportRequestSummary = true
	}
	if raw.Policy != nil && raw.Policy.Rules != nil {
		cfg.Policy.Rules = clonePolicyRules(*raw.Policy.Rules)
		cfg.Policy.hasRules = true
	}
	if raw.DockerSocket != nil {
		if raw.DockerSocket.Enabled != nil {
			cfg.DockerSocket.Enabled = *raw.DockerSocket.Enabled
			cfg.DockerSocket.hasEnabled = true
		}
		if raw.DockerSocket.MountPath != nil {
			cfg.DockerSocket.MountPath = *raw.DockerSocket.MountPath
			cfg.DockerSocket.hasMountPath = true
		}
		if raw.DockerSocket.TargetSocketPath != nil {
			cfg.DockerSocket.TargetSocketPath = *raw.DockerSocket.TargetSocketPath
			cfg.DockerSocket.hasTargetPath = true
		}
		if raw.DockerSocket.DefaultAction != nil {
			cfg.DockerSocket.DefaultAction = *raw.DockerSocket.DefaultAction
			cfg.DockerSocket.hasDefaultAction = true
		}
		if raw.DockerSocket.Rules != nil {
			cfg.DockerSocket.Rules = cloneDockerSocketRules(toCLIDockerSocketRules(*raw.DockerSocket.Rules))
			cfg.DockerSocket.hasRules = true
		}
	}
	if raw.DockerBuild != nil {
		if raw.DockerBuild.Enabled != nil {
			cfg.DockerBuild.Enabled = *raw.DockerBuild.Enabled
			cfg.DockerBuild.hasEnabled = true
		}
		if raw.DockerBuild.BuildkitdPath != nil {
			cfg.DockerBuild.BuildkitdPath = *raw.DockerBuild.BuildkitdPath
			cfg.DockerBuild.hasBuildkitd = true
		}
		if raw.DockerBuild.BuildctlPath != nil {
			cfg.DockerBuild.BuildctlPath = *raw.DockerBuild.BuildctlPath
			cfg.DockerBuild.hasBuildctl = true
		}
		if raw.DockerBuild.RuncPath != nil {
			cfg.DockerBuild.RuncPath = *raw.DockerBuild.RuncPath
			cfg.DockerBuild.hasRunc = true
		}
		if raw.DockerBuild.PodmanPath != nil {
			cfg.DockerBuild.PodmanPath = *raw.DockerBuild.PodmanPath
			cfg.DockerBuild.hasPodman = true
		}
		if raw.DockerBuild.NewuidmapPath != nil {
			cfg.DockerBuild.NewuidmapPath = *raw.DockerBuild.NewuidmapPath
			cfg.DockerBuild.hasNewuidmap = true
		}
		if raw.DockerBuild.NewgidmapPath != nil {
			cfg.DockerBuild.NewgidmapPath = *raw.DockerBuild.NewgidmapPath
			cfg.DockerBuild.hasNewgidmap = true
		}
	}
	return cfg
}

func resolveCLIFileConfigPaths(cfg *cliFileConfig, configDir string) {
	if cfg.hasWorkDir {
		cfg.WorkDir = resolveConfigPath(cfg.WorkDir, configDir)
	}
	if cfg.hasMountRO {
		cfg.MountRO = resolveConfigMountSpecs(cfg.MountRO, configDir)
	}
	if cfg.hasMountRW {
		cfg.MountRW = resolveConfigMountSpecs(cfg.MountRW, configDir)
	}
	if cfg.DockerBuild.hasBuildkitd {
		cfg.DockerBuild.BuildkitdPath = resolveConfigPath(cfg.DockerBuild.BuildkitdPath, configDir)
	}
	if cfg.DockerBuild.hasBuildctl {
		cfg.DockerBuild.BuildctlPath = resolveConfigPath(cfg.DockerBuild.BuildctlPath, configDir)
	}
	if cfg.DockerBuild.hasRunc {
		cfg.DockerBuild.RuncPath = resolveConfigPath(cfg.DockerBuild.RuncPath, configDir)
	}
	if cfg.DockerBuild.hasPodman {
		cfg.DockerBuild.PodmanPath = resolveConfigPath(cfg.DockerBuild.PodmanPath, configDir)
	}
	if cfg.DockerBuild.hasNewuidmap {
		cfg.DockerBuild.NewuidmapPath = resolveConfigPath(cfg.DockerBuild.NewuidmapPath, configDir)
	}
	if cfg.DockerBuild.hasNewgidmap {
		cfg.DockerBuild.NewgidmapPath = resolveConfigPath(cfg.DockerBuild.NewgidmapPath, configDir)
	}
}

func resolveConfigPath(value string, baseDir string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

func resolveConfigMountSpecs(specs []string, baseDir string) []string {
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		src, dst, ok := strings.Cut(spec, ":")
		if !ok {
			out = append(out, spec)
			continue
		}
		out = append(out, resolveConfigPath(src, baseDir)+":"+resolveConfigPath(dst, baseDir))
	}
	return out
}

func defaultCLIFileConfig() cliFileConfig {
	return cliFileConfig{
		TrafficMode:               "proxy",
		AccessLog:                 "json",
		ReportPolicyViolations:    true,
		ReportAccessSummary:       true,
		ReportRequestSummary:      true,
		hasTrafficMode:            true,
		hasAccessLog:              true,
		hasReportPolicyViolations: true,
		hasReportAccessSummary:    true,
		hasReportRequestSummary:   true,
		Policy: cliPolicyConfig{
			Rules: []cliPolicyRuleConfig{
				{ConnectPorts: []string{"443"}},
			},
			hasRules: true,
		},
	}
}

func mergeCLIConfig(defaults cliFileConfig, fileCfg cliFileConfig, flags cliFlagOverrides, audit bool) cliFileConfig {
	merged := mergeCLIConfigLayer(defaults, fileCfg)

	if flags.TrafficMode != nil {
		merged.TrafficMode = *flags.TrafficMode
		merged.hasTrafficMode = true
	}
	if flags.ReportPolicy != nil {
		merged.ReportPolicyViolations = *flags.ReportPolicy
		merged.hasReportPolicyViolations = true
	}
	if flags.ReportAccessSummary != nil {
		merged.ReportAccessSummary = *flags.ReportAccessSummary
		merged.hasReportAccessSummary = true
	}
	if flags.ReportRequestSummary != nil {
		merged.ReportRequestSummary = *flags.ReportRequestSummary
		merged.hasReportRequestSummary = true
	}
	if flags.AccessLog != nil {
		merged.AccessLog = *flags.AccessLog
		merged.hasAccessLog = true
	}

	if audit {
		merged.ReportPolicyViolations = true
		merged.ReportAccessSummary = true
		merged.ReportRequestSummary = true
		merged.hasReportPolicyViolations = true
		merged.hasReportAccessSummary = true
		merged.hasReportRequestSummary = true
	}

	return merged
}

func mergeCLIConfigLayer(base cliFileConfig, overlay cliFileConfig) cliFileConfig {
	if overlay.hasName {
		base.Name = overlay.Name
		base.hasName = true
	}
	if overlay.hasWorkDir {
		base.WorkDir = overlay.WorkDir
		base.hasWorkDir = true
	}
	if overlay.hasBin {
		base.Bin = cloneStringSlice(overlay.Bin)
		base.hasBin = true
	}
	if overlay.hasMountRO {
		base.MountRO = cloneStringSlice(overlay.MountRO)
		base.hasMountRO = true
	}
	if overlay.hasMountRW {
		base.MountRW = cloneStringSlice(overlay.MountRW)
		base.hasMountRW = true
	}
	if overlay.hasEnv {
		base.Env = cloneStringSlice(overlay.Env)
		base.hasEnv = true
	}
	if overlay.hasClearEnv {
		base.ClearEnv = overlay.ClearEnv
		base.hasClearEnv = true
	}
	if overlay.hasTrafficMode {
		base.TrafficMode = overlay.TrafficMode
		base.hasTrafficMode = true
	}
	if overlay.hasMaxRequestBodyBytes {
		base.MaxRequestBodyBytes = overlay.MaxRequestBodyBytes
		base.hasMaxRequestBodyBytes = true
	}
	if overlay.hasAccessLog {
		base.AccessLog = overlay.AccessLog
		base.hasAccessLog = true
	}
	if overlay.hasReportPolicyViolations {
		base.ReportPolicyViolations = overlay.ReportPolicyViolations
		base.hasReportPolicyViolations = true
	}
	if overlay.hasReportAccessSummary {
		base.ReportAccessSummary = overlay.ReportAccessSummary
		base.hasReportAccessSummary = true
	}
	if overlay.hasReportRequestSummary {
		base.ReportRequestSummary = overlay.ReportRequestSummary
		base.hasReportRequestSummary = true
	}
	if overlay.Policy.hasRules {
		base.Policy.Rules = clonePolicyRules(overlay.Policy.Rules)
		base.Policy.hasRules = true
	}
	if overlay.DockerSocket.hasEnabled {
		base.DockerSocket.Enabled = overlay.DockerSocket.Enabled
		base.DockerSocket.hasEnabled = true
	}
	if overlay.DockerSocket.hasMountPath {
		base.DockerSocket.MountPath = overlay.DockerSocket.MountPath
		base.DockerSocket.hasMountPath = true
	}
	if overlay.DockerSocket.hasTargetPath {
		base.DockerSocket.TargetSocketPath = overlay.DockerSocket.TargetSocketPath
		base.DockerSocket.hasTargetPath = true
	}
	if overlay.DockerSocket.hasDefaultAction {
		base.DockerSocket.DefaultAction = overlay.DockerSocket.DefaultAction
		base.DockerSocket.hasDefaultAction = true
	}
	if overlay.DockerSocket.hasRules {
		base.DockerSocket.Rules = cloneDockerSocketRules(overlay.DockerSocket.Rules)
		base.DockerSocket.hasRules = true
	}
	if overlay.DockerBuild.hasEnabled {
		base.DockerBuild.Enabled = overlay.DockerBuild.Enabled
		base.DockerBuild.hasEnabled = true
	}
	if overlay.DockerBuild.hasBuildkitd {
		base.DockerBuild.BuildkitdPath = overlay.DockerBuild.BuildkitdPath
		base.DockerBuild.hasBuildkitd = true
	}
	if overlay.DockerBuild.hasBuildctl {
		base.DockerBuild.BuildctlPath = overlay.DockerBuild.BuildctlPath
		base.DockerBuild.hasBuildctl = true
	}
	if overlay.DockerBuild.hasRunc {
		base.DockerBuild.RuncPath = overlay.DockerBuild.RuncPath
		base.DockerBuild.hasRunc = true
	}
	if overlay.DockerBuild.hasPodman {
		base.DockerBuild.PodmanPath = overlay.DockerBuild.PodmanPath
		base.DockerBuild.hasPodman = true
	}
	if overlay.DockerBuild.hasNewuidmap {
		base.DockerBuild.NewuidmapPath = overlay.DockerBuild.NewuidmapPath
		base.DockerBuild.hasNewuidmap = true
	}
	if overlay.DockerBuild.hasNewgidmap {
		base.DockerBuild.NewgidmapPath = overlay.DockerBuild.NewgidmapPath
		base.DockerBuild.hasNewgidmap = true
	}
	return base
}

func cloneStringSlice(in []string) []string {
	return append([]string(nil), in...)
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = cloneStringSlice(v)
	}
	return out
}

func clonePolicyRules(in []cliPolicyRuleConfig) []cliPolicyRuleConfig {
	out := make([]cliPolicyRuleConfig, 0, len(in))
	for _, rule := range in {
		out = append(out, cliPolicyRuleConfig{
			HostPatterns:   cloneStringSlice(rule.HostPatterns),
			IPCIDRs:        cloneStringSlice(rule.IPCIDRs),
			HTTPMethods:    cloneStringSlice(rule.HTTPMethods),
			ConnectPorts:   cloneStringSlice(rule.ConnectPorts),
			PathPatterns:   cloneStringSlice(rule.PathPatterns),
			HeaderPatterns: cloneStringSliceMap(rule.HeaderPatterns),
			BodyPatterns:   cloneStringSlice(rule.BodyPatterns),
		})
	}
	return out
}

func toCLIDockerSocketRules(in []rawCLIDockerSocketRuleConfig) []cliDockerSocketRuleConfig {
	out := make([]cliDockerSocketRuleConfig, 0, len(in))
	for _, rule := range in {
		next := cliDockerSocketRuleConfig{}
		if rule.Action != nil {
			next.Action = *rule.Action
		}
		if rule.Operations != nil {
			next.Operations = cloneStringSlice(*rule.Operations)
		}
		if rule.HTTP != nil {
			next.HTTP = &cliDockerSocketHTTPConfig{}
			if rule.HTTP.Methods != nil {
				next.HTTP.Methods = cloneStringSlice(*rule.HTTP.Methods)
			}
			if rule.HTTP.PathPatterns != nil {
				next.HTTP.PathPatterns = cloneStringSlice(*rule.HTTP.PathPatterns)
			}
		}
		if rule.Build != nil {
			next.Build = &cliDockerSocketBuildConfig{}
			if rule.Build.Context != nil {
				next.Build.Context = *rule.Build.Context
			}
			if rule.Build.DockerfilePaths != nil {
				next.Build.DockerfilePaths = cloneStringSlice(*rule.Build.DockerfilePaths)
			}
		}
		out = append(out, next)
	}
	return out
}

func cloneDockerSocketRules(in []cliDockerSocketRuleConfig) []cliDockerSocketRuleConfig {
	out := make([]cliDockerSocketRuleConfig, 0, len(in))
	for _, rule := range in {
		next := cliDockerSocketRuleConfig{
			Action:     rule.Action,
			Operations: cloneStringSlice(rule.Operations),
		}
		if rule.HTTP != nil {
			next.HTTP = &cliDockerSocketHTTPConfig{
				Methods:      cloneStringSlice(rule.HTTP.Methods),
				PathPatterns: cloneStringSlice(rule.HTTP.PathPatterns),
			}
		}
		if rule.Build != nil {
			next.Build = &cliDockerSocketBuildConfig{
				Context:         rule.Build.Context,
				DockerfilePaths: cloneStringSlice(rule.Build.DockerfilePaths),
			}
		}
		out = append(out, next)
	}
	return out
}
