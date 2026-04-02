package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type cliPolicyConfig struct {
	AllowHostPatterns   []string            `yaml:"allow_host_patterns"`
	DenyHostPatterns    []string            `yaml:"deny_host_patterns"`
	AllowIPCIDRs        []string            `yaml:"allow_ip_cidrs"`
	DenyIPCIDRs         []string            `yaml:"deny_ip_cidrs"`
	AllowHTTPMethods    []string            `yaml:"allow_http_methods"`
	AllowConnect        bool                `yaml:"allow_connect"`
	AllowConnectPorts   []string            `yaml:"allow_connect_ports"`
	AllowPathPatterns   []string            `yaml:"allow_path_patterns"`
	DenyPathPatterns    []string            `yaml:"deny_path_patterns"`
	AllowHeaderPatterns map[string][]string `yaml:"allow_header_patterns"`
	DenyHeaderPatterns  map[string][]string `yaml:"deny_header_patterns"`
	AllowBodyPatterns   []string            `yaml:"allow_body_patterns"`
	DenyBodyPatterns    []string            `yaml:"deny_body_patterns"`
}

type cliFileConfig struct {
	Name                   string          `yaml:"name"`
	WorkDir                string          `yaml:"workdir"`
	Bin                    []string        `yaml:"bin"`
	MountRO                []string        `yaml:"mount_ro"`
	MountRW                []string        `yaml:"mount_rw"`
	Env                    []string        `yaml:"env"`
	ClearEnv               bool            `yaml:"clear_env"`
	TrafficMode            string          `yaml:"traffic_mode"`
	MaxRequestBodyBytes    int64           `yaml:"max_request_body_bytes"`
	AccessLog              string          `yaml:"access_log"`
	ReportPolicyViolations bool            `yaml:"report_policy_violations"`
	ReportAccessSummary    bool            `yaml:"report_access_summary"`
	ReportRequestSummary   bool            `yaml:"report_request_summary"`
	PolicyMode             string          `yaml:"policy_mode"`
	Policy                 cliPolicyConfig `yaml:"policy"`

	hasReportPolicyViolations bool `yaml:"-"`
	hasReportAccessSummary    bool `yaml:"-"`
	hasReportRequestSummary   bool `yaml:"-"`
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

	type rawCLIFileConfig struct {
		Name                   string          `yaml:"name"`
		WorkDir                string          `yaml:"workdir"`
		Bin                    []string        `yaml:"bin"`
		MountRO                []string        `yaml:"mount_ro"`
		MountRW                []string        `yaml:"mount_rw"`
		Env                    []string        `yaml:"env"`
		ClearEnv               bool            `yaml:"clear_env"`
		TrafficMode            string          `yaml:"traffic_mode"`
		MaxRequestBodyBytes    int64           `yaml:"max_request_body_bytes"`
		AccessLog              string          `yaml:"access_log"`
		ReportPolicyViolations *bool           `yaml:"report_policy_violations"`
		ReportAccessSummary    *bool           `yaml:"report_access_summary"`
		ReportRequestSummary   *bool           `yaml:"report_request_summary"`
		PolicyMode             string          `yaml:"policy_mode"`
		Policy                 cliPolicyConfig `yaml:"policy"`
	}

	var raw rawCLIFileConfig
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return cliFileConfig{}, fmt.Errorf("decode config file %q: %w", path, err)
	}

	cfg := cliFileConfig{
		Name:                raw.Name,
		WorkDir:             raw.WorkDir,
		Bin:                 raw.Bin,
		MountRO:             raw.MountRO,
		MountRW:             raw.MountRW,
		Env:                 raw.Env,
		ClearEnv:            raw.ClearEnv,
		TrafficMode:         raw.TrafficMode,
		MaxRequestBodyBytes: raw.MaxRequestBodyBytes,
		AccessLog:           raw.AccessLog,
		PolicyMode:          raw.PolicyMode,
		Policy:              raw.Policy,
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

	dir := filepath.Dir(path)
	resolveCLIFileConfigPaths(&cfg, dir)
	return cfg, nil
}

func resolveCLIFileConfigPaths(cfg *cliFileConfig, configDir string) {
	cfg.WorkDir = resolveConfigPath(cfg.WorkDir, configDir)
	cfg.MountRO = resolveConfigMountSpecs(cfg.MountRO, configDir)
	cfg.MountRW = resolveConfigMountSpecs(cfg.MountRW, configDir)
}

func resolveConfigPath(value string, baseDir string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}

func resolveConfigMountSpecs(specs []string, baseDir string) []string {
	if len(specs) == 0 {
		return nil
	}

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
		PolicyMode:                "audit",
		AccessLog:                 "json",
		ReportPolicyViolations:    true,
		ReportAccessSummary:       true,
		ReportRequestSummary:      true,
		hasReportPolicyViolations: true,
		hasReportAccessSummary:    true,
		hasReportRequestSummary:   true,
	}
}

func mergeCLIConfig(defaults cliFileConfig, fileCfg cliFileConfig, flags cliFlagOverrides, audit bool) cliFileConfig {
	merged := defaults
	merged = mergeCLIConfigLayer(merged, fileCfg)

	if flags.TrafficMode != nil {
		merged.TrafficMode = *flags.TrafficMode
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
	}

	if audit {
		merged.PolicyMode = "audit"
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
	if overlay.Name != "" {
		base.Name = overlay.Name
	}
	if overlay.WorkDir != "" {
		base.WorkDir = overlay.WorkDir
	}
	if len(overlay.Bin) > 0 {
		base.Bin = append([]string(nil), overlay.Bin...)
	}
	if len(overlay.MountRO) > 0 {
		base.MountRO = append([]string(nil), overlay.MountRO...)
	}
	if len(overlay.MountRW) > 0 {
		base.MountRW = append([]string(nil), overlay.MountRW...)
	}
	if len(overlay.Env) > 0 {
		base.Env = append([]string(nil), overlay.Env...)
	}
	if overlay.ClearEnv {
		base.ClearEnv = true
	}
	if overlay.TrafficMode != "" {
		base.TrafficMode = overlay.TrafficMode
	}
	if overlay.MaxRequestBodyBytes != 0 {
		base.MaxRequestBodyBytes = overlay.MaxRequestBodyBytes
	}
	if overlay.AccessLog != "" {
		base.AccessLog = overlay.AccessLog
	}
	if overlay.PolicyMode != "" {
		base.PolicyMode = overlay.PolicyMode
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
	if len(overlay.Policy.AllowHostPatterns) > 0 {
		base.Policy.AllowHostPatterns = append([]string(nil), overlay.Policy.AllowHostPatterns...)
	}
	if len(overlay.Policy.DenyHostPatterns) > 0 {
		base.Policy.DenyHostPatterns = append([]string(nil), overlay.Policy.DenyHostPatterns...)
	}
	if len(overlay.Policy.AllowIPCIDRs) > 0 {
		base.Policy.AllowIPCIDRs = append([]string(nil), overlay.Policy.AllowIPCIDRs...)
	}
	if len(overlay.Policy.DenyIPCIDRs) > 0 {
		base.Policy.DenyIPCIDRs = append([]string(nil), overlay.Policy.DenyIPCIDRs...)
	}
	if len(overlay.Policy.AllowHTTPMethods) > 0 {
		base.Policy.AllowHTTPMethods = append([]string(nil), overlay.Policy.AllowHTTPMethods...)
	}
	if overlay.Policy.AllowConnect {
		base.Policy.AllowConnect = true
	}
	if len(overlay.Policy.AllowConnectPorts) > 0 {
		base.Policy.AllowConnectPorts = append([]string(nil), overlay.Policy.AllowConnectPorts...)
	}
	if len(overlay.Policy.AllowPathPatterns) > 0 {
		base.Policy.AllowPathPatterns = append([]string(nil), overlay.Policy.AllowPathPatterns...)
	}
	if len(overlay.Policy.DenyPathPatterns) > 0 {
		base.Policy.DenyPathPatterns = append([]string(nil), overlay.Policy.DenyPathPatterns...)
	}
	if len(overlay.Policy.AllowHeaderPatterns) > 0 {
		base.Policy.AllowHeaderPatterns = cloneStringSliceMap(overlay.Policy.AllowHeaderPatterns)
	}
	if len(overlay.Policy.DenyHeaderPatterns) > 0 {
		base.Policy.DenyHeaderPatterns = cloneStringSliceMap(overlay.Policy.DenyHeaderPatterns)
	}
	if len(overlay.Policy.AllowBodyPatterns) > 0 {
		base.Policy.AllowBodyPatterns = append([]string(nil), overlay.Policy.AllowBodyPatterns...)
	}
	if len(overlay.Policy.DenyBodyPatterns) > 0 {
		base.Policy.DenyBodyPatterns = append([]string(nil), overlay.Policy.DenyBodyPatterns...)
	}
	return base
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
