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

type cliPolicyConfig struct {
	AllowHostPatterns    []string            `yaml:"allow_host_patterns"`
	DenyHostPatterns     []string            `yaml:"deny_host_patterns"`
	AllowIPCIDRs         []string            `yaml:"allow_ip_cidrs"`
	DenyIPCIDRs          []string            `yaml:"deny_ip_cidrs"`
	AllowHTTPMethods     []string            `yaml:"allow_http_methods"`
	AllowConnect         bool                `yaml:"allow_connect"`
	AllowConnectPorts    []string            `yaml:"allow_connect_ports"`
	AllowPathPatterns    []string            `yaml:"allow_path_patterns"`
	DenyPathPatterns     []string            `yaml:"deny_path_patterns"`
	AllowHeaderPatterns  map[string][]string `yaml:"allow_header_patterns"`
	DenyHeaderPatterns   map[string][]string `yaml:"deny_header_patterns"`
	AllowBodyPatterns    []string            `yaml:"allow_body_patterns"`
	DenyBodyPatterns     []string            `yaml:"deny_body_patterns"`
	hasAllowHostPatterns bool                `yaml:"-"`
	hasDenyHostPatterns  bool                `yaml:"-"`
	hasAllowIPCIDRs      bool                `yaml:"-"`
	hasDenyIPCIDRs       bool                `yaml:"-"`
	hasAllowHTTPMethods  bool                `yaml:"-"`
	hasAllowConnect      bool                `yaml:"-"`
	hasAllowConnectPorts bool                `yaml:"-"`
	hasAllowPathPatterns bool                `yaml:"-"`
	hasDenyPathPatterns  bool                `yaml:"-"`
	hasAllowHeaders      bool                `yaml:"-"`
	hasDenyHeaders       bool                `yaml:"-"`
	hasAllowBodyPatterns bool                `yaml:"-"`
	hasDenyBodyPatterns  bool                `yaml:"-"`
}

type cliFileConfig struct {
	Name                      string          `yaml:"name"`
	WorkDir                   string          `yaml:"workdir"`
	Bin                       []string        `yaml:"bin"`
	MountRO                   []string        `yaml:"mount_ro"`
	MountRW                   []string        `yaml:"mount_rw"`
	Env                       []string        `yaml:"env"`
	ClearEnv                  bool            `yaml:"clear_env"`
	TrafficMode               string          `yaml:"traffic_mode"`
	MaxRequestBodyBytes       int64           `yaml:"max_request_body_bytes"`
	AccessLog                 string          `yaml:"access_log"`
	ReportPolicyViolations    bool            `yaml:"report_policy_violations"`
	ReportAccessSummary       bool            `yaml:"report_access_summary"`
	ReportRequestSummary      bool            `yaml:"report_request_summary"`
	Policy                    cliPolicyConfig `yaml:"policy"`
	hasName                   bool            `yaml:"-"`
	hasWorkDir                bool            `yaml:"-"`
	hasBin                    bool            `yaml:"-"`
	hasMountRO                bool            `yaml:"-"`
	hasMountRW                bool            `yaml:"-"`
	hasEnv                    bool            `yaml:"-"`
	hasClearEnv               bool            `yaml:"-"`
	hasTrafficMode            bool            `yaml:"-"`
	hasMaxRequestBodyBytes    bool            `yaml:"-"`
	hasAccessLog              bool            `yaml:"-"`
	hasReportPolicyViolations bool            `yaml:"-"`
	hasReportAccessSummary    bool            `yaml:"-"`
	hasReportRequestSummary   bool            `yaml:"-"`
}

type rawCLIPolicyConfig struct {
	AllowHostPatterns   *[]string            `yaml:"allow_host_patterns"`
	DenyHostPatterns    *[]string            `yaml:"deny_host_patterns"`
	AllowIPCIDRs        *[]string            `yaml:"allow_ip_cidrs"`
	DenyIPCIDRs         *[]string            `yaml:"deny_ip_cidrs"`
	AllowHTTPMethods    *[]string            `yaml:"allow_http_methods"`
	AllowConnect        *bool                `yaml:"allow_connect"`
	AllowConnectPorts   *[]string            `yaml:"allow_connect_ports"`
	AllowPathPatterns   *[]string            `yaml:"allow_path_patterns"`
	DenyPathPatterns    *[]string            `yaml:"deny_path_patterns"`
	AllowHeaderPatterns *map[string][]string `yaml:"allow_header_patterns"`
	DenyHeaderPatterns  *map[string][]string `yaml:"deny_header_patterns"`
	AllowBodyPatterns   *[]string            `yaml:"allow_body_patterns"`
	DenyBodyPatterns    *[]string            `yaml:"deny_body_patterns"`
}

type rawCLIFileConfig struct {
	Name                   *string             `yaml:"name"`
	WorkDir                *string             `yaml:"workdir"`
	Bin                    *[]string           `yaml:"bin"`
	MountRO                *[]string           `yaml:"mount_ro"`
	MountRW                *[]string           `yaml:"mount_rw"`
	Env                    *[]string           `yaml:"env"`
	ClearEnv               *bool               `yaml:"clear_env"`
	TrafficMode            *string             `yaml:"traffic_mode"`
	MaxRequestBodyBytes    *int64              `yaml:"max_request_body_bytes"`
	AccessLog              *string             `yaml:"access_log"`
	ReportPolicyViolations *bool               `yaml:"report_policy_violations"`
	ReportAccessSummary    *bool               `yaml:"report_access_summary"`
	ReportRequestSummary   *bool               `yaml:"report_request_summary"`
	Policy                 *rawCLIPolicyConfig `yaml:"policy"`
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
	if raw.Policy != nil {
		if raw.Policy.AllowHostPatterns != nil {
			cfg.Policy.AllowHostPatterns = cloneStringSlice(*raw.Policy.AllowHostPatterns)
			cfg.Policy.hasAllowHostPatterns = true
		}
		if raw.Policy.DenyHostPatterns != nil {
			cfg.Policy.DenyHostPatterns = cloneStringSlice(*raw.Policy.DenyHostPatterns)
			cfg.Policy.hasDenyHostPatterns = true
		}
		if raw.Policy.AllowIPCIDRs != nil {
			cfg.Policy.AllowIPCIDRs = cloneStringSlice(*raw.Policy.AllowIPCIDRs)
			cfg.Policy.hasAllowIPCIDRs = true
		}
		if raw.Policy.DenyIPCIDRs != nil {
			cfg.Policy.DenyIPCIDRs = cloneStringSlice(*raw.Policy.DenyIPCIDRs)
			cfg.Policy.hasDenyIPCIDRs = true
		}
		if raw.Policy.AllowHTTPMethods != nil {
			cfg.Policy.AllowHTTPMethods = cloneStringSlice(*raw.Policy.AllowHTTPMethods)
			cfg.Policy.hasAllowHTTPMethods = true
		}
		if raw.Policy.AllowConnect != nil {
			cfg.Policy.AllowConnect = *raw.Policy.AllowConnect
			cfg.Policy.hasAllowConnect = true
		}
		if raw.Policy.AllowConnectPorts != nil {
			cfg.Policy.AllowConnectPorts = cloneStringSlice(*raw.Policy.AllowConnectPorts)
			cfg.Policy.hasAllowConnectPorts = true
		}
		if raw.Policy.AllowPathPatterns != nil {
			cfg.Policy.AllowPathPatterns = cloneStringSlice(*raw.Policy.AllowPathPatterns)
			cfg.Policy.hasAllowPathPatterns = true
		}
		if raw.Policy.DenyPathPatterns != nil {
			cfg.Policy.DenyPathPatterns = cloneStringSlice(*raw.Policy.DenyPathPatterns)
			cfg.Policy.hasDenyPathPatterns = true
		}
		if raw.Policy.AllowHeaderPatterns != nil {
			cfg.Policy.AllowHeaderPatterns = cloneStringSliceMap(*raw.Policy.AllowHeaderPatterns)
			cfg.Policy.hasAllowHeaders = true
		}
		if raw.Policy.DenyHeaderPatterns != nil {
			cfg.Policy.DenyHeaderPatterns = cloneStringSliceMap(*raw.Policy.DenyHeaderPatterns)
			cfg.Policy.hasDenyHeaders = true
		}
		if raw.Policy.AllowBodyPatterns != nil {
			cfg.Policy.AllowBodyPatterns = cloneStringSlice(*raw.Policy.AllowBodyPatterns)
			cfg.Policy.hasAllowBodyPatterns = true
		}
		if raw.Policy.DenyBodyPatterns != nil {
			cfg.Policy.DenyBodyPatterns = cloneStringSlice(*raw.Policy.DenyBodyPatterns)
			cfg.Policy.hasDenyBodyPatterns = true
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
	if overlay.Policy.hasAllowHostPatterns {
		base.Policy.AllowHostPatterns = cloneStringSlice(overlay.Policy.AllowHostPatterns)
		base.Policy.hasAllowHostPatterns = true
	}
	if overlay.Policy.hasDenyHostPatterns {
		base.Policy.DenyHostPatterns = cloneStringSlice(overlay.Policy.DenyHostPatterns)
		base.Policy.hasDenyHostPatterns = true
	}
	if overlay.Policy.hasAllowIPCIDRs {
		base.Policy.AllowIPCIDRs = cloneStringSlice(overlay.Policy.AllowIPCIDRs)
		base.Policy.hasAllowIPCIDRs = true
	}
	if overlay.Policy.hasDenyIPCIDRs {
		base.Policy.DenyIPCIDRs = cloneStringSlice(overlay.Policy.DenyIPCIDRs)
		base.Policy.hasDenyIPCIDRs = true
	}
	if overlay.Policy.hasAllowHTTPMethods {
		base.Policy.AllowHTTPMethods = cloneStringSlice(overlay.Policy.AllowHTTPMethods)
		base.Policy.hasAllowHTTPMethods = true
	}
	if overlay.Policy.hasAllowConnect {
		base.Policy.AllowConnect = overlay.Policy.AllowConnect
		base.Policy.hasAllowConnect = true
	}
	if overlay.Policy.hasAllowConnectPorts {
		base.Policy.AllowConnectPorts = cloneStringSlice(overlay.Policy.AllowConnectPorts)
		base.Policy.hasAllowConnectPorts = true
	}
	if overlay.Policy.hasAllowPathPatterns {
		base.Policy.AllowPathPatterns = cloneStringSlice(overlay.Policy.AllowPathPatterns)
		base.Policy.hasAllowPathPatterns = true
	}
	if overlay.Policy.hasDenyPathPatterns {
		base.Policy.DenyPathPatterns = cloneStringSlice(overlay.Policy.DenyPathPatterns)
		base.Policy.hasDenyPathPatterns = true
	}
	if overlay.Policy.hasAllowHeaders {
		base.Policy.AllowHeaderPatterns = cloneStringSliceMap(overlay.Policy.AllowHeaderPatterns)
		base.Policy.hasAllowHeaders = true
	}
	if overlay.Policy.hasDenyHeaders {
		base.Policy.DenyHeaderPatterns = cloneStringSliceMap(overlay.Policy.DenyHeaderPatterns)
		base.Policy.hasDenyHeaders = true
	}
	if overlay.Policy.hasAllowBodyPatterns {
		base.Policy.AllowBodyPatterns = cloneStringSlice(overlay.Policy.AllowBodyPatterns)
		base.Policy.hasAllowBodyPatterns = true
	}
	if overlay.Policy.hasDenyBodyPatterns {
		base.Policy.DenyBodyPatterns = cloneStringSlice(overlay.Policy.DenyBodyPatterns)
		base.Policy.hasDenyBodyPatterns = true
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
