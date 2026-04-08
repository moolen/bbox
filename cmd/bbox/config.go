package main

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
	PolicyMode                string                `yaml:"policy_mode"`
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
	hasPolicyMode             bool                  `yaml:"-"`
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
	PolicyMode             *string                   `yaml:"policy_mode"`
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
	PolicyMode           *string
	ReportPolicy         *bool
	ReportAccessSummary  *bool
	ReportRequestSummary *bool
	AccessLog            *string
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
