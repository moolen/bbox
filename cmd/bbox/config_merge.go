package main

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
	if overlay.hasMounts {
		base.Mounts = cloneMountConfigs(overlay.Mounts)
		base.hasMounts = true
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
