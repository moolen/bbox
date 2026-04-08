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
	if raw.Mounts != nil {
		cfg.Mounts = cloneMountConfigs(*raw.Mounts)
		cfg.hasMounts = true
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
	if raw.PolicyMode != nil {
		cfg.PolicyMode = *raw.PolicyMode
		cfg.hasPolicyMode = true
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
	if cfg.hasMounts {
		resolved := make([]cliMountConfig, 0, len(cfg.Mounts))
		for _, mount := range cfg.Mounts {
			resolved = append(resolved, resolveConfigMount(mount, configDir))
		}
		cfg.Mounts = resolved
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
