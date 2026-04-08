package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moolen/bbox"
)

type effectiveCLIConfig struct {
	Name                string
	WorkDir             string
	Binaries            []string
	MountsRO            []string
	MountsRW            []string
	Env                 []string
	ClearEnv            bool
	TrafficMode         string
	MaxRequestBodyBytes int64
	Policy              cliPolicyConfig
	Reporting           bbox.ReportingOptions
	AccessLog           string
	DockerBuild         cliDockerBuildConfig
	DockerSocket        cliDockerSocketConfig
}

func buildConfig(opts cliOptions, payload []string, cwd string, environ []string) (runConfig, error) {
	if len(payload) == 0 {
		return runConfig{}, fmt.Errorf("payload command required after --")
	}

	absCWD, err := filepath.Abs(cwd)
	if err != nil {
		return runConfig{}, fmt.Errorf("resolve current working directory: %w", err)
	}

	effectiveCfg, err := loadEffectiveCLIConfig(opts, absCWD)
	if err != nil {
		return runConfig{}, err
	}
	cfg, err := buildRunConfig(effectiveCfg, payload, absCWD, environ)
	if err != nil {
		return runConfig{}, err
	}
	cfg.printPolicy = opts.printPolicy
	return cfg, nil
}

func loadEffectiveCLIConfig(opts cliOptions, absCWD string) (effectiveCLIConfig, error) {
	defaults := defaultCLIFileConfig()
	defaults.MaxRequestBodyBytes = 64 << 10
	defaults.hasMaxRequestBodyBytes = true

	var fileCfg cliFileConfig
	configPath, err := findConfigFile(absCWD)
	if err != nil {
		return effectiveCLIConfig{}, err
	}
	if configPath != "" {
		loaded, err := loadCLIFileConfig(configPath)
		if err != nil {
			return effectiveCLIConfig{}, err
		}
		fileCfg = loaded
	}

	mergedCfg := mergeCLIConfig(defaults, fileCfg, opts.flagOverrides, opts.audit)
	mergedCfg = mergeCLIConfigLayer(mergedCfg, buildRuntimeCLIConfigLayer(opts))

	return toEffectiveCLIConfig(mergedCfg, absCWD), nil
}

func buildRuntimeCLIConfigLayer(opts cliOptions) cliFileConfig {
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
	if opts.clearEnvSet {
		runtimeLayer.ClearEnv = opts.clearEnv
		runtimeLayer.hasClearEnv = true
	}
	if opts.maxBodySizeSet {
		runtimeLayer.MaxRequestBodyBytes = opts.maxRequestBodyBytes
		runtimeLayer.hasMaxRequestBodyBytes = true
	}
	return runtimeLayer
}

func toEffectiveCLIConfig(mergedCfg cliFileConfig, absCWD string) effectiveCLIConfig {
	workDir := strings.TrimSpace(mergedCfg.WorkDir)
	if workDir == "" {
		workDir = absCWD
	} else if !filepath.IsAbs(workDir) {
		workDir = filepath.Join(absCWD, workDir)
	}

	return effectiveCLIConfig{
		Name:                mergedCfg.Name,
		WorkDir:             workDir,
		Binaries:            cloneStringSlice(mergedCfg.Bin),
		MountsRO:            cloneStringSlice(mergedCfg.MountRO),
		MountsRW:            cloneStringSlice(mergedCfg.MountRW),
		Env:                 cloneStringSlice(mergedCfg.Env),
		ClearEnv:            mergedCfg.ClearEnv,
		TrafficMode:         mergedCfg.TrafficMode,
		MaxRequestBodyBytes: mergedCfg.MaxRequestBodyBytes,
		Policy:              mergedCfg.Policy,
		Reporting: bbox.ReportingOptions{
			PolicyViolations: mergedCfg.ReportPolicyViolations,
			AccessSummary:    mergedCfg.ReportAccessSummary,
			RequestSummary:   mergedCfg.ReportRequestSummary,
		},
		AccessLog:    mergedCfg.AccessLog,
		DockerBuild:  mergedCfg.DockerBuild,
		DockerSocket: mergedCfg.DockerSocket,
	}
}
