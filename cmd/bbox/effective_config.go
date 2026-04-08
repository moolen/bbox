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
	Mounts              []cliMountConfig
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

	fileCfg, err := loadSelectedCLIFileConfig(opts.configPath, absCWD)
	if err != nil {
		return effectiveCLIConfig{}, err
	}

	mergedCfg := mergeCLIConfig(defaults, fileCfg, opts.flagOverrides, opts.audit)
	runtimeLayer, err := buildRuntimeCLIConfigLayer(opts)
	if err != nil {
		return effectiveCLIConfig{}, err
	}
	mergedCfg = mergeCLIConfigLayer(mergedCfg, runtimeLayer)

	return toEffectiveCLIConfig(mergedCfg, absCWD), nil
}

func loadSelectedCLIFileConfig(configPath string, absCWD string) (cliFileConfig, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath != "" {
		resolvedPath, err := absPathFromCWD(configPath, absCWD)
		if err != nil {
			return cliFileConfig{}, fmt.Errorf("resolve config file %q: %w", configPath, err)
		}
		return loadCLIFileConfig(resolvedPath)
	}

	discoveredPath, err := findConfigFile(absCWD)
	if err != nil {
		return cliFileConfig{}, err
	}
	if discoveredPath == "" {
		return cliFileConfig{}, nil
	}
	return loadCLIFileConfig(discoveredPath)
}

func buildRuntimeCLIConfigLayer(opts cliOptions) (cliFileConfig, error) {
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
	if len(opts.mounts) > 0 {
		runtimeLayer.Mounts = make([]cliMountConfig, 0, len(opts.mounts))
		for _, spec := range opts.mounts {
			mount, err := parseCLIMountSpec(spec)
			if err != nil {
				return cliFileConfig{}, err
			}
			runtimeLayer.Mounts = append(runtimeLayer.Mounts, toCLIMountConfig(mount))
		}
		runtimeLayer.hasMounts = true
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
	return runtimeLayer, nil
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
		Mounts:              cloneMountConfigs(mergedCfg.Mounts),
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
