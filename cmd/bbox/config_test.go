package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestFindConfigFileUsesCurrentDirectoryFirst(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}

	parentConfig := filepath.Join(root, "bbox.yaml")
	if err := os.WriteFile(parentConfig, []byte("name: parent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	currentConfig := filepath.Join(child, "bbox.yaml")
	if err := os.WriteFile(currentConfig, []byte("name: child\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findConfigFile(child)
	if err != nil {
		t.Fatal(err)
	}
	if got != currentConfig {
		t.Fatalf("got %q want %q", got, currentConfig)
	}
}

func TestFindConfigFileWalksUpParentDirectories(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(root, "bbox.yaml")
	if err := os.WriteFile(want, []byte("name: root\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findConfigFile(deep)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFindConfigFileReturnsEmptyWhenMissing(t *testing.T) {
	start := filepath.Join(t.TempDir(), "nested", "dir")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findConfigFile(start)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

func TestLoadCLIFileConfigDecodesStructuredMounts(t *testing.T) {
	path := fixturePath(t, "flat_config.yaml")
	got, err := loadCLIFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if got.Name != "from-file" {
		t.Fatalf("got name %q", got.Name)
	}
	if got.WorkDir != "/workspace" {
		t.Fatalf("got workdir %q", got.WorkDir)
	}
	if !reflect.DeepEqual(got.Bin, []string{"bash", "curl"}) {
		t.Fatalf("got bin %v", got.Bin)
	}
	wantMounts := []cliMountConfig{
		{
			Type:     "bind",
			Source:   "/etc/ssl/certs",
			Target:   "/etc/ssl/certs",
			ReadOnly: true,
		},
		{
			Type:   "bind",
			Source: "/host/cache",
			Target: "/cache",
		},
	}
	if !reflect.DeepEqual(got.Mounts, wantMounts) {
		t.Fatalf("got mounts %v want %v", got.Mounts, wantMounts)
	}
	if !reflect.DeepEqual(got.Env, []string{"FOO=bar"}) {
		t.Fatalf("got env %v", got.Env)
	}
	if !got.ClearEnv {
		t.Fatal("expected clear_env=true")
	}
	if got.TrafficMode != "transparent" {
		t.Fatalf("got traffic_mode %q", got.TrafficMode)
	}
	if got.MaxRequestBodyBytes != 12345 {
		t.Fatalf("got max_request_body_bytes %d", got.MaxRequestBodyBytes)
	}
	if got.AccessLog != "off" {
		t.Fatalf("got access_log %q", got.AccessLog)
	}
	if !got.ReportPolicyViolations || !got.ReportAccessSummary || got.ReportRequestSummary {
		t.Fatalf("unexpected reporting flags: %#v", got)
	}
	if len(got.Policy.Rules) != 1 {
		t.Fatalf("expected one policy rule, got %#v", got.Policy.Rules)
	}
	if !reflect.DeepEqual(got.Policy.Rules[0].HostPatterns, []string{"^api[.]example[.]com$"}) {
		t.Fatalf("got policy host_patterns %v", got.Policy.Rules[0].HostPatterns)
	}
	if !reflect.DeepEqual(got.Policy.Rules[0].HTTPMethods, []string{"post"}) {
		t.Fatalf("got policy http_methods %v", got.Policy.Rules[0].HTTPMethods)
	}
}

func TestLoadCLIFileConfigDecodesDockerSocketPolicy(t *testing.T) {
	path := fixturePath(t, "docker_socket.yaml")
	got, err := loadCLIFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if !got.DockerSocket.Enabled {
		t.Fatal("expected docker_socket.enabled=true")
	}
	if got.DockerSocket.MountPath != "/var/run/docker.sock" {
		t.Fatalf("got docker_socket.mount_path %q", got.DockerSocket.MountPath)
	}
	if got.DockerSocket.TargetSocketPath != "/run/user/1000/docker.sock" {
		t.Fatalf("got docker_socket.target_socket_path %q", got.DockerSocket.TargetSocketPath)
	}
	if got.DockerSocket.DefaultAction != "deny" {
		t.Fatalf("got docker_socket.default_action %q", got.DockerSocket.DefaultAction)
	}
	if len(got.DockerSocket.Rules) != 2 {
		t.Fatalf("expected 2 docker socket rules, got %#v", got.DockerSocket.Rules)
	}
	if !reflect.DeepEqual(got.DockerSocket.Rules[0].Operations, []string{"image_pull", "build"}) {
		t.Fatalf("got docker_socket.operations %v", got.DockerSocket.Rules[0].Operations)
	}
	if got.DockerSocket.Rules[1].Action != "deny" {
		t.Fatalf("got docker_socket rule action %q", got.DockerSocket.Rules[1].Action)
	}
}

func TestLoadCLIFileConfigDecodesDockerBuild(t *testing.T) {
	path := fixturePath(t, "docker_build.yaml")
	configDir := filepath.Dir(path)
	got, err := loadCLIFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if !got.DockerBuild.Enabled {
		t.Fatal("expected docker_build.enabled=true")
	}
	if got.DockerBuild.BuildkitdPath != filepath.Join(configDir, "bin/buildkitd") {
		t.Fatalf("got docker_build.buildkitd_path %q", got.DockerBuild.BuildkitdPath)
	}
	if got.DockerBuild.BuildctlPath != filepath.Join(configDir, "bin/buildctl") {
		t.Fatalf("got docker_build.buildctl_path %q", got.DockerBuild.BuildctlPath)
	}
	if got.DockerBuild.RuncPath != "/usr/bin/runc" {
		t.Fatalf("got docker_build.runc_path %q", got.DockerBuild.RuncPath)
	}
	if got.DockerBuild.PodmanPath != "/usr/bin/podman" {
		t.Fatalf("got docker_build.podman_path %q", got.DockerBuild.PodmanPath)
	}
	if got.DockerBuild.NewuidmapPath != "/usr/bin/newuidmap" {
		t.Fatalf("got docker_build.newuidmap_path %q", got.DockerBuild.NewuidmapPath)
	}
	if got.DockerBuild.NewgidmapPath != "/usr/bin/newgidmap" {
		t.Fatalf("got docker_build.newgidmap_path %q", got.DockerBuild.NewgidmapPath)
	}
}

func TestLoadCLIFileConfigResolvesRelativePathsInStructuredMounts(t *testing.T) {
	path := fixturePath(t, "relative_paths.yaml")
	configDir := filepath.Dir(path)
	got, err := loadCLIFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	wantWorkDir := filepath.Join(configDir, "workspace")
	if got.WorkDir != wantWorkDir {
		t.Fatalf("got workdir %q want %q", got.WorkDir, wantWorkDir)
	}

	wantMounts := []cliMountConfig{
		{
			Type:     "bind",
			Source:   filepath.Join(configDir, "certs"),
			Target:   "/etc/ssl/certs",
			ReadOnly: true,
		},
		{
			Type:   "bind",
			Source: filepath.Join(configDir, "..", "shared"),
			Target: filepath.Join(configDir, "sandbox", "shared"),
		},
		{
			Type:   "bind",
			Source: "/var/tmp",
			Target: "/abs-target",
		},
	}
	if !reflect.DeepEqual(got.Mounts, wantMounts) {
		t.Fatalf("got mounts %v want %v", got.Mounts, wantMounts)
	}
}

func TestLoadCLIFileConfigRejectsUnknownKeys(t *testing.T) {
	path := fixturePath(t, "unknown_key.yaml")
	_, err := loadCLIFileConfig(path)
	if err == nil {
		t.Fatal("expected unknown key to fail")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("expected path-qualified error, got %v", err)
	}
	if !(strings.Contains(err.Error(), "decode config file") && strings.Contains(err.Error(), "unknown")) {
		t.Fatalf("expected unknown-field decode error, got %v", err)
	}
}

func TestLoadCLIFileConfigRejectsRemovedMountKeys(t *testing.T) {
	path := fixturePath(t, "removed_mount_keys.yaml")
	_, err := loadCLIFileConfig(path)
	if err == nil {
		t.Fatal("expected removed mount keys to fail")
	}
	if !strings.Contains(err.Error(), "field mount_ro not found") && !strings.Contains(err.Error(), "field mount_rw not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
	if !strings.Contains(err.Error(), "mount_ro") && !strings.Contains(err.Error(), "mount_rw") {
		t.Fatalf("expected error to reference removed key, got %v", err)
	}
}

func TestLoadCLIFileConfigAcceptsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bbox.yaml")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadCLIFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cliFileConfig{}) {
		t.Fatalf("expected empty config, got %#v", got)
	}
}

func TestLoadEffectiveCLIConfigUsesExplicitConfigPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bbox.yaml"), []byte("traffic_mode: proxy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(root, "configs")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	explicitPath := filepath.Join(configDir, "explicit.yaml")
	if err := os.WriteFile(explicitPath, []byte("traffic_mode: transparent\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadEffectiveCLIConfig(cliOptions{configPath: filepath.Join("configs", "explicit.yaml")}, root)
	if err != nil {
		t.Fatal(err)
	}
	if got.TrafficMode != "transparent" {
		t.Fatalf("got traffic_mode %q want %q", got.TrafficMode, "transparent")
	}
}

func TestLoadEffectiveCLIConfigExplicitPathErrorsWhenMissing(t *testing.T) {
	root := t.TempDir()

	_, err := loadEffectiveCLIConfig(cliOptions{configPath: "missing.yaml"}, root)
	if err == nil {
		t.Fatal("expected missing explicit config to fail")
	}
	if !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("expected missing path in error, got %v", err)
	}
}

func TestLoadEffectiveCLIConfigExplicitPathErrorsForDirectory(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "configs")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := loadEffectiveCLIConfig(cliOptions{configPath: "configs"}, root)
	if err == nil {
		t.Fatal("expected directory explicit config to fail")
	}
	if !strings.Contains(err.Error(), "configs") {
		t.Fatalf("expected directory path in error, got %v", err)
	}
}

func TestMergeCLIConfigPrecedenceDefaultsFileFlagsAudit(t *testing.T) {
	defaults := defaultCLIFileConfig()
	fileCfg := cliFileConfig{
		TrafficMode:            "transparent",
		ReportPolicyViolations: false,
		ReportAccessSummary:    false,
		ReportRequestSummary:   false,
		AccessLog:              "off",
		MaxRequestBodyBytes:    999,
		Policy: cliPolicyConfig{
			Rules: []cliPolicyRuleConfig{
				{HostPatterns: []string{"^file[.]example[.]com$"}},
			},
		},
		hasTrafficMode:            true,
		hasAccessLog:              true,
		hasMaxRequestBodyBytes:    true,
		hasReportPolicyViolations: true,
		hasReportAccessSummary:    true,
		hasReportRequestSummary:   true,
	}
	fileCfg.Policy.hasRules = true
	flags := cliFlagOverrides{
		TrafficMode:         stringPtr("proxy"),
		ReportAccessSummary: boolPtr(false),
		AccessLog:           stringPtr("json"),
	}

	got := mergeCLIConfig(defaults, fileCfg, flags, true)

	if got.TrafficMode != "proxy" {
		t.Fatalf("got traffic_mode %q", got.TrafficMode)
	}
	if !got.ReportPolicyViolations || !got.ReportAccessSummary || !got.ReportRequestSummary {
		t.Fatalf("expected audit reporting enabled, got %#v", got)
	}
	if got.AccessLog != "json" {
		t.Fatalf("got access_log %q", got.AccessLog)
	}
	if got.MaxRequestBodyBytes != 999 {
		t.Fatalf("got max_request_body_bytes %d", got.MaxRequestBodyBytes)
	}
	if !reflect.DeepEqual(got.Policy.Rules, []cliPolicyRuleConfig{{HostPatterns: []string{"^file[.]example[.]com$"}}}) {
		t.Fatalf("got policy rules %v", got.Policy.Rules)
	}
}

func TestMergeCLIConfigLayerSupportsExplicitFalseZeroAndEmptyOverrides(t *testing.T) {
	base := cliFileConfig{
		ClearEnv:               true,
		MaxRequestBodyBytes:    123,
		Bin:                    []string{"bash"},
		hasClearEnv:            true,
		hasMaxRequestBodyBytes: true,
		hasBin:                 true,
		Policy: cliPolicyConfig{
			Rules: []cliPolicyRuleConfig{
				{
					HostPatterns:   []string{"^example[.]com$"},
					ConnectPorts:   []string{"443"},
					HeaderPatterns: map[string][]string{"x-test": {"one"}},
				},
			},
			hasRules: true,
		},
	}

	overlay := cliFileConfig{
		ClearEnv:               false,
		MaxRequestBodyBytes:    0,
		Bin:                    []string{},
		hasClearEnv:            true,
		hasMaxRequestBodyBytes: true,
		hasBin:                 true,
		Policy: cliPolicyConfig{
			Rules:    []cliPolicyRuleConfig{},
			hasRules: true,
		},
	}

	got := mergeCLIConfigLayer(base, overlay)
	if got.ClearEnv {
		t.Fatal("expected clear_env override to false")
	}
	if got.MaxRequestBodyBytes != 0 {
		t.Fatalf("got max_request_body_bytes %d want 0", got.MaxRequestBodyBytes)
	}
	if len(got.Bin) != 0 {
		t.Fatalf("expected bin to be cleared, got %v", got.Bin)
	}
	if len(got.Policy.Rules) != 0 {
		t.Fatalf("expected policy rules to be cleared, got %v", got.Policy.Rules)
	}
}

func TestMergeCLIConfigPreservesDockerSocketPolicy(t *testing.T) {
	base := cliFileConfig{
		DockerSocket: cliDockerSocketConfig{
			Enabled:       true,
			DefaultAction: "deny",
			Rules: []cliDockerSocketRuleConfig{
				{Action: "allow", Operations: []string{"image_pull"}},
			},
			hasEnabled:       true,
			hasDefaultAction: true,
			hasRules:         true,
		},
	}

	overlay := cliFileConfig{
		DockerSocket: cliDockerSocketConfig{
			MountPath: "/tmp/docker.sock",
			Rules: []cliDockerSocketRuleConfig{
				{Action: "deny", Operations: []string{"image_push"}},
			},
			hasMountPath: true,
			hasRules:     true,
		},
	}

	got := mergeCLIConfigLayer(base, overlay)
	if !got.DockerSocket.Enabled {
		t.Fatal("expected docker socket enabled flag to be preserved")
	}
	if got.DockerSocket.MountPath != "/tmp/docker.sock" {
		t.Fatalf("got docker_socket.mount_path %q", got.DockerSocket.MountPath)
	}
	if got.DockerSocket.DefaultAction != "deny" {
		t.Fatalf("got docker_socket.default_action %q", got.DockerSocket.DefaultAction)
	}
	if !reflect.DeepEqual(got.DockerSocket.Rules, []cliDockerSocketRuleConfig{
		{Action: "deny", Operations: []string{"image_push"}},
	}) {
		t.Fatalf("got docker socket rules %#v", got.DockerSocket.Rules)
	}
}

func TestMergeCLIConfigPreservesDockerBuildConfig(t *testing.T) {
	base := cliFileConfig{
		DockerBuild: cliDockerBuildConfig{
			Enabled:       true,
			BuildkitdPath: "/base/buildkitd",
			NewuidmapPath: "/base/newuidmap",
			hasEnabled:    true,
			hasBuildkitd:  true,
			hasNewuidmap:  true,
		},
	}

	overlay := cliFileConfig{
		DockerBuild: cliDockerBuildConfig{
			BuildctlPath: "/overlay/buildctl",
			hasBuildctl:  true,
		},
	}

	got := mergeCLIConfigLayer(base, overlay)
	if !got.DockerBuild.Enabled {
		t.Fatal("expected docker_build.enabled to be preserved")
	}
	if got.DockerBuild.BuildkitdPath != "/base/buildkitd" {
		t.Fatalf("got docker_build.buildkitd_path %q", got.DockerBuild.BuildkitdPath)
	}
	if got.DockerBuild.BuildctlPath != "/overlay/buildctl" {
		t.Fatalf("got docker_build.buildctl_path %q", got.DockerBuild.BuildctlPath)
	}
	if got.DockerBuild.NewuidmapPath != "/base/newuidmap" {
		t.Fatalf("got docker_build.newuidmap_path %q", got.DockerBuild.NewuidmapPath)
	}
}

func TestMergeCLIConfigLeavesPathNormalizationToBuildConfig(t *testing.T) {
	defaults := defaultCLIFileConfig()
	fileCfg := cliFileConfig{
		WorkDir:    "./workspace",
		hasWorkDir: true,
	}

	got := mergeCLIConfig(defaults, fileCfg, cliFlagOverrides{}, false)
	if got.WorkDir != "./workspace" {
		t.Fatalf("got workdir %q want %q", got.WorkDir, "./workspace")
	}
}

func TestToEffectiveCLIConfigNormalizesWorkDirAndReporting(t *testing.T) {
	cwd := t.TempDir()
	merged := cliFileConfig{
		WorkDir:                "./workspace",
		TrafficMode:            "proxy",
		AccessLog:              "off",
		ReportPolicyViolations: true,
		ReportAccessSummary:    false,
		ReportRequestSummary:   true,
	}

	got := toEffectiveCLIConfig(merged, cwd)
	if got.WorkDir != filepath.Join(cwd, "workspace") {
		t.Fatalf("got workdir %q", got.WorkDir)
	}
	if got.TrafficMode != "proxy" {
		t.Fatalf("got traffic_mode %q", got.TrafficMode)
	}
	if got.AccessLog != "off" {
		t.Fatalf("got access_log %q", got.AccessLog)
	}
	if !got.Reporting.PolicyViolations || got.Reporting.AccessSummary || !got.Reporting.RequestSummary {
		t.Fatalf("unexpected reporting %#v", got.Reporting)
	}
}

func stringPtr(v string) *string { return &v }

func boolPtr(v bool) *bool { return &v }

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "testdata", name)
}
