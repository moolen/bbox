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

func TestLoadCLIFileConfigDecodesFlatYAML(t *testing.T) {
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
	if !reflect.DeepEqual(got.MountRO, []string{"/etc/ssl/certs:/etc/ssl/certs"}) {
		t.Fatalf("got mount_ro %v", got.MountRO)
	}
	if !reflect.DeepEqual(got.MountRW, []string{"/host/cache:/cache"}) {
		t.Fatalf("got mount_rw %v", got.MountRW)
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
	if !reflect.DeepEqual(got.Policy.AllowHostPatterns, []string{"^api[.]example[.]com$"}) {
		t.Fatalf("got policy allow_host_patterns %v", got.Policy.AllowHostPatterns)
	}
	if got.Policy.AllowConnect {
		t.Fatal("expected policy.allow_connect=false")
	}
}

func TestLoadCLIFileConfigResolvesRelativePathsFromConfigDirectory(t *testing.T) {
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

	wantRO := []string{
		filepath.Join(configDir, "certs") + ":/etc/ssl/certs",
	}
	if !reflect.DeepEqual(got.MountRO, wantRO) {
		t.Fatalf("got mount_ro %v want %v", got.MountRO, wantRO)
	}

	wantRW := []string{
		filepath.Join(configDir, "..", "shared") + ":" + filepath.Join(configDir, "sandbox", "shared"),
		"/var/tmp:/abs-target",
	}
	if !reflect.DeepEqual(got.MountRW, wantRW) {
		t.Fatalf("got mount_rw %v want %v", got.MountRW, wantRW)
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
	if !strings.Contains(err.Error(), "field unknown_key not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestMergeCLIConfigPrecedenceDefaultsFileFlagsAudit(t *testing.T) {
	defaults := defaultCLIFileConfig()
	fileCfg := cliFileConfig{
		TrafficMode:               "transparent",
		ReportPolicyViolations:    false,
		ReportAccessSummary:       false,
		ReportRequestSummary:      false,
		AccessLog:                 "off",
		MaxRequestBodyBytes:       999,
		Policy:                    cliPolicyConfig{AllowHostPatterns: []string{"^file[.]example[.]com$"}},
		hasTrafficMode:            true,
		hasAccessLog:              true,
		hasMaxRequestBodyBytes:    true,
		hasReportPolicyViolations: true,
		hasReportAccessSummary:    true,
		hasReportRequestSummary:   true,
	}
	fileCfg.Policy.hasAllowHostPatterns = true
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
	if !reflect.DeepEqual(got.Policy.AllowHostPatterns, []string{"^file[.]example[.]com$"}) {
		t.Fatalf("got policy allow_host_patterns %v", got.Policy.AllowHostPatterns)
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
			AllowConnect:         true,
			AllowHostPatterns:    []string{"^example[.]com$"},
			AllowHeaderPatterns:  map[string][]string{"x-test": []string{"one"}},
			hasAllowConnect:      true,
			hasAllowHostPatterns: true,
			hasAllowHeaders:      true,
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
			AllowConnect:         false,
			AllowHostPatterns:    []string{},
			AllowHeaderPatterns:  map[string][]string{},
			hasAllowConnect:      true,
			hasAllowHostPatterns: true,
			hasAllowHeaders:      true,
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
	if got.Policy.AllowConnect {
		t.Fatal("expected policy.allow_connect override to false")
	}
	if len(got.Policy.AllowHostPatterns) != 0 {
		t.Fatalf("expected allow_host_patterns to be cleared, got %v", got.Policy.AllowHostPatterns)
	}
	if len(got.Policy.AllowHeaderPatterns) != 0 {
		t.Fatalf("expected allow_header_patterns to be cleared, got %v", got.Policy.AllowHeaderPatterns)
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
