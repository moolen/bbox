package main

import (
	"os"
	"path/filepath"
	"reflect"
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
	dir := t.TempDir()
	path := filepath.Join(dir, "bbox.yaml")
	content := `
name: from-file
workdir: /workspace
bin: [bash, curl]
mount_ro:
  - /etc/ssl/certs:/etc/ssl/certs
mount_rw:
  - /host/cache:/cache
env:
  - FOO=bar
clear_env: true
traffic_mode: transparent
max_request_body_bytes: 12345
access_log: off
report_policy_violations: true
report_access_summary: true
report_request_summary: false
policy:
  allow_host_patterns:
    - "^api[.]example[.]com$"
  allow_connect: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

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
	root := t.TempDir()
	configDir := filepath.Join(root, "configs", "dev")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(configDir, "bbox.yaml")
	content := `
workdir: ./workspace
mount_ro:
  - ./certs:/etc/ssl/certs
mount_rw:
  - ../shared:./sandbox/shared
  - /var/tmp:/abs-target
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

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

func TestMergeCLIConfigPrecedenceDefaultsFileFlagsAudit(t *testing.T) {
	defaults := defaultCLIFileConfig()
	fileCfg := cliFileConfig{
		TrafficMode:            "transparent",
		ReportPolicyViolations: false,
		ReportAccessSummary:    false,
		ReportRequestSummary:   false,
		PolicyMode:             "enforce",
		AccessLog:              "off",
		MaxRequestBodyBytes:    999,
		Policy:                 cliPolicyConfig{AllowHostPatterns: []string{"^file[.]example[.]com$"}},
	}
	flags := cliFlagOverrides{
		TrafficMode:         stringPtr("proxy"),
		ReportAccessSummary: boolPtr(false),
		AccessLog:           stringPtr("json"),
	}

	got := mergeCLIConfig(defaults, fileCfg, flags, true)

	if got.TrafficMode != "proxy" {
		t.Fatalf("got traffic_mode %q", got.TrafficMode)
	}
	if got.PolicyMode != "audit" {
		t.Fatalf("got policy_mode %q", got.PolicyMode)
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

func stringPtr(v string) *string { return &v }

func boolPtr(v bool) *bool { return &v }
