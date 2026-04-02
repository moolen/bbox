package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/bbox"
)

func TestReadDomainListFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.txt")
	content := strings.Join([]string{
		"",
		"# comment",
		"example.com",
		"  *.github.com  ",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readDomainListFile(path)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"example.com", "*.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDomainPatternFromEntry(t *testing.T) {
	tests := []struct {
		entry string
		want  string
	}{
		{entry: "example.com", want: `^example[.]com$`},
		{entry: "*.github.com", want: `^([^.]+[.])+github[.]com$`},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got, err := domainPatternFromEntry(tt.entry)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseMountSpec(t *testing.T) {
	got, err := parseMountSpec("/host/path:/sandbox/path", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "/host/path" || got.Target != "/sandbox/path" || got.ReadOnly {
		t.Fatalf("unexpected mount: %#v", got)
	}
}

func TestBuildConfigDefaultsMountsCurrentWorkingDirectory(t *testing.T) {
	cwd := t.TempDir()
	cfg, err := buildConfig(cliOptions{}, []string{"bash", "-lc", "pwd"}, cwd, []string{"HOME=/tmp/home", "FOO=bar"})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.sandbox.WorkDir != cwd {
		t.Fatalf("unexpected workdir: got %q want %q", cfg.sandbox.WorkDir, cwd)
	}
	if len(cfg.sandbox.Mounts) != 1 {
		t.Fatalf("expected exactly one default mount, got %d", len(cfg.sandbox.Mounts))
	}
	if cfg.sandbox.Mounts[0].Source != cwd || cfg.sandbox.Mounts[0].Target != cwd || cfg.sandbox.Mounts[0].ReadOnly {
		t.Fatalf("unexpected default mount: %#v", cfg.sandbox.Mounts[0])
	}
	if len(cfg.argv) == 0 || cfg.argv[0] != "bash" {
		t.Fatalf("unexpected argv: %v", cfg.argv)
	}
	if len(cfg.sandbox.Binaries) == 0 || cfg.sandbox.Binaries[0] != "bash" {
		t.Fatalf("expected payload binary to be staged first, got %v", cfg.sandbox.Binaries)
	}
	if !containsString(cfg.sandbox.Env, "FOO=bar") {
		t.Fatalf("expected inherited env in sandbox env, got %v", cfg.sandbox.Env)
	}
}

func TestRootCommandRejectsMissingPayload(t *testing.T) {
	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		run: func(runConfig) error {
			t.Fatal("did not expect runner to be called")
			return nil
		},
	})
	cmd.SetArgs(nil)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing payload to fail")
	}
	if !strings.Contains(err.Error(), "payload command required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRootCommandAuditFlagPassesAuditReportingToRunner(t *testing.T) {
	var got runConfig

	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		getwd: func() (string, error) {
			return t.TempDir(), nil
		},
		environ: func() []string { return nil },
		run: func(cfg runConfig) error {
			got = cfg
			return nil
		},
	})
	cmd.SetArgs([]string{"--audit", "--", "bash"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("expected audit mode, got %q", got.manager.PolicyMode)
	}
	if !got.reporting.PolicyViolations || !got.reporting.AccessSummary || !got.reporting.RequestSummary {
		t.Fatalf("expected audit reporting to be enabled, got %#v", got.reporting)
	}
}

func TestRootCommandDoesNotRegisterRemovedPolicyFlags(t *testing.T) {
	cmd := newRootCommand(commandDeps{stdout: io.Discard, stderr: io.Discard})
	for _, flag := range []string{
		"allowed-domain",
		"deny-domain",
		"allow-http-method",
		"policy-mode",
		"mitm",
	} {
		if got := cmd.Flags().Lookup(flag); got != nil {
			t.Fatalf("expected %q to be removed, found %q", flag, got.Name)
		}
	}
}

func TestBuildConfigDefaultsToAuditReportingWithoutConfigFile(t *testing.T) {
	cfg, err := buildConfig(cliOptions{}, []string{"bash"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("expected default policy mode to be audit, got %q", cfg.manager.PolicyMode)
	}
	if !cfg.reporting.PolicyViolations || !cfg.reporting.AccessSummary || !cfg.reporting.RequestSummary {
		t.Fatalf("expected default reporting to be enabled, got %#v", cfg.reporting)
	}
}

func TestBuildConfigUsesBBoxYAMLWhenPresent(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "nested")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBBoxYAML(t, root, `
traffic_mode: transparent
access_log: off
max_request_body_bytes: 123
policy:
  allow_host_patterns:
    - "^api[.]example[.]com$"
  allow_http_methods:
    - post
`)

	cfg, err := buildConfig(cliOptions{}, []string{"bash"}, child, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("expected transparent traffic mode from config file, got %q", cfg.sandbox.TrafficMode)
	}
	if cfg.accessLogMode != "off" {
		t.Fatalf("expected access log mode off from config file, got %q", cfg.accessLogMode)
	}
	if cfg.manager.MaxRequestBodyBytes != 123 {
		t.Fatalf("expected max request body bytes from config file, got %d", cfg.manager.MaxRequestBodyBytes)
	}
	if !reflect.DeepEqual(cfg.sandbox.Policy.AllowHostPatterns, []string{"^api[.]example[.]com$"}) {
		t.Fatalf("unexpected allow host patterns: %v", cfg.sandbox.Policy.AllowHostPatterns)
	}
	if !reflect.DeepEqual(cfg.sandbox.Policy.AllowHTTPMethods, []string{"POST"}) {
		t.Fatalf("unexpected allow methods: %v", cfg.sandbox.Policy.AllowHTTPMethods)
	}
}

func TestBuildConfigCLIFlagsOverrideBBoxYAML(t *testing.T) {
	root := t.TempDir()
	writeBBoxYAML(t, root, `
traffic_mode: transparent
access_log: off
report_policy_violations: false
report_access_summary: false
report_request_summary: false
`)

	cfg, err := buildConfig(cliOptions{
		trafficMode:    "proxy",
		accessLog:      "json",
		reportPolicy:   true,
		reportAccess:   true,
		reportRequests: true,
	}, []string{"bash"}, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sandbox.TrafficMode != bbox.TrafficModeProxy {
		t.Fatalf("expected traffic mode override from CLI, got %q", cfg.sandbox.TrafficMode)
	}
	if cfg.accessLogMode != "json" {
		t.Fatalf("expected access log override from CLI, got %q", cfg.accessLogMode)
	}
	if !cfg.reporting.PolicyViolations || !cfg.reporting.AccessSummary || !cfg.reporting.RequestSummary {
		t.Fatalf("expected reporting overrides from CLI, got %#v", cfg.reporting)
	}
}

func TestBuildConfigTransparentModeDoesNotRequireMITMFlag(t *testing.T) {
	cfg, err := buildConfig(cliOptions{trafficMode: "transparent"}, []string{"curl"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("unexpected traffic mode: %q", cfg.sandbox.TrafficMode)
	}
	if !cfg.manager.MITM.Enabled {
		t.Fatal("expected transparent mode to enable mitm internally")
	}
}

func TestAuditFlagStillOverridesMergedConfig(t *testing.T) {
	root := t.TempDir()
	writeBBoxYAML(t, root, `
report_policy_violations: false
report_access_summary: false
report_request_summary: false
`)
	cfg, err := buildConfig(cliOptions{audit: true}, []string{"bash"}, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("expected policy mode audit, got %q", cfg.manager.PolicyMode)
	}
	if !cfg.reporting.PolicyViolations || !cfg.reporting.AccessSummary || !cfg.reporting.RequestSummary {
		t.Fatalf("expected audit flag to force reporting on, got %#v", cfg.reporting)
	}
}

func TestBuildConfigClearEnvSkipsInheritedEnv(t *testing.T) {
	cfg, err := buildConfig(cliOptions{
		clearEnv: true,
		env:      []string{"FOO=bar"},
	}, []string{"bash"}, t.TempDir(), []string{"SECRET=value"})
	if err != nil {
		t.Fatal(err)
	}
	if containsString(cfg.sandbox.Env, "SECRET=value") {
		t.Fatalf("did not expect inherited env, got %v", cfg.sandbox.Env)
	}
	if !containsString(cfg.sandbox.Env, "FOO=bar") {
		t.Fatalf("expected explicit env override, got %v", cfg.sandbox.Env)
	}
}

func TestBuildConfigAuditShorthandEnablesAuditModeAndReporting(t *testing.T) {
	cfg, err := buildConfig(cliOptions{audit: true}, []string{"bash"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("expected audit mode, got %q", cfg.manager.PolicyMode)
	}
	if !cfg.manager.Reporting.PolicyViolations || !cfg.manager.Reporting.AccessSummary || !cfg.manager.Reporting.RequestSummary {
		t.Fatalf("expected audit shorthand to enable reporting, got %#v", cfg.manager.Reporting)
	}
}

func TestDispatchRunsInternalHelperWithoutCobra(t *testing.T) {
	helperCalled := false
	err := dispatch(
		[]string{"internal-helper", "--bridge-fd", "3"},
		commandDeps{},
		func(args []string) error {
			helperCalled = true
			if len(args) == 0 || args[0] != "--bridge-fd" {
				t.Fatalf("args = %v", args)
			}
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !helperCalled {
		t.Fatal("expected internal helper dispatch")
	}
}

func TestDispatchRunsInternalLauncherWithoutCobra(t *testing.T) {
	launcherCalled := false
	err := dispatch(
		[]string{"internal-launcher", "--launcher-fd", "7", "--", "bbox-seccomp-launcher", "/bin/true"},
		commandDeps{},
		nil,
		func(args []string) error {
			launcherCalled = true
			if len(args) < 4 || args[0] != "--launcher-fd" {
				t.Fatalf("args = %v", args)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !launcherCalled {
		t.Fatal("expected internal launcher dispatch")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeBBoxYAML(t *testing.T, dir string, content string) {
	t.Helper()
	path := filepath.Join(dir, "bbox.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
