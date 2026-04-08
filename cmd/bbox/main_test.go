package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/bbox"
)

func TestParseMountSpec(t *testing.T) {
	got, err := parseMountSpec("/host/path:/sandbox/path", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "/host/path" || got.Target != "/sandbox/path" || got.ReadOnly {
		t.Fatalf("unexpected mount: %#v", got)
	}
}

func TestBuildRunConfigUsesEffectiveCLIConfig(t *testing.T) {
	payload := []string{"/bin/sh"}
	cwd := t.TempDir()
	env := []string{"PATH=/usr/bin"}

	effective := effectiveCLIConfig{
		TrafficMode: "proxy",
	}
	cfg, err := buildRunConfig(effective, payload, cwd, env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("policy mode = %q", cfg.manager.PolicyMode)
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

func TestBuildConfigNormalizesFileFlagsAndEnvironmentIntoOneEffectiveShape(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	certsDir := filepath.Join(root, "certs")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeBBoxYAML(t, root, `
workdir: ./from-file
mount_ro:
  - ./certs:/etc/ssl/certs
env:
  - FROM_FILE=1
clear_env: true
traffic_mode: transparent
`)

	opts := cliOptions{
		workDir:     "./from-flag",
		env:         []string{"FROM_FLAG=1"},
		trafficMode: "proxy",
		flagOverrides: cliFlagOverrides{
			TrafficMode: stringPtr("proxy"),
		},
	}
	opts.clearEnvSet = true
	opts.clearEnv = false

	cfg, err := buildConfig(opts, []string{"bash", "-lc", "pwd"}, nested, []string{"FROM_HOST=1"})
	if err != nil {
		t.Fatal(err)
	}

	wantWorkDir := filepath.Join(nested, "from-flag")
	if cfg.sandbox.WorkDir != wantWorkDir {
		t.Fatalf("workdir = %q want %q", cfg.sandbox.WorkDir, wantWorkDir)
	}
	if cfg.sandbox.TrafficMode != bbox.TrafficModeProxy {
		t.Fatalf("traffic mode = %q want %q", cfg.sandbox.TrafficMode, bbox.TrafficModeProxy)
	}
	wantMount := bbox.Mount{
		Source:   certsDir,
		Target:   "/etc/ssl/certs",
		ReadOnly: true,
	}
	if !containsMount(cfg.sandbox.Mounts, wantMount) {
		t.Fatalf("expected file-relative mount to be resolved and included, mounts=%v want=%#v", cfg.sandbox.Mounts, wantMount)
	}
	if containsString(cfg.sandbox.Env, "FROM_FILE=1") {
		t.Fatalf("did not expect file env entry after runtime env replacement, got %v", cfg.sandbox.Env)
	}
	if !containsString(cfg.sandbox.Env, "FROM_FLAG=1") || !containsString(cfg.sandbox.Env, "FROM_HOST=1") {
		t.Fatalf("expected merged environment entries in sandbox env, got %v", cfg.sandbox.Env)
	}
}

func TestBuildCLIProcessRunOptionsForwardsStdinWithoutTTY(t *testing.T) {
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()

	opts, interactive, cleanup, err := buildCLIProcessRunOptions(stdin, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if interactive {
		t.Fatal("expected non-tty stdin to disable interactive execution")
	}
	if opts.Interactive {
		t.Fatalf("expected non-tty run options to stay buffered, got %#v", opts)
	}
	if opts.Stdin != stdin {
		t.Fatalf("expected non-tty run options to preserve stdin, got %#v", opts)
	}
	if opts.Stdout != nil || opts.Stderr != nil {
		t.Fatalf("expected non-tty run options to avoid live stdout/stderr forwarding, got %#v", opts)
	}
	if opts.Terminal || opts.Resize != nil {
		t.Fatalf("expected non-tty run options to avoid terminal plumbing, got %#v", opts)
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
		"allowed-domains-file",
		"deny-domain",
		"allow-connect",
		"allow-connect-port",
		"allow-http-method",
		"allow-path",
		"deny-path",
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

func TestBuildConfigDefaultsAllowHTTPSConnectWithoutConfigFile(t *testing.T) {
	cfg, err := buildConfig(cliOptions{}, []string{"bash"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := bbox.NetworkPolicy{
		Rules: []bbox.PolicyRule{
			{ConnectPorts: []string{"443"}},
		},
	}
	if !reflect.DeepEqual(cfg.sandbox.Policy, want) {
		t.Fatalf("expected default CONNECT rule %#v, got %#v", want, cfg.sandbox.Policy)
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
  rules:
    - host_patterns:
        - "^api[.]example[.]com$"
      http_methods:
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
	wantPolicy := bbox.NetworkPolicy{
		Rules: []bbox.PolicyRule{
			{
				HostPatterns: []string{"^api[.]example[.]com$"},
				HTTPMethods:  []string{"POST"},
			},
		},
	}
	if !reflect.DeepEqual(cfg.sandbox.Policy, wantPolicy) {
		t.Fatalf("unexpected policy: %#v", cfg.sandbox.Policy)
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
	trafficMode := "proxy"
	accessLog := "json"
	reportPolicy := true
	reportAccess := true
	reportRequests := true

	cfg, err := buildConfig(cliOptions{
		trafficMode:    "proxy",
		accessLog:      "json",
		reportPolicy:   true,
		reportAccess:   true,
		reportRequests: true,
		flagOverrides: cliFlagOverrides{
			TrafficMode:          &trafficMode,
			ReportPolicy:         &reportPolicy,
			ReportAccessSummary:  &reportAccess,
			ReportRequestSummary: &reportRequests,
			AccessLog:            &accessLog,
		},
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

func TestBuildConfigWiresDockerSocketOptionsIntoManagerAndSandbox(t *testing.T) {
	root := t.TempDir()
	writeBBoxYAML(t, root, `
docker_socket:
  enabled: true
  mount_path: /var/run/docker.sock
  target_socket_path: /run/user/1000/docker.sock
  default_action: deny
  rules:
    - action: allow
      operations:
        - image_pull
        - build
`)

	cfg, err := buildConfig(cliOptions{}, []string{"/bin/sh"}, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.manager.DockerSocket.Enabled {
		t.Fatal("expected manager docker socket to be enabled")
	}
	if cfg.manager.DockerSocket.MountPath != "/var/run/docker.sock" {
		t.Fatalf("unexpected manager docker socket mount path: %q", cfg.manager.DockerSocket.MountPath)
	}
	if cfg.manager.DockerSocket.TargetSocketPath != "/run/user/1000/docker.sock" {
		t.Fatalf("unexpected manager docker socket target path: %q", cfg.manager.DockerSocket.TargetSocketPath)
	}
	if cfg.manager.DockerSocket.Policy.DefaultAction != bbox.DockerRuleActionDeny {
		t.Fatalf("unexpected manager docker socket default action: %q", cfg.manager.DockerSocket.Policy.DefaultAction)
	}
	if !reflect.DeepEqual(cfg.manager.DockerSocket.Policy.Rules, []bbox.DockerSocketRule{
		{
			Action:     bbox.DockerRuleActionAllow,
			Operations: []bbox.DockerOperation{"image_pull", "build"},
		},
	}) {
		t.Fatalf("unexpected manager docker socket rules: %#v", cfg.manager.DockerSocket.Policy.Rules)
	}
	if !cfg.sandbox.DockerSocket.Enabled {
		t.Fatal("expected sandbox docker socket to be enabled")
	}
}

func TestBuildConfigDarwinKeepsSameConfigButFailsUnsupportedAtRuntime(t *testing.T) {
	prevPlatform := cliPlatform
	cliPlatform = "darwin"
	t.Cleanup(func() {
		cliPlatform = prevPlatform
	})

	cwd := t.TempDir()
	mountSource := t.TempDir()

	cfg, err := buildConfig(cliOptions{
		mountRO: []string{mountSource + ":/workspace"},
	}, []string{"/bin/sh"}, cwd, nil)
	if err != nil {
		t.Fatalf("buildConfig() error = %v", err)
	}

	if cfg.sandbox.WorkDir != cwd {
		t.Fatalf("unexpected workdir: got %q want %q", cfg.sandbox.WorkDir, cwd)
	}
	if len(cfg.sandbox.Binaries) == 0 || cfg.sandbox.Binaries[0] != "/bin/sh" {
		t.Fatalf("unexpected binaries: %#v", cfg.sandbox.Binaries)
	}
	if len(cfg.sandbox.Mounts) != 1 {
		t.Fatalf("expected only the explicit mount on darwin, got %#v", cfg.sandbox.Mounts)
	}

	err = validateRunConfigPlatform(cfg)
	if err == nil {
		t.Fatal("expected explicit mount to fail on darwin")
	}
	if !strings.Contains(err.Error(), "mount_ro is not supported on darwin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRootCommandUnchangedFlagsDoNotOverrideBBoxYAML(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBBoxYAML(t, root, `
traffic_mode: transparent
access_log: off
`)

	var got runConfig
	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		getwd: func() (string, error) {
			return nested, nil
		},
		environ: func() []string { return nil },
		run: func(cfg runConfig) error {
			got = cfg
			return nil
		},
	})
	cmd.SetArgs([]string{"--", "bash"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got.sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("expected file traffic mode to survive when flag unchanged, got %q", got.sandbox.TrafficMode)
	}
	if got.accessLogMode != "off" {
		t.Fatalf("expected file access_log to survive when flag unchanged, got %q", got.accessLogMode)
	}
}

func TestRootCommandConfigDiscoveryPrefersNearestBBoxYAML(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	nested := filepath.Join(project, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBBoxYAML(t, root, `
traffic_mode: proxy
access_log: off
`)
	writeBBoxYAML(t, project, `
traffic_mode: transparent
access_log: json
`)

	var got runConfig
	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		getwd: func() (string, error) {
			return nested, nil
		},
		environ: func() []string { return nil },
		run: func(cfg runConfig) error {
			got = cfg
			return nil
		},
	})
	cmd.SetArgs([]string{"--", "bash"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got.sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("expected nearest bbox.yaml traffic mode, got %q", got.sandbox.TrafficMode)
	}
	if got.accessLogMode != "json" {
		t.Fatalf("expected nearest bbox.yaml access log, got %q", got.accessLogMode)
	}
}

func TestBuildConfigOmittedPolicyStillUsesAuditReportingDefaults(t *testing.T) {
	root := t.TempDir()
	writeBBoxYAML(t, root, `
traffic_mode: proxy
access_log: json
`)

	cfg, err := buildConfig(cliOptions{}, []string{"bash"}, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.manager.PolicyMode != bbox.PolicyModeAudit {
		t.Fatalf("expected default policy mode audit when policy section omitted, got %q", cfg.manager.PolicyMode)
	}
	if !cfg.reporting.PolicyViolations || !cfg.reporting.AccessSummary || !cfg.reporting.RequestSummary {
		t.Fatalf("expected reporting defaults when policy section omitted, got %#v", cfg.reporting)
	}
}

func TestRootCommandClearEnvFalseOverridesBBoxYAMLTrue(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBBoxYAML(t, root, `
clear_env: true
`)

	var got runConfig
	cmd := newRootCommand(commandDeps{
		stdout: io.Discard,
		stderr: io.Discard,
		getwd: func() (string, error) {
			return nested, nil
		},
		environ: func() []string { return []string{"SECRET=value"} },
		run: func(cfg runConfig) error {
			got = cfg
			return nil
		},
	})
	cmd.SetArgs([]string{"--clear-env=false", "--", "bash"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !containsString(got.sandbox.Env, "SECRET=value") {
		t.Fatalf("expected inherited env to be restored by --clear-env=false, got %v", got.sandbox.Env)
	}
}

func TestBuildConfigTrafficModesDoNotRequireMITMFlag(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		want     bbox.TrafficMode
		wantMITM bool
	}{
		{name: "proxy", mode: "proxy", want: bbox.TrafficModeProxy, wantMITM: false},
		{name: "transparent", mode: "transparent", want: bbox.TrafficModeTransparent, wantMITM: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trafficMode := tt.mode
			cfg, err := buildConfig(cliOptions{
				trafficMode: tt.mode,
				flagOverrides: cliFlagOverrides{
					TrafficMode: &trafficMode,
				},
			}, []string{"curl"}, t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.sandbox.TrafficMode != tt.want {
				t.Fatalf("unexpected traffic mode: %q", cfg.sandbox.TrafficMode)
			}
			if cfg.manager.MITM.Enabled != tt.wantMITM {
				t.Fatalf("expected %s mode mitm=%v, got %v", tt.mode, tt.wantMITM, cfg.manager.MITM.Enabled)
			}
		})
	}
}

func TestBuildConfigDockerBuildFromBBoxYAMLDoesNotRequireHostDockerBinary(t *testing.T) {
	root := t.TempDir()
	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"buildkitd", "buildctl", "runc", "podman", "newuidmap", "newgidmap"} {
		writeExecutableFixture(t, toolDir, name)
	}

	writeBBoxYAML(t, root, `
docker_build:
  enabled: true
  buildkitd_path: ./tools/buildkitd
  buildctl_path: ./tools/buildctl
  runc_path: ./tools/runc
  podman_path: ./tools/podman
  newuidmap_path: ./tools/newuidmap
  newgidmap_path: ./tools/newgidmap
env:
  - PATH=`+toolDir+`
clear_env: true
`)

	cfg, err := buildConfig(cliOptions{}, []string{"docker", "build", "--target", "builder", "."}, root, []string{"PATH=/does/not/exist"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.sandbox.DockerBuild.Enabled {
		t.Fatal("expected docker build to be enabled")
	}
	if cfg.sandbox.DockerBuild.BuildkitdPath != filepath.Join(root, "tools/buildkitd") {
		t.Fatalf("unexpected buildkitd path: %q", cfg.sandbox.DockerBuild.BuildkitdPath)
	}
	if len(cfg.sandbox.Binaries) != 0 {
		t.Fatalf("expected host docker binary to be skipped, got %v", cfg.sandbox.Binaries)
	}
	if containsMount(cfg.sandbox.Mounts, bbox.Mount{Source: "/usr", Target: "/usr", ReadOnly: true}) {
		t.Fatalf("did not expect /usr PATH mount to hide staged docker shim, got %v", cfg.sandbox.Mounts)
	}
}

func TestRootCommandPrintPolicyShowsMergedConfigAndFlagState(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBBoxYAML(t, root, `
traffic_mode: transparent
policy:
  rules:
    - host_patterns:
        - "^api[.]example[.]com$"
`)

	var got runConfig
	var stdout bytes.Buffer
	cmd := newRootCommand(commandDeps{
		stdout: &stdout,
		stderr: io.Discard,
		getwd: func() (string, error) {
			return nested, nil
		},
		environ: func() []string { return nil },
		run: func(cfg runConfig) error {
			got = cfg
			return nil
		},
	})
	cmd.SetArgs([]string{"--print-policy", "--report-access-summary=false", "--", "bash"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got.sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("expected merged config traffic mode in run config, got %q", got.sandbox.TrafficMode)
	}
	if got.reporting.AccessSummary {
		t.Fatalf("expected CLI flag override to disable access summary in run config, got %#v", got.reporting)
	}

	var printed struct {
		Manager bbox.ProxyOptions   `json:"manager"`
		Sandbox bbox.SandboxOptions `json:"sandbox"`
		Argv    []string            `json:"argv"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		t.Fatalf("decode print-policy output: %v\noutput=%s", err, stdout.String())
	}
	if printed.Sandbox.TrafficMode != bbox.TrafficModeTransparent {
		t.Fatalf("expected print-policy to show merged file traffic mode, got %q", printed.Sandbox.TrafficMode)
	}
	wantPolicy := bbox.NetworkPolicy{
		Rules: []bbox.PolicyRule{
			{HostPatterns: []string{"^api[.]example[.]com$"}},
		},
	}
	if !reflect.DeepEqual(printed.Sandbox.Policy, wantPolicy) {
		t.Fatalf("expected print-policy to include merged file policy, got %#v", printed.Sandbox.Policy)
	}
	if printed.Manager.Reporting.AccessSummary {
		t.Fatalf("expected print-policy to include CLI override state, got %#v", printed.Manager.Reporting)
	}
	if len(printed.Argv) != 1 || printed.Argv[0] != "bash" {
		t.Fatalf("expected print-policy argv to match payload, got %v", printed.Argv)
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
		clearEnv:    true,
		clearEnvSet: true,
		env:         []string{"FOO=bar"},
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

func TestBuildConfigResolvesRequestedBinariesAgainstEffectivePATHAndAddsPathMounts(t *testing.T) {
	cwd := t.TempDir()
	pathRoot := filepath.Join(t.TempDir(), "toolchain")
	pathDir := filepath.Join(pathRoot, "bin")
	if err := os.MkdirAll(pathDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadPath := writeExecutableFixture(t, pathDir, "tool-a")
	explicitPath := writeExecutableFixture(t, pathDir, "tool-b")
	if err := os.WriteFile(filepath.Join(pathDir, "tool-c"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig(cliOptions{
		binaries:    []string{"tool-b"},
		env:         []string{"PATH=" + pathDir},
		clearEnv:    true,
		clearEnvSet: true,
	}, []string{"tool-a"}, cwd, []string{"PATH=/does/not/matter"})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cfg.sandbox.Binaries, []string{payloadPath, explicitPath}) {
		t.Fatalf("unexpected staged binaries: got %v want %v", cfg.sandbox.Binaries, []string{payloadPath, explicitPath})
	}
	if got := envValue(cfg.sandbox.Env, "PATH"); got != pathDir {
		t.Fatalf("expected sandbox PATH %q, got %q", pathDir, got)
	}
	if !containsMount(cfg.sandbox.Mounts, bbox.Mount{Source: pathRoot, Target: pathRoot, ReadOnly: true}) {
		t.Fatalf("expected PATH root mount for %q in %v", pathRoot, cfg.sandbox.Mounts)
	}
}

func TestBuildConfigEnvPATHOverrideWinsOverInheritedPATHForMounts(t *testing.T) {
	cwd := t.TempDir()
	inheritedRoot := filepath.Join(t.TempDir(), "inherited")
	inheritedDir := filepath.Join(inheritedRoot, "bin")
	if err := os.MkdirAll(inheritedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	overrideRoot := filepath.Join(t.TempDir(), "override")
	overrideDir := filepath.Join(overrideRoot, "bin")
	if err := os.MkdirAll(overrideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inheritedOnly := writeExecutableFixture(t, inheritedDir, "tool-old")
	overridePayload := writeExecutableFixture(t, overrideDir, "tool-new")
	overrideExtra := writeExecutableFixture(t, overrideDir, "tool-extra")

	cfg, err := buildConfig(cliOptions{
		env: []string{"PATH=" + overrideDir},
	}, []string{"tool-new"}, cwd, []string{"PATH=" + inheritedDir})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cfg.sandbox.Binaries, []string{overridePayload}) {
		t.Fatalf("unexpected staged binaries: got %v want %v", cfg.sandbox.Binaries, []string{overridePayload})
	}
	if containsString(cfg.sandbox.Binaries, overrideExtra) || containsString(cfg.sandbox.Binaries, inheritedOnly) {
		t.Fatalf("did not expect inherited PATH binary %q in %v", inheritedOnly, cfg.sandbox.Binaries)
	}
	if got := envValue(cfg.sandbox.Env, "PATH"); got != overrideDir {
		t.Fatalf("expected sandbox PATH %q, got %q", overrideDir, got)
	}
	if !containsMount(cfg.sandbox.Mounts, bbox.Mount{Source: overrideRoot, Target: overrideRoot, ReadOnly: true}) {
		t.Fatalf("expected override PATH root mount in %v", cfg.sandbox.Mounts)
	}
	if containsMount(cfg.sandbox.Mounts, bbox.Mount{Source: inheritedRoot, Target: inheritedRoot, ReadOnly: true}) {
		t.Fatalf("did not expect inherited PATH root mount in %v", cfg.sandbox.Mounts)
	}
}

func TestBuildConfigCollapsesUsrPathEntriesIntoSingleUsrMount(t *testing.T) {
	cwd := t.TempDir()
	cfg, err := buildConfig(cliOptions{
		env:         []string{"PATH=/usr/local/bin:/usr/bin"},
		clearEnv:    true,
		clearEnvSet: true,
	}, []string{"/bin/true"}, cwd, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := bbox.Mount{Source: "/usr", Target: "/usr", ReadOnly: true}
	if !containsMount(cfg.sandbox.Mounts, want) {
		t.Fatalf("expected /usr PATH mount in %v", cfg.sandbox.Mounts)
	}
	count := 0
	for _, mount := range cfg.sandbox.Mounts {
		if mount == want {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one /usr PATH mount, got %d in %v", count, cfg.sandbox.Mounts)
	}
}

func TestPathMountTargetDoesNotCollapseRootBinDirectories(t *testing.T) {
	tests := []struct {
		dir      string
		resolved string
		want     string
	}{
		{dir: "/bin", resolved: "/bin", want: "/bin"},
		{dir: "/sbin", resolved: "/sbin", want: "/sbin"},
	}

	for _, tt := range tests {
		if got := pathMountTarget(tt.dir, tt.resolved); got != tt.want {
			t.Fatalf("pathMountTarget(%q, %q) = %q, want %q", tt.dir, tt.resolved, got, tt.want)
		}
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
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !launcherCalled {
		t.Fatal("expected internal launcher dispatch")
	}
}

func TestDispatchRunsInternalDockerBuildWithoutCobra(t *testing.T) {
	var stdout bytes.Buffer
	dockerBuildCalled := false
	err := dispatch(
		[]string{"internal-docker-build", "build", "."},
		commandDeps{stdout: &stdout, stderr: io.Discard},
		nil,
		nil,
		func(args []string, env []string, stdout io.Writer, stderr io.Writer) error {
			dockerBuildCalled = true
			if len(args) < 2 || args[0] != "build" {
				t.Fatalf("args = %v", args)
			}
			if stdout == nil || stderr == nil {
				t.Fatal("expected stdio writers to be forwarded")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !dockerBuildCalled {
		t.Fatal("expected internal docker build dispatch")
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

func containsMount(values []bbox.Mount, want bbox.Mount) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func envValue(values []string, key string) string {
	for i := len(values) - 1; i >= 0; i-- {
		entry := values[i]
		prefix := key + "="
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func writeExecutableFixture(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
	return path
}

func writeBBoxYAML(t *testing.T, dir string, content string) {
	t.Helper()
	path := filepath.Join(dir, "bbox.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
