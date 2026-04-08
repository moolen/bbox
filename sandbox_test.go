package bbox

import (
	"path/filepath"
	"testing"
)

func TestSandboxRunRejectsEmptyArgv(t *testing.T) {
	s := &Sandbox{}
	_, err := s.Run(nil, nil, RunOptions{})
	if err == nil {
		t.Fatal("expected empty argv to fail")
	}
}

func TestSandboxRunInteractiveRejectsEmptyArgv(t *testing.T) {
	s := &Sandbox{}
	_, err := s.RunInteractive(nil, nil, RunOptions{})
	if err == nil {
		t.Fatal("expected empty argv to fail")
	}
}

func TestSandboxCloseDoesNotUnregisterExistingSandboxOnDuplicateStartupFailure(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{})
	if err != nil {
		t.Fatal(err)
	}

	manager := newProxyManager(policy)
	original := &Sandbox{manager: manager, id: "dup"}
	if err := manager.registerSandbox("dup", nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.attachSandbox("dup", original); err != nil {
		t.Fatal(err)
	}

	duplicate := &Sandbox{manager: manager, id: "dup"}
	if err := duplicate.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	registeredPolicy, ok := manager.policyForSandbox("dup")
	if !ok {
		t.Fatal("expected original sandbox registration to remain intact")
	}
	if registeredPolicy != policy {
		t.Fatal("expected original sandbox policy to remain registered")
	}

	attached, ok := manager.registry.Sandbox("dup")
	if !ok {
		t.Fatal("expected sandbox entry to remain registered")
	}
	if attached != original {
		t.Fatal("expected original sandbox entry to remain attached")
	}
}

func TestSandboxUsesHelperReportedProxyEnv(t *testing.T) {
	env := runEnvForProxyAddr("127.0.0.1:40123", []string{
		"FOO=bar",
		"HTTP_PROXY=http://stale",
		"HTTPS_PROXY=http://stale-secure",
	})

	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := splitEnv(entry)
		if !ok {
			t.Fatalf("invalid env entry %q", entry)
		}
		got[key] = value
	}

	if got["PATH"] != "/usr/bin" {
		t.Fatalf("unexpected PATH: got %q", got["PATH"])
	}
	if got["HTTP_PROXY"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected HTTP_PROXY: got %q", got["HTTP_PROXY"])
	}
	if got["http_proxy"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected http_proxy: got %q", got["http_proxy"])
	}
	if got["HTTPS_PROXY"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected HTTPS_PROXY: got %q", got["HTTPS_PROXY"])
	}
	if got["https_proxy"] != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected https_proxy: got %q", got["https_proxy"])
	}
	if got["FOO"] != "bar" {
		t.Fatalf("unexpected FOO: got %q", got["FOO"])
	}
}

func TestSandboxUsesProvidedPATHInProxyMode(t *testing.T) {
	env := runEnvForProxyAddr("127.0.0.1:40123", []string{
		"PATH=/custom/bin:/custom/sbin",
	})

	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := splitEnv(entry)
		if !ok {
			t.Fatalf("invalid env entry %q", entry)
		}
		got[key] = value
	}

	if got["PATH"] != "/custom/bin:/custom/sbin" {
		t.Fatalf("unexpected PATH: got %q", got["PATH"])
	}
}

func TestSandboxProxyAccessors(t *testing.T) {
	sandbox := &Sandbox{proxyAddr: "127.0.0.1:40123"}

	if got := sandbox.ProxyAddr(); got != "127.0.0.1:40123" {
		t.Fatalf("unexpected proxy addr: got %q", got)
	}
	if got := sandbox.ProxyURL(); got != "http://127.0.0.1:40123" {
		t.Fatalf("unexpected proxy url: got %q", got)
	}
}

func TestNilSandboxProxyAccessorsReturnEmptyString(t *testing.T) {
	var sandbox *Sandbox

	if got := sandbox.ProxyAddr(); got != "" {
		t.Fatalf("expected empty proxy addr, got %q", got)
	}
	if got := sandbox.ProxyURL(); got != "" {
		t.Fatalf("expected empty proxy url, got %q", got)
	}
}

func TestSandboxProxyAccessorsRemainEmptyInTransparentMode(t *testing.T) {
	sandbox := &Sandbox{
		trafficMode: TrafficModeTransparent,
		proxyAddr:   "127.0.0.1:40123",
	}

	if got := sandbox.ProxyAddr(); got != "" {
		t.Fatalf("expected transparent sandbox proxy addr to be empty, got %q", got)
	}
	if got := sandbox.ProxyURL(); got != "" {
		t.Fatalf("expected transparent sandbox proxy url to be empty, got %q", got)
	}
}

func TestTrafficModeDefaultsToProxy(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		if got := normalizeTrafficMode(""); got != TrafficModeProxy {
			t.Fatalf("expected traffic mode to default to proxy, got %q", got)
		}
	})

	t.Run("normalizes", func(t *testing.T) {
		if got := normalizeTrafficMode("  ProXy "); got != TrafficModeProxy {
			t.Fatalf("expected proxy normalization, got %q", got)
		}
		if got := normalizeTrafficMode("  TRANSPARENT "); got != TrafficModeTransparent {
			t.Fatalf("expected transparent normalization, got %q", got)
		}
	})

	t.Run("runEnvRejectsInvalid", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("expected runEnvForTrafficMode to panic on invalid mode")
			}
		}()
		_ = runEnvForTrafficMode(TrafficMode("unknown"), "127.0.0.1:40123", nil)
	})
}

func TestValidateSandboxOptionsRejectsUnknownTrafficMode(t *testing.T) {
	opts := SandboxOptions{TrafficMode: TrafficMode("unknown")}

	if err := validateSandboxOptions(opts, true); err == nil {
		t.Fatal("expected unknown traffic mode to fail validation")
	}
}

func TestValidateSandboxOptionsRejectsTransparentModeWithoutMITM(t *testing.T) {
	opts := SandboxOptions{TrafficMode: TrafficModeTransparent}

	if err := validateSandboxOptions(opts, false); err == nil {
		t.Fatal("expected transparent mode without MITM to fail validation")
	}
}

func TestValidateSandboxOptionsAllowsDockerBuildInTransparentModeWithMITM(t *testing.T) {
	opts := SandboxOptions{
		TrafficMode: TrafficModeTransparent,
		DockerBuild: DockerBuildOptions{Enabled: true},
	}

	if err := validateSandboxOptions(opts, true); err != nil {
		t.Fatalf("expected docker build support in transparent mode to validate, got %v", err)
	}
}

func TestValidateSandboxOptionsDoesNotResolveDockerBuildTooling(t *testing.T) {
	opts := SandboxOptions{
		TrafficMode: TrafficModeTransparent,
		DockerBuild: DockerBuildOptions{
			Enabled:       true,
			BuildkitdPath: filepath.Join(t.TempDir(), "missing-buildkitd"),
		},
	}

	if err := validateSandboxOptions(opts, true); err != nil {
		t.Fatalf("expected validation to ignore docker build host tooling resolution, got %v", err)
	}
}

func TestValidateSandboxOptionsRejectsUnknownPolicyMode(t *testing.T) {
	opts := SandboxOptions{PolicyMode: PolicyMode("broken")}

	if err := validateSandboxOptions(opts, true); err == nil {
		t.Fatal("expected unknown policy mode to fail validation")
	}
}

func TestValidateSandboxOptionsRejectsRelativeDockerSocketMountPath(t *testing.T) {
	opts := SandboxOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:   true,
			MountPath: "var/run/docker.sock",
		},
	}

	if err := validateSandboxOptions(opts, true); err == nil {
		t.Fatal("expected relative docker socket mount path to fail validation")
	}
}

func TestNewSandboxRejectsDockerSocketMountPathOverlap(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{
		DockerSocket: DockerSocketOptions{
			Enabled:          true,
			TargetSocketPath: filepath.Join(t.TempDir(), "docker.sock"),
		},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	_, err = manager.NewSandbox(t.Context(), SandboxOptions{
		Name: "docker-overlap",
		Mounts: []Mount{
			{
				Source:   t.TempDir(),
				Target:   "/var/run",
				ReadOnly: false,
			},
		},
		DockerSocket: DockerSocketOptions{
			Enabled: true,
		},
	})
	if err == nil {
		t.Fatal("expected overlapping docker socket mount to fail")
	}
}

func TestRunEnvForTrafficModeSkipsProxyEnvInTransparentMode(t *testing.T) {
	env := runEnvForTrafficMode(TrafficModeTransparent, "127.0.0.1:40123", []string{
		"FOO=bar",
		"HTTP_PROXY=http://stale",
		"HTTPS_PROXY=http://stale-secure",
	})

	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := splitEnv(entry)
		if !ok {
			t.Fatalf("invalid env entry %q", entry)
		}
		got[key] = value
	}

	if got["PATH"] != "/usr/bin" {
		t.Fatalf("unexpected PATH: got %q", got["PATH"])
	}
	if _, ok := got["HTTP_PROXY"]; ok {
		t.Fatalf("expected HTTP_PROXY to be omitted, got %q", got["HTTP_PROXY"])
	}
	if _, ok := got["http_proxy"]; ok {
		t.Fatalf("expected http_proxy to be omitted, got %q", got["http_proxy"])
	}
	if _, ok := got["HTTPS_PROXY"]; ok {
		t.Fatalf("expected HTTPS_PROXY to be omitted, got %q", got["HTTPS_PROXY"])
	}
	if _, ok := got["https_proxy"]; ok {
		t.Fatalf("expected https_proxy to be omitted, got %q", got["https_proxy"])
	}
	if got["FOO"] != "bar" {
		t.Fatalf("unexpected FOO: got %q", got["FOO"])
	}
}

func TestRunEnvForTrafficModePreservesPATHOverrideInTransparentMode(t *testing.T) {
	env := runEnvForTrafficMode(TrafficModeTransparent, "127.0.0.1:40123", []string{
		"PATH=/custom/bin:/custom/sbin",
	})

	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := splitEnv(entry)
		if !ok {
			t.Fatalf("invalid env entry %q", entry)
		}
		got[key] = value
	}

	if got["PATH"] != "/custom/bin:/custom/sbin" {
		t.Fatalf("unexpected PATH: got %q", got["PATH"])
	}
}
