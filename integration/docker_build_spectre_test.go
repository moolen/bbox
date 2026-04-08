package integration_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

func TestDockerBuildsSpectre(t *testing.T) {
	requireDockerBuildSandboxPrereqs(t)
	requireDockerBuildPrereqs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fixture := writeDockerBuildMatrixFixture(t)
	result := runDockerBuildFixture(t, ctx, bbox.NewProxyManager, bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true},
	}, dockerBuildRunSpec{
		name:        "docker-build-proxy-matrix",
		trafficMode: bbox.TrafficModeProxy,
		policy:      dockerBuildMatrixNetworkPolicy(),
		fixture:     fixture,
	})

	if result.ExitCode != 0 {
		t.Fatalf("docker build failed: exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}
	if _, err := os.Stat(fixture.outputPath); err != nil {
		t.Fatalf("expected docker build artifact at %s: %v", fixture.outputPath, err)
	}
}

func TestDockerBuildsSpectreTransparent(t *testing.T) {
	requireDockerBuildSandboxPrereqs(t)
	requireDockerBuildPrereqs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fixture := writeDockerBuildMatrixFixture(t)
	result := runDockerBuildFixture(t, ctx, bbox.NewProxyManager, bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true},
	}, dockerBuildRunSpec{
		name:        "docker-build-transparent-matrix",
		trafficMode: bbox.TrafficModeTransparent,
		policy:      dockerBuildMatrixNetworkPolicy(),
		fixture:     fixture,
	})

	if result.ExitCode != 0 {
		t.Fatalf("docker build failed in transparent mode: exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}
	if _, err := os.Stat(fixture.outputPath); err != nil {
		t.Fatalf("expected docker build artifact at %s: %v", fixture.outputPath, err)
	}
}

func TestDockerBuildProxyModeFailsClosedForNonProxyAwareClient(t *testing.T) {
	requireDockerBuildSandboxPrereqs(t)
	requireDockerBuildPrereqs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	fixture := writeDockerBuildProxyFailClosedFixture(t)
	result := runDockerBuildFixture(t, ctx, bbox.NewProxyManager, bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true},
	}, dockerBuildRunSpec{
		name:        "docker-build-proxy-fail-closed",
		trafficMode: bbox.TrafficModeProxy,
		policy:      dockerBuildMatrixNetworkPolicy(),
		fixture:     fixture,
	})

	if result.ExitCode == 0 {
		t.Fatalf("expected non-proxy-aware docker build to fail, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
	combined := strings.ToLower(string(result.Stdout) + "\n" + string(result.Stderr))
	if !strings.Contains(combined, "raw-client-direct-connect-failed:") {
		t.Fatalf("expected direct-connect failure marker, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
	if _, err := os.Stat(fixture.outputPath); err == nil {
		t.Fatalf("did not expect docker build artifact at %s", fixture.outputPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat docker build artifact %s: %v", fixture.outputPath, err)
	}
}

func TestDockerBuildSpectreCharacterizesPlannerExecutorBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	if err := os.WriteFile(path, []byte("nobody:100000:65536\n"), 0o644); err != nil {
		t.Fatalf("write subordinate id file: %v", err)
	}

	err := requireSubordinateIDMapping(path)
	if err == nil {
		t.Fatalf("expected subordinate id mapping check to fail for missing current user entry in %q", path)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("expected error to reference %q, got %v", path, err)
	}
	if !strings.Contains(err.Error(), "does not contain an entry for") {
		t.Fatalf("expected missing-entry error detail, got %v", err)
	}
}

type dockerBuildRunSpec struct {
	name        string
	trafficMode bbox.TrafficMode
	policy      bbox.NetworkPolicy
	fixture     dockerBuildFixture
}

type proxyManagerFactory func(bbox.ProxyOptions) (*bbox.ProxyManager, error)

func runDockerBuildFixture(t *testing.T, ctx context.Context, newManager proxyManagerFactory, managerOpts bbox.ProxyOptions, spec dockerBuildRunSpec) *bbox.RunResult {
	t.Helper()

	manager, err := newManager(managerOpts)
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:        spec.name,
		TrafficMode: spec.trafficMode,
		PolicyMode:  bbox.PolicyModeEnforce,
		Policy:      spec.policy,
		WorkDir:     spec.fixture.sandboxRepoDir,
		Mounts: []bbox.Mount{{
			Source:   spec.fixture.repoDir,
			Target:   spec.fixture.sandboxRepoDir,
			ReadOnly: false,
		}},
		DockerBuild: bbox.DockerBuildOptions{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{"docker", "build", "."}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("docker build transport failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected docker build result")
	}
	return result
}

func requireDockerBuildSandboxPrereqs(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatalf("docker-build integration test requires linux, got %s", runtime.GOOS)
	}
	if _, err := requireTool("bwrap"); err != nil {
		t.Fatalf("missing required docker-build prerequisite %q: %v", "bwrap", err)
	}
}

func requireDockerBuildPrereqs(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"buildkitd", "buildctl", "runc", "podman", "newuidmap", "newgidmap"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("missing required docker-build prerequisite %q: %v", tool, err)
		}
	}
	for _, path := range []string{"/etc/subuid", "/etc/subgid"} {
		if err := requireSubordinateIDMapping(path); err != nil {
			t.Fatalf("missing required docker-build prerequisite: %v", err)
		}
	}
}

func requireSubordinateIDMapping(path string) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user for subordinate ID check: %w", err)
	}
	username := currentUser.Username
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("resolve current username for subordinate ID check: username is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	prefix := username + ":"
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(strings.TrimSpace(scanner.Text()), prefix) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	return fmt.Errorf("%s does not contain an entry for %s", path, username)
}
