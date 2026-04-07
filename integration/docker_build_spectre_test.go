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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repoDir := cloneRepository(t, ctx, "https://github.com/moolen/spectre")
	sandboxRepoDir := "/workspace/spectre"
	outputPath := filepath.Join(repoDir, ".bbox-docker-build.oci.tar")

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:        "docker-build-spectre",
		TrafficMode: bbox.TrafficModeProxy,
		PolicyMode:  bbox.PolicyModeEnforce,
		Policy:      spectreBuilderNetworkPolicy(),
		WorkDir:     sandboxRepoDir,
		Mounts: []bbox.Mount{{
			Source:   repoDir,
			Target:   sandboxRepoDir,
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

	result, err := sandbox.Run(ctx, []string{"docker", "build", "--target", "builder", "."}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("docker build transport failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("docker build failed: exit=%d stdout=%q stderr=%q", result.ExitCode, string(result.Stdout), string(result.Stderr))
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected docker build artifact at %s: %v", outputPath, err)
	}
}

func spectreBuilderNetworkPolicy() bbox.NetworkPolicy {
	httpsHosts := []string{
		`^auth[.]docker[.]io$`,
		`^registry-1[.]docker[.]io$`,
		`^docker-images-prod[.]6aa30f8b08e16409b46e0173d6de2f56[.]r2[.]cloudflarestorage[.]com$`,
		`^proxy[.]golang[.]org$`,
		`^sum[.]golang[.]org$`,
		`^storage[.]googleapis[.]com$`,
	}
	httpHosts := []string{
		`^dl-cdn[.]alpinelinux[.]org$`,
	}

	rules := make([]bbox.PolicyRule, 0, len(httpsHosts)*2+len(httpHosts)*2)
	for _, host := range httpsHosts {
		rules = append(rules, bbox.PolicyRule{HostPatterns: []string{host}})
		rules = append(rules, bbox.PolicyRule{
			HostPatterns: []string{host},
			ConnectPorts: []string{"443"},
		})
	}
	for _, host := range httpHosts {
		rules = append(rules, bbox.PolicyRule{HostPatterns: []string{host}})
		rules = append(rules, bbox.PolicyRule{
			HostPatterns: []string{host},
			ConnectPorts: []string{"443"},
		})
	}
	return bbox.NetworkPolicy{Rules: rules}
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

func cloneRepository(t *testing.T, ctx context.Context, remote string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", remote, dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("clone %s: %v: %s", remote, err, string(output))
	}
	return dir
}
