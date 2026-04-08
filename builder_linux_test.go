//go:build linux

package bbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moolen/bbox/internal/sandboxroot"
)

func TestResolveDockerBuildSupportRejectsMissingRequiredTool(t *testing.T) {
	dir := t.TempDir()
	opts := DockerBuildOptions{
		Enabled:       true,
		BuildkitdPath: writeExecutableFixture(t, dir, "buildkitd"),
		BuildctlPath:  writeExecutableFixture(t, dir, "buildctl"),
		RuncPath:      writeExecutableFixture(t, dir, "runc"),
		PodmanPath:    writeExecutableFixture(t, dir, "podman"),
		NewgidmapPath: writeExecutableFixture(t, dir, "newgidmap"),
		NewuidmapPath: filepath.Join(dir, "missing-newuidmap"),
	}

	_, err := resolveDockerBuildSupport(opts)
	if err == nil {
		t.Fatal("expected missing newuidmap to fail")
	}
	if !strings.Contains(err.Error(), "newuidmap") {
		t.Fatalf("expected error to mention newuidmap, got %v", err)
	}
}

func TestValidateSubordinateIDMappings(t *testing.T) {
	dir := t.TempDir()
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	username := "sandbox-user"
	entry := username + ":100000:65536\n"

	if err := os.WriteFile(subuidPath, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(subgidPath, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := sandboxroot.ValidateSubordinateIDMappingsForUser(username, subuidPath, subgidPath); err != nil {
		t.Fatalf("validate subordinate id mappings failed: %v", err)
	}
}
