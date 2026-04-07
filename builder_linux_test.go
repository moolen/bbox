//go:build linux

package bbox

import (
	"path/filepath"
	"strings"
	"testing"
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
