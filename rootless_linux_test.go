//go:build linux

package bbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moolen/bbox/internal/sandboxroot"
)

func TestBuildLinuxSandboxCommandUsesPodmanUnshareForDockerBuild(t *testing.T) {
	dir := t.TempDir()
	bboxPath := writeExecutableFixture(t, dir, "bbox")
	buildkitdPath := writeExecutableFixture(t, dir, "buildkitd")
	buildctlPath := writeExecutableFixture(t, dir, "buildctl")
	runcPath := writeExecutableFixture(t, dir, "runc")
	podmanPath := writeExecutableFixture(t, dir, "podman")
	newuidmapPath := writeExecutableFixture(t, dir, "newuidmap")
	newgidmapPath := writeExecutableFixture(t, dir, "newgidmap")
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   bboxPath,
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts: SandboxOptions{
			DockerBuild: DockerBuildOptions{
				Enabled:       true,
				BuildkitdPath: buildkitdPath,
				BuildctlPath:  buildctlPath,
				RuncPath:      runcPath,
				PodmanPath:    podmanPath,
				NewuidmapPath: newuidmapPath,
				NewgidmapPath: newgidmapPath,
			},
		},
		mode:       TrafficModeProxy,
		bridgeFD:   3,
		seccompFD:  -1,
		extraFiles: []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if got := filepath.Clean(cmd.Path); got != filepath.Clean(podmanPath) {
		t.Fatalf("unexpected command path: got %q want %q", got, podmanPath)
	}
	if !containsRootlessArgSequence(cmd.Args, []string{"--cgroup-manager=cgroupfs"}) {
		t.Fatalf("expected podman cgroupfs flag in %v", cmd.Args)
	}
	if len(cmd.Args) < 4 || cmd.Args[2] != "unshare" || cmd.Args[3] != "bwrap" {
		t.Fatalf("expected podman unshare bwrap argv, got %v", cmd.Args)
	}
	if containsString(cmd.Args, "--unshare-user") {
		t.Fatalf("did not expect nested --unshare-user under podman unshare, got %v", cmd.Args)
	}
	if !containsRootlessArgSequence(cmd.Args, []string{"--cap-add", "CAP_SYS_ADMIN"}) {
		t.Fatalf("expected CAP_SYS_ADMIN for builder-enabled sandbox, got %v", cmd.Args)
	}
}

func TestBuildLinuxSandboxCommandMountsCgroupForDockerBuild(t *testing.T) {
	dir := t.TempDir()
	bboxPath := writeExecutableFixture(t, dir, "bbox")
	buildkitdPath := writeExecutableFixture(t, dir, "buildkitd")
	buildctlPath := writeExecutableFixture(t, dir, "buildctl")
	runcPath := writeExecutableFixture(t, dir, "runc")
	podmanPath := writeExecutableFixture(t, dir, "podman")
	newuidmapPath := writeExecutableFixture(t, dir, "newuidmap")
	newgidmapPath := writeExecutableFixture(t, dir, "newgidmap")
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   bboxPath,
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts: SandboxOptions{
			DockerBuild: DockerBuildOptions{
				Enabled:       true,
				BuildkitdPath: buildkitdPath,
				BuildctlPath:  buildctlPath,
				RuncPath:      runcPath,
				PodmanPath:    podmanPath,
				NewuidmapPath: newuidmapPath,
				NewgidmapPath: newgidmapPath,
			},
		},
		mode:       TrafficModeProxy,
		bridgeFD:   3,
		seccompFD:  -1,
		extraFiles: []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if !containsRootlessArgSequence(cmd.Args, []string{"--ro-bind", "/sys/fs/cgroup", "/sys/fs/cgroup"}) {
		t.Fatalf("expected builder-enabled sandbox to mount /sys/fs/cgroup, got %v", cmd.Args)
	}
}

func TestBuildLinuxSandboxCommandMountsBuilderStateDirsAsTmpfs(t *testing.T) {
	dir := t.TempDir()
	bboxPath := writeExecutableFixture(t, dir, "bbox")
	buildkitdPath := writeExecutableFixture(t, dir, "buildkitd")
	buildctlPath := writeExecutableFixture(t, dir, "buildctl")
	runcPath := writeExecutableFixture(t, dir, "runc")
	podmanPath := writeExecutableFixture(t, dir, "podman")
	newuidmapPath := writeExecutableFixture(t, dir, "newuidmap")
	newgidmapPath := writeExecutableFixture(t, dir, "newgidmap")
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   bboxPath,
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts: SandboxOptions{
			DockerBuild: DockerBuildOptions{
				Enabled:       true,
				BuildkitdPath: buildkitdPath,
				BuildctlPath:  buildctlPath,
				RuncPath:      runcPath,
				PodmanPath:    podmanPath,
				NewuidmapPath: newuidmapPath,
				NewgidmapPath: newgidmapPath,
			},
		},
		mode:       TrafficModeProxy,
		bridgeFD:   3,
		seccompFD:  -1,
		extraFiles: []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if !containsRootlessArgSequence(cmd.Args, []string{"--tmpfs", "/var/lib/buildkitd"}) {
		t.Fatalf("expected tmpfs buildkit root mount in %v", cmd.Args)
	}
	if !containsRootlessArgSequence(cmd.Args, []string{"--tmpfs", "/var/lib/buildkitd-out"}) {
		t.Fatalf("expected tmpfs build output mount in %v", cmd.Args)
	}
}

func TestBuildLinuxSandboxCommandSkipsBuilderTmpfsWhenUserMountExists(t *testing.T) {
	dir := t.TempDir()
	bboxPath := writeExecutableFixture(t, dir, "bbox")
	buildkitdPath := writeExecutableFixture(t, dir, "buildkitd")
	buildctlPath := writeExecutableFixture(t, dir, "buildctl")
	runcPath := writeExecutableFixture(t, dir, "runc")
	podmanPath := writeExecutableFixture(t, dir, "podman")
	newuidmapPath := writeExecutableFixture(t, dir, "newuidmap")
	newgidmapPath := writeExecutableFixture(t, dir, "newgidmap")
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	outputDir := t.TempDir()
	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   bboxPath,
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts: SandboxOptions{
			Mounts: []Mount{{
				Type:   MountTypeBind,
				Source: outputDir,
				Target: "/var/lib/buildkitd-out",
			}},
			DockerBuild: DockerBuildOptions{
				Enabled:       true,
				BuildkitdPath: buildkitdPath,
				BuildctlPath:  buildctlPath,
				RuncPath:      runcPath,
				PodmanPath:    podmanPath,
				NewuidmapPath: newuidmapPath,
				NewgidmapPath: newgidmapPath,
			},
		},
		mode:       TrafficModeProxy,
		bridgeFD:   3,
		seccompFD:  -1,
		extraFiles: []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if containsRootlessArgSequence(cmd.Args, []string{"--tmpfs", "/var/lib/buildkitd-out"}) {
		t.Fatalf("did not expect tmpfs build output mount when user provided a mount: %v", cmd.Args)
	}
}

func TestBuildLinuxSandboxCommandUsesPlainBwrapWithoutDockerBuild(t *testing.T) {
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   "/app/bbox",
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts:            SandboxOptions{},
		mode:            TrafficModeProxy,
		bridgeFD:        3,
		seccompFD:       -1,
		extraFiles:      []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if got := filepath.Base(cmd.Path); got != "bwrap" {
		t.Fatalf("unexpected command path: got %q want bwrap", got)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != "bwrap" {
		t.Fatalf("expected bwrap argv, got %v", cmd.Args)
	}
	if !containsString(cmd.Args, "--unshare-user") {
		t.Fatalf("expected --unshare-user in %v", cmd.Args)
	}
}

func TestBuildLinuxSandboxCommandUsesProvidedBuilderTooling(t *testing.T) {
	dir := t.TempDir()
	bridgeFile, err := os.CreateTemp(t.TempDir(), "bridge-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridgeFile.Close() })

	podmanPath := writeExecutableFixture(t, dir, "podman")
	cmd, err := buildLinuxSandboxCommand(bwrapCommandConfig{
		runtimeBinary:   "/app/bbox",
		root:            t.TempDir(),
		proxyListenAddr: "127.0.0.1:31111",
		opts: SandboxOptions{
			DockerBuild: DockerBuildOptions{
				Enabled:       true,
				BuildkitdPath: filepath.Join(dir, "missing-buildkitd"),
			},
		},
		builder: &sandboxroot.BuilderTooling{
			PodmanPath: podmanPath,
		},
		mode:       TrafficModeProxy,
		bridgeFD:   3,
		seccompFD:  -1,
		extraFiles: []*os.File{bridgeFile},
	})
	if err != nil {
		t.Fatalf("buildLinuxSandboxCommand failed: %v", err)
	}

	if got := filepath.Clean(cmd.Path); got != filepath.Clean(podmanPath) {
		t.Fatalf("unexpected command path: got %q want %q", got, podmanPath)
	}
}

func containsRootlessArgSequence(args []string, want []string) bool {
	if len(want) == 0 || len(args) < len(want) {
		return false
	}
	for start := 0; start <= len(args)-len(want); start++ {
		match := true
		for i := range want {
			if args[start+i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
