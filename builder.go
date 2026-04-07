package bbox

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
)

const (
	defaultSandboxDockerShimPath = "/usr/bin/docker"
	defaultSandboxBuildkitdPath  = "/usr/bin/buildkitd"
	defaultSandboxBuildctlPath   = "/usr/bin/buildctl"
	defaultSandboxRuncPath       = "/usr/bin/runc"
)

// DockerBuildOptions enables the in-sandbox docker-build compatibility path.
// The path fields are optional overrides primarily intended for tests and
// explicit host tool selection.
type DockerBuildOptions struct {
	Enabled       bool
	BuildkitdPath string
	BuildctlPath  string
	RuncPath      string
	PodmanPath    string
	NewuidmapPath string
	NewgidmapPath string
}

type dockerBuildSupport struct {
	buildkitdPath string
	buildctlPath  string
	runcPath      string
	podmanPath    string
	newuidmapPath string
	newgidmapPath string
}

func resolveDockerBuildSupport(opts DockerBuildOptions) (*dockerBuildSupport, error) {
	if !opts.Enabled {
		return nil, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("docker build sandbox support is only available on linux")
	}

	resolve := func(override string, fallback string, label string) (string, error) {
		candidate := strings.TrimSpace(override)
		if candidate == "" {
			candidate = fallback
		}
		path, err := resolveBinary(candidate)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", label, err)
		}
		return path, nil
	}

	buildkitdPath, err := resolve(opts.BuildkitdPath, "buildkitd", "buildkitd")
	if err != nil {
		return nil, err
	}
	buildctlPath, err := resolve(opts.BuildctlPath, "buildctl", "buildctl")
	if err != nil {
		return nil, err
	}
	runcPath, err := resolve(opts.RuncPath, "runc", "runc")
	if err != nil {
		return nil, err
	}
	podmanPath, err := resolve(opts.PodmanPath, "podman", "podman")
	if err != nil {
		return nil, err
	}
	newuidmapPath, err := resolve(opts.NewuidmapPath, "newuidmap", "newuidmap")
	if err != nil {
		return nil, err
	}
	newgidmapPath, err := resolve(opts.NewgidmapPath, "newgidmap", "newgidmap")
	if err != nil {
		return nil, err
	}

	if err := validateSubordinateIDMappings(); err != nil {
		return nil, err
	}

	return &dockerBuildSupport{
		buildkitdPath: buildkitdPath,
		buildctlPath:  buildctlPath,
		runcPath:      runcPath,
		podmanPath:    podmanPath,
		newuidmapPath: newuidmapPath,
		newgidmapPath: newgidmapPath,
	}, nil
}

func validateSubordinateIDMappings() error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}
	if currentUser.Username == "" {
		return fmt.Errorf("current username is empty")
	}

	for _, path := range []string{"/etc/subuid", "/etc/subgid"} {
		ok, err := fileHasSubordinateIDEntry(path, currentUser.Username)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s does not contain an entry for %s", path, currentUser.Username)
		}
	}
	return nil
}

func fileHasSubordinateIDEntry(path string, username string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	prefix := username + ":"
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, prefix) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan %s: %w", path, err)
	}
	return false, nil
}
