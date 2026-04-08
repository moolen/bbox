package sandboxroot

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
)

const (
	DefaultSandboxDockerShimPath = "/usr/bin/docker"
	DefaultSandboxBuildkitdPath  = "/usr/bin/buildkitd"
	DefaultSandboxBuildctlPath   = "/usr/bin/buildctl"
	DefaultSandboxRuncPath       = "/usr/bin/runc"
)

type DockerBuildOptions struct {
	Enabled       bool
	BuildkitdPath string
	BuildctlPath  string
	RuncPath      string
	PodmanPath    string
	NewuidmapPath string
	NewgidmapPath string
}

type BuilderTooling struct {
	BuildkitdPath string
	BuildctlPath  string
	RuncPath      string
	PodmanPath    string
	NewuidmapPath string
	NewgidmapPath string
}

func ResolveDockerBuildSupport(opts DockerBuildOptions) (*BuilderTooling, error) {
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
		path, err := ResolveBinary(candidate)
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

	if err := ValidateSubordinateIDMappings(); err != nil {
		return nil, err
	}

	return &BuilderTooling{
		BuildkitdPath: buildkitdPath,
		BuildctlPath:  buildctlPath,
		RuncPath:      runcPath,
		PodmanPath:    podmanPath,
		NewuidmapPath: newuidmapPath,
		NewgidmapPath: newgidmapPath,
	}, nil
}

func ValidateSubordinateIDMappings() error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}
	return ValidateSubordinateIDMappingsForUser(currentUser.Username, "/etc/subuid", "/etc/subgid")
}

func ValidateSubordinateIDMappingsForUser(username string, subuidPath string, subgidPath string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("current username is empty")
	}
	for _, path := range []string{subuidPath, subgidPath} {
		ok, err := FileHasSubordinateIDEntry(path, username)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s does not contain an entry for %s", path, username)
		}
	}
	return nil
}

func FileHasSubordinateIDEntry(path string, username string) (bool, error) {
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
