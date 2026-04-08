package bbox

import (
	"github.com/moolen/bbox/internal/sandboxroot"
)

const (
	defaultSandboxDockerShimPath = sandboxroot.DefaultSandboxDockerShimPath
	defaultSandboxBuildkitdPath  = sandboxroot.DefaultSandboxBuildkitdPath
	defaultSandboxBuildctlPath   = sandboxroot.DefaultSandboxBuildctlPath
	defaultSandboxRuncPath       = sandboxroot.DefaultSandboxRuncPath
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

type BuilderTooling = sandboxroot.BuilderTooling

func resolveDockerBuildSupport(opts DockerBuildOptions) (*BuilderTooling, error) {
	return sandboxroot.ResolveDockerBuildSupport(sandboxroot.DockerBuildOptions{
		Enabled:       opts.Enabled,
		BuildkitdPath: opts.BuildkitdPath,
		BuildctlPath:  opts.BuildctlPath,
		RuncPath:      opts.RuncPath,
		PodmanPath:    opts.PodmanPath,
		NewuidmapPath: opts.NewuidmapPath,
		NewgidmapPath: opts.NewgidmapPath,
	})
}

func validateSubordinateIDMappings() error {
	return sandboxroot.ValidateSubordinateIDMappings()
}

func fileHasSubordinateIDEntry(path string, username string) (bool, error) {
	return sandboxroot.FileHasSubordinateIDEntry(path, username)
}
