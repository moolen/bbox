package bbox

import "github.com/moolen/bbox/internal/sandboxroot"

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

func toSandboxrootDockerBuildOptions(opts DockerBuildOptions) sandboxroot.DockerBuildOptions {
	return sandboxroot.DockerBuildOptions{
		Enabled:       opts.Enabled,
		BuildkitdPath: opts.BuildkitdPath,
		BuildctlPath:  opts.BuildctlPath,
		RuncPath:      opts.RuncPath,
		PodmanPath:    opts.PodmanPath,
		NewuidmapPath: opts.NewuidmapPath,
		NewgidmapPath: opts.NewgidmapPath,
	}
}
