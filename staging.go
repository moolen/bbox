package bbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/moolen/bbox/internal/sandboxroot"
)

const (
	defaultSandboxBBoxPath           = sandboxroot.DefaultSandboxBBoxPath
	defaultSandboxPayloadSeccompPath = "/app/bbox-payload-seccomp.bpf"
)

func resolveBinary(nameOrPath string) (string, error) {
	return sandboxroot.ResolveBinary(nameOrPath)
}

func parseLddOutput(output string) []string {
	return sandboxroot.ParseLddOutput(output)
}

func runtimeFilesForBinary(binaryPath string) ([]string, error) {
	return sandboxroot.RuntimeFilesForBinary(binaryPath)
}

func filesForCommand(commandPath string) ([]string, error) {
	return sandboxroot.FilesForCommand(commandPath)
}

func stageSandboxRoot(opts SandboxOptions, runtimeBinary string, mitmCAPEM []byte, mode TrafficMode) (string, error) {
	result, err := stageSandboxRootWithBuilder(opts, runtimeBinary, mitmCAPEM, mode)
	if err != nil {
		return "", err
	}
	return result.Root, nil
}

func stageSandboxRootWithBuilder(opts SandboxOptions, runtimeBinary string, mitmCAPEM []byte, mode TrafficMode) (sandboxroot.StageResult, error) {
	return sandboxroot.Stage(sandboxroot.StageOptions{
		Binaries: opts.Binaries,
		DockerBuild: sandboxroot.DockerBuildOptions{
			Enabled:       opts.DockerBuild.Enabled,
			BuildkitdPath: opts.DockerBuild.BuildkitdPath,
			BuildctlPath:  opts.DockerBuild.BuildctlPath,
			RuncPath:      opts.DockerBuild.RuncPath,
			PodmanPath:    opts.DockerBuild.PodmanPath,
			NewuidmapPath: opts.DockerBuild.NewuidmapPath,
			NewgidmapPath: opts.DockerBuild.NewgidmapPath,
		},
	}, runtimeBinary, mitmCAPEM, sandboxroot.TrafficMode(mode))
}

func writeDockerBuildShim(root string) error {
	return sandboxroot.WriteDockerBuildShim(root)
}

func writeSandboxConfig(root string, mitmCAPEM []byte, mode TrafficMode) error {
	return sandboxroot.WriteSandboxConfig(root, mitmCAPEM, sandboxroot.TrafficMode(mode))
}

func hostTrustBundleContent() ([]byte, error) {
	return sandboxroot.HostTrustBundleContent()
}

func appendTrustBundlePEM(base []byte, extra []byte) []byte {
	return sandboxroot.AppendTrustBundlePEM(base, extra)
}

func transparentResolvConfContent() (string, error) {
	return sandboxroot.TransparentResolvConfContent()
}

func copyFileIntoRoot(root, hostPath string) error {
	return sandboxroot.CopyFileIntoRoot(root, hostPath)
}

func copyFileToPath(root, hostPath, sandboxPath string) error {
	return sandboxroot.CopyFileToPath(root, hostPath, sandboxPath)
}

func sandboxPathInRoot(root, sandboxPath string) (string, error) {
	return sandboxroot.SandboxPathInRoot(root, sandboxPath)
}

func nssModuleCandidatePaths(module string) []string {
	return sandboxroot.NSSModuleCandidatePaths(module)
}

func firstExistingPath(paths []string) (string, bool) {
	return sandboxroot.FirstExistingPath(paths)
}

func stageTransparentPayloadSeccompProgram(root string, opts SeccompOptions) (string, error) {
	program, err := compileSeccompProgram(opts)
	if err != nil {
		return "", err
	}
	if len(program) == 0 {
		return "", nil
	}

	dest, err := sandboxPathInRoot(root, defaultSandboxPayloadSeccompPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(dest), err)
	}
	if err := os.WriteFile(dest, program, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", dest, err)
	}
	return defaultSandboxPayloadSeccompPath, nil
}
