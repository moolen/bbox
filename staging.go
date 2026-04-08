package bbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/moolen/bbox/internal/sandboxroot"
)

const defaultSandboxPayloadSeccompPath = "/app/bbox-payload-seccomp.bpf"

func toSandboxrootStageOptions(opts SandboxOptions) sandboxroot.StageOptions {
	return sandboxroot.StageOptions{
		Binaries:    opts.Binaries,
		DockerBuild: toSandboxrootDockerBuildOptions(opts.DockerBuild),
	}
}

func stageTransparentPayloadSeccompProgram(root string, opts SeccompOptions) (string, error) {
	program, err := compileSeccompProgram(opts)
	if err != nil {
		return "", err
	}
	if len(program) == 0 {
		return "", nil
	}

	dest, err := sandboxroot.SandboxPathInRoot(root, defaultSandboxPayloadSeccompPath)
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
