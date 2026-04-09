//go:build linux

package helperruntime

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/moolen/bbox/internal/embeddedlauncher"
)

const payloadSeccompBootstrapPath = "/app/bbox"

var (
	payloadSeccompExecTargetFactory = embeddedlauncher.OpenExecTarget
	payloadSeccompExecBootstrap     = func() (string, []string, error) {
		return payloadSeccompBootstrapPath, []string{"internal-launcher"}, nil
	}
)

func preparePayloadSeccompExec(cmd *exec.Cmd, payloadSeccompBPFPath string) (func() error, error) {
	if payloadSeccompBPFPath == "" {
		return nil, nil
	}
	if cmd == nil {
		return nil, fmt.Errorf("command is required")
	}
	if cmd.Path == "" {
		return nil, fmt.Errorf("command path is required")
	}

	target, err := payloadSeccompExecTargetFactory()
	if err != nil {
		return nil, err
	}
	closeTarget := func() error {
		if target.Close != nil {
			return target.Close()
		}
		if target.File != nil {
			return target.File.Close()
		}
		return nil
	}

	originalPath := cmd.Path
	originalArgs := append([]string(nil), cmd.Args...)
	if len(originalArgs) == 0 {
		originalArgs = []string{originalPath}
	}

	if target.File != nil {
		bootstrapPath, bootstrapArgs, err := payloadSeccompExecBootstrap()
		if err != nil {
			_ = closeTarget()
			return nil, err
		}
		launcherFD := 3 + len(cmd.ExtraFiles)
		cmd.ExtraFiles = append(cmd.ExtraFiles, target.File)
		launcherArgv := []string{
			"bbox-seccomp-launcher",
			"--payload-seccomp-bpf", payloadSeccompBPFPath,
		}
		launcherArgv = append(launcherArgv, target.Args...)
		launcherArgv = append(launcherArgv, originalPath, "--")
		launcherArgv = append(launcherArgv, originalArgs...)
		cmd.Path = bootstrapPath
		cmd.Args = append(
			append(
				append([]string{bootstrapPath}, bootstrapArgs...),
				"--launcher-fd", strconv.Itoa(launcherFD), "--",
			),
			launcherArgv...,
		)
		return closeTarget, nil
	}

	launcherArgs := append([]string(nil), target.Args...)
	launcherArgs = append(launcherArgs, "--payload-seccomp-bpf", payloadSeccompBPFPath)
	cmd.Path = target.Path
	cmd.Args = append(
		append(
			append([]string{target.Path}, launcherArgs...),
			originalPath, "--",
		),
		originalArgs...,
	)
	return closeTarget, nil
}
