package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/moolen/bbox/internal/dockerbuild"
	"github.com/moolen/bbox/internal/helperentrypoint"
	"github.com/moolen/bbox/internal/launcherentrypoint"
)

type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("process exited with code %d", e.code)
}

func main() {
	err := dispatch(os.Args[1:], commandDeps{
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		getwd:   os.Getwd,
		environ: os.Environ,
		run:     runSandbox,
	}, helperentrypoint.Run, launcherentrypoint.Run, dockerbuild.RunCLI)
	if err != nil {
		var exitErr exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// dispatch owns top-level entrypoint routing only. User-facing CLI parsing
// stays in the root command, while helper, launcher, and docker-build shims
// remain injected internal entrypoints.
func dispatch(args []string, deps commandDeps, runHelper func([]string) error, runLauncher func([]string) error, runDockerBuild func([]string, []string, io.Writer, io.Writer) error) error {
	if runHelper != nil && len(args) > 0 && args[0] == "internal-helper" {
		return runHelper(args[1:])
	}
	if runLauncher != nil && len(args) > 0 && args[0] == "internal-launcher" {
		return runLauncher(args[1:])
	}
	if runDockerBuild != nil && len(args) > 0 && args[0] == "internal-docker-build" {
		return runDockerBuild(args[1:], os.Environ(), deps.stdout, deps.stderr)
	}

	cmd := newRootCommand(deps)
	cmd.SetArgs(args)
	return cmd.Execute()
}
