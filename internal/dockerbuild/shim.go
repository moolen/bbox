package dockerbuild

import (
	"fmt"
	"io"
	"os"
)

var runCLIGetwd = os.Getwd
var runCLIExecutorForPlan = func(plan Plan, env []string, stdout io.Writer, stderr io.Writer) cliExecutor {
	return newBuildkitExecutor(plan, env, stdout, stderr)
}

// RunCLI is the docker-build entrypoint shim. It resolves cwd, builds a
// concrete plan, and hands execution to the buildkit-backed executor.
func RunCLI(args []string, env []string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cwd, err := runCLIGetwd()
	if err != nil {
		return fmt.Errorf("resolve current working directory: %w", err)
	}

	plan, err := PlanForArgs(args, env, cwd)
	if err != nil {
		return err
	}
	defer cleanupPaths(plan.CleanupPaths)
	return runCLIExecutorForPlan(plan, env, stdout, stderr).Run()
}
