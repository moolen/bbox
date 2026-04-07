package dockerbuild

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Plan struct {
	BuildctlArgs []string
	OutputPath   string
}

const (
	buildkitSocketPath = "/tmp/bbox-buildkitd.sock"
	buildkitRootPath   = "/tmp/bbox-buildkitd-root"
	buildkitLogPath    = "/tmp/bbox-buildkitd.log"
)

func PlanForArgs(args []string, env []string, cwd string) (Plan, error) {
	if len(args) == 0 {
		return Plan{}, fmt.Errorf("docker subcommand is required")
	}
	if args[0] != "build" {
		return Plan{}, fmt.Errorf("unsupported docker subcommand %q", args[0])
	}

	contextPath := "."
	dockerfilePath := "Dockerfile"
	targetStage := ""
	var tags []string
	var buildArgs []string

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-f", "--file":
			i++
			if i >= len(args) {
				return Plan{}, fmt.Errorf("%s requires a value", arg)
			}
			dockerfilePath = args[i]
		case "-t", "--tag":
			i++
			if i >= len(args) {
				return Plan{}, fmt.Errorf("%s requires a value", arg)
			}
			tags = append(tags, args[i])
		case "--build-arg":
			i++
			if i >= len(args) {
				return Plan{}, fmt.Errorf("--build-arg requires a value")
			}
			buildArgs = append(buildArgs, args[i])
		case "--target":
			i++
			if i >= len(args) {
				return Plan{}, fmt.Errorf("--target requires a value")
			}
			targetStage = args[i]
		default:
			if strings.HasPrefix(arg, "--build-arg=") {
				buildArgs = append(buildArgs, strings.TrimPrefix(arg, "--build-arg="))
				continue
			}
			if strings.HasPrefix(arg, "--target=") {
				targetStage = strings.TrimPrefix(arg, "--target=")
				if strings.TrimSpace(targetStage) == "" {
					return Plan{}, fmt.Errorf("--target requires a value")
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return Plan{}, fmt.Errorf("unsupported docker build flag %q", arg)
			}
			contextPath = arg
		}
	}

	contextAbs, err := absFromCWD(cwd, contextPath)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve build context: %w", err)
	}
	if dockerfilePath == "Dockerfile" {
		dockerfilePath = filepath.Join(contextAbs, dockerfilePath)
	}
	dockerfileAbs, err := absFromCWD(cwd, dockerfilePath)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve dockerfile path: %w", err)
	}
	dockerfileDir := filepath.Dir(dockerfileAbs)
	dockerfileName := filepath.Base(dockerfileAbs)

	outputName := "bbox-build"
	if len(tags) > 0 {
		outputName = tags[0]
	}
	outputPath := filepath.Join(cwd, ".bbox-docker-build.oci.tar")

	buildctlArgs := []string{
		"build",
		"--progress=plain",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + contextAbs,
		"--local", "dockerfile=" + dockerfileDir,
		"--opt", "filename=" + dockerfileName,
	}

	for _, buildArg := range append(buildArgs, proxyBuildArgsFromEnv(env)...) {
		buildctlArgs = append(buildctlArgs, "--opt", "build-arg:"+buildArg)
	}
	if targetStage != "" {
		buildctlArgs = append(buildctlArgs, "--opt", "target="+targetStage)
	}

	buildctlArgs = append(buildctlArgs, "--output", "type=oci,dest="+outputPath+",name="+outputName)

	return Plan{
		BuildctlArgs: buildctlArgs,
		OutputPath:   outputPath,
	}, nil
}

func proxyBuildArgsFromEnv(env []string) []string {
	keys := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",
		"http_proxy",
		"https_proxy",
		"no_proxy",
	}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := lookupEnvValue(env, key); ok {
			values = append(values, key+"="+value)
		}
	}
	return values
}

func lookupEnvValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix), true
		}
	}
	return "", false
}

func absFromCWD(cwd string, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Abs(filepath.Join(cwd, path))
}

func RunCLI(args []string, env []string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current working directory: %w", err)
	}

	plan, err := PlanForArgs(args, env, cwd)
	if err != nil {
		return err
	}
	if err := ensureBuildkitd(env); err != nil {
		return err
	}

	buildctlArgs := append([]string{"--addr", "unix://" + buildkitSocketPath}, plan.BuildctlArgs...)
	cmd := exec.Command("buildctl", buildctlArgs...)
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "bbox docker build output: %s\n", plan.OutputPath)
	return nil
}

func ensureBuildkitd(env []string) error {
	if buildkitdReady() {
		return nil
	}
	_ = os.Remove(buildkitSocketPath)
	if err := os.MkdirAll(buildkitRootPath, 0o755); err != nil {
		return fmt.Errorf("create buildkit root: %w", err)
	}

	logFile, err := os.OpenFile(buildkitLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open buildkit log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(
		"buildkitd",
		"--rootless",
		"--addr", "unix://"+buildkitSocketPath,
		"--root", buildkitRootPath,
		"--oci-worker-snapshotter=native",
		"--oci-worker-no-process-sandbox",
	)
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start buildkitd: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if buildkitdReady() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("buildkitd did not become ready; see %s", buildkitLogPath)
}

func buildkitdReady() bool {
	conn, err := net.DialTimeout("unix", buildkitSocketPath, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
