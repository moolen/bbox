package dockerbuild

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moolen/bbox/internal/dockerbuildpaths"
)

type Plan struct {
	BuildctlArgs []string
	OutputPath   string
	CleanupPaths []string
}

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
	outputName := "bbox-build"
	if len(tags) > 0 {
		outputName = tags[0]
	}
	outputPath := dockerbuildpaths.DefaultBuildOutputPath
	inputs, err := prepareBuildInputs(contextAbs, dockerfileAbs, env)
	if err != nil {
		return Plan{}, err
	}

	buildctlArgs := []string{
		"build",
		"--progress=plain",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + inputs.ContextDir,
		"--local", "dockerfile=" + inputs.DockerfileDir,
		"--opt", "filename=" + inputs.DockerfileName,
	}
	for _, local := range inputs.ExtraLocals {
		buildctlArgs = append(buildctlArgs, "--local", local)
	}
	for _, opt := range inputs.FrontendOpts {
		buildctlArgs = append(buildctlArgs, "--opt", opt)
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
		CleanupPaths: inputs.CleanupPaths,
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
