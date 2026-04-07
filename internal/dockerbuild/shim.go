package dockerbuild

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type Plan struct {
	BuildctlArgs []string
	OutputPath   string
	CleanupPaths []string
}

const (
	buildkitSocketPath      = "/tmp/bbox-buildkitd.sock"
	buildkitRootPath        = "/tmp/bbox-buildkitd-root"
	buildkitLogPath         = "/tmp/bbox-buildkitd.log"
	bboxTrustBundleEnvKey   = "BBOX_TRUST_BUNDLE_PATH"
	bboxProxyArgsOnlyEnvKey = "BBOX_DOCKER_BUILD_PROXY_ARGS_ONLY"
	bboxTrustContextName    = "bbox_mitm_trust"
	bboxTrustBundleFileName = "bbox-trust-bundle.pem"
)

var injectedTrustBundleDestinations = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

const injectedTrustBundlePrimaryPath = "/etc/ssl/certs/ca-certificates.crt"
const injectedJavaTruststorePath = "/etc/ssl/certs/bbox-truststore.p12"
const injectedMavenSettingsPath = "/etc/maven/bbox-settings.xml"

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
	outputPath := filepath.Join(cwd, ".bbox-docker-build.oci.tar")
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

func hasProxyEnvConfigured(env []string) bool {
	keys := []string{
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"http_proxy",
		"https_proxy",
	}
	for _, key := range keys {
		value, ok := lookupEnvValue(env, key)
		if !ok {
			continue
		}
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

type buildInputs struct {
	ContextDir     string
	DockerfileDir  string
	DockerfileName string
	ExtraLocals    []string
	FrontendOpts   []string
	CleanupPaths   []string
	Truststore     generatedTruststore
	MavenSettings  string
}

type trustInjectionOptions struct {
	pemPath            string
	javaTruststorePath string
	javaTruststoreType string
	javaTruststorePass string
	mavenSettingsPath  string
}

func prepareBuildInputs(contextAbs string, dockerfileAbs string, env []string) (buildInputs, error) {
	inputs := buildInputs{
		ContextDir:     contextAbs,
		DockerfileDir:  filepath.Dir(dockerfileAbs),
		DockerfileName: filepath.Base(dockerfileAbs),
	}

	trustBundlePath, ok := resolveTrustBundlePath(env)
	if !ok {
		return inputs, nil
	}
	if _, err := os.Stat(dockerfileAbs); err != nil {
		if os.IsNotExist(err) {
			return inputs, nil
		}
		return buildInputs{}, fmt.Errorf("stat dockerfile %s: %w", dockerfileAbs, err)
	}

	original, err := os.ReadFile(dockerfileAbs)
	if err != nil {
		return buildInputs{}, fmt.Errorf("read dockerfile %s: %w", dockerfileAbs, err)
	}
	rewrittenWithPEMOnly, err := rewriteDockerfileWithTrustBundle(original, trustInjectionOptions{
		pemPath: injectedTrustBundlePrimaryPath,
	})
	if err != nil {
		return buildInputs{}, fmt.Errorf("rewrite dockerfile %s for trust injection: %w", dockerfileAbs, err)
	}
	if bytes.Equal(rewrittenWithPEMOnly, original) {
		return inputs, nil
	}

	trustBundle, err := os.ReadFile(trustBundlePath)
	if err != nil {
		return buildInputs{}, fmt.Errorf("read trust bundle %s: %w", trustBundlePath, err)
	}

	stageDir, err := os.MkdirTemp("", "bbox-build-inputs-")
	if err != nil {
		return buildInputs{}, fmt.Errorf("create build input staging dir: %w", err)
	}

	rewrittenPath := filepath.Join(stageDir, filepath.Base(dockerfileAbs))
	if err := os.WriteFile(filepath.Join(stageDir, bboxTrustBundleFileName), trustBundle, 0o644); err != nil {
		_ = os.RemoveAll(stageDir)
		return buildInputs{}, fmt.Errorf("write staged trust bundle: %w", err)
	}
	if len(trustBundle) > 0 {
		truststore, err := writePKCS12Truststore(stageDir, trustBundle)
		if err != nil {
			_ = os.RemoveAll(stageDir)
			return buildInputs{}, fmt.Errorf("write staged JVM truststore: %w", err)
		}
		inputs.Truststore = truststore
		if hasProxyEnvConfigured(env) {
			settingsPath, err := writeMavenSettings(stageDir, truststore)
			if err != nil {
				_ = os.RemoveAll(stageDir)
				return buildInputs{}, fmt.Errorf("write staged Maven settings: %w", err)
			}
			inputs.MavenSettings = settingsPath
		}
	}

	trustInjection := trustInjectionOptionsFromStagedAssets(inputs)
	rewritten, err := rewriteDockerfileWithTrustBundle(original, trustInjection)
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return buildInputs{}, fmt.Errorf("rewrite dockerfile %s for trust injection: %w", dockerfileAbs, err)
	}
	if err := os.WriteFile(rewrittenPath, rewritten, 0o644); err != nil {
		_ = os.RemoveAll(stageDir)
		return buildInputs{}, fmt.Errorf("write rewritten dockerfile %s: %w", rewrittenPath, err)
	}

	inputs.DockerfileDir = stageDir
	inputs.DockerfileName = filepath.Base(rewrittenPath)
	inputs.ExtraLocals = append(inputs.ExtraLocals, bboxTrustContextName+"="+stageDir)
	inputs.FrontendOpts = append(inputs.FrontendOpts, "context:"+bboxTrustContextName+"=local:"+bboxTrustContextName)
	inputs.CleanupPaths = append(inputs.CleanupPaths, stageDir)
	return inputs, nil
}

func trustInjectionOptionsFromStagedAssets(inputs buildInputs) trustInjectionOptions {
	opts := trustInjectionOptions{
		pemPath: injectedTrustBundlePrimaryPath,
	}
	if strings.TrimSpace(inputs.Truststore.Path) != "" &&
		strings.TrimSpace(inputs.Truststore.Type) != "" &&
		strings.TrimSpace(inputs.Truststore.Password) != "" {
		if _, err := os.Stat(inputs.Truststore.Path); err == nil {
			opts.javaTruststorePath = injectedJavaTruststorePath
			opts.javaTruststoreType = inputs.Truststore.Type
			opts.javaTruststorePass = inputs.Truststore.Password
		}
	}
	if strings.TrimSpace(inputs.MavenSettings) != "" {
		if _, err := os.Stat(inputs.MavenSettings); err == nil {
			opts.mavenSettingsPath = injectedMavenSettingsPath
		}
	}
	return opts
}

func resolveTrustBundlePath(env []string) (string, bool) {
	if value, ok := lookupEnvValue(env, bboxTrustBundleEnvKey); ok {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", false
		}
		if _, err := os.Stat(value); err == nil {
			return value, true
		}
		return "", false
	}

	const defaultTrustBundlePath = "/etc/ssl/certs/ca-certificates.crt"
	if _, err := os.Stat(defaultTrustBundlePath); err == nil {
		return defaultTrustBundlePath, true
	}
	return "", false
}

func rewriteDockerfileWithTrustBundle(content []byte, opts trustInjectionOptions) ([]byte, error) {
	result, err := parser.Parse(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	if result == nil || result.AST == nil {
		return append([]byte(nil), content...), nil
	}

	injectBeforeLine := make(map[int]struct{})
	injectStageBootstrapBeforeLine := make(map[int]struct{})
	currentStageSawRun := false
	for _, child := range result.AST.Children {
		instruction := strings.ToLower(strings.TrimSpace(child.Value))
		if instruction == "from" {
			currentStageSawRun = false
		}
		if instruction == "run" && child.StartLine > 0 {
			injectBeforeLine[child.StartLine] = struct{}{}
			if !currentStageSawRun {
				injectStageBootstrapBeforeLine[child.StartLine] = struct{}{}
				currentStageSawRun = true
			}
		}
	}
	if len(injectBeforeLine) == 0 {
		return append([]byte(nil), content...), nil
	}

	lines := strings.SplitAfter(string(content), "\n")
	if len(lines) == 0 {
		lines = []string{string(content)}
	}

	var out strings.Builder
	for i, line := range lines {
		lineNo := i + 1
		if _, ok := injectStageBootstrapBeforeLine[lineNo]; ok {
			out.WriteString(trustStageBootstrapSnippet(opts))
		}
		if _, ok := injectBeforeLine[lineNo]; ok {
			out.WriteString(trustBundlePerRunInjectionSnippet(opts))
		}
		out.WriteString(line)
	}

	return []byte(out.String()), nil
}

func trustBundleInjectionSnippet(opts ...trustInjectionOptions) string {
	return trustStageBootstrapSnippet(opts...) + trustBundlePerRunInjectionSnippet(opts...)
}

func trustBundlePerRunInjectionSnippet(opts ...trustInjectionOptions) string {
	injection := trustInjectionOptions{
		pemPath: injectedTrustBundlePrimaryPath,
	}
	if len(opts) > 0 {
		injection = opts[0]
		if strings.TrimSpace(injection.pemPath) == "" {
			injection.pemPath = injectedTrustBundlePrimaryPath
		}
	}

	var b strings.Builder
	for _, dest := range injectedTrustBundleDestinations {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxTrustBundleFileName, dest)
	}
	fmt.Fprintf(&b, "ENV SSL_CERT_FILE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV NODE_EXTRA_CA_CERTS=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV NPM_CONFIG_CAFILE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV CURL_CA_BUNDLE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV REQUESTS_CA_BUNDLE=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV PIP_CERT=%s\n", injection.pemPath)
	fmt.Fprintf(&b, "ENV GIT_SSL_CAINFO=%s\n", injection.pemPath)
	return b.String()
}

func trustStageBootstrapSnippet(opts ...trustInjectionOptions) string {
	injection := trustInjectionOptions{}
	if len(opts) > 0 {
		injection = opts[0]
	}

	var b strings.Builder
	if strings.TrimSpace(injection.javaTruststorePath) != "" {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxJavaTruststoreFileName, injection.javaTruststorePath)
	}
	if strings.TrimSpace(injection.javaTruststorePath) != "" &&
		strings.TrimSpace(injection.javaTruststoreType) != "" &&
		strings.TrimSpace(injection.javaTruststorePass) != "" {
		fmt.Fprintf(
			&b,
			"ENV JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=%s -Djavax.net.ssl.trustStorePassword=%s ${JAVA_TOOL_OPTIONS}\n",
			injection.javaTruststorePath,
			injection.javaTruststoreType,
			injection.javaTruststorePass,
		)
	}
	if strings.TrimSpace(injection.mavenSettingsPath) != "" {
		fmt.Fprintf(&b, "COPY --from=%s /%s %s\n", bboxTrustContextName, bboxMavenSettingsFileName, injection.mavenSettingsPath)
		fmt.Fprintf(&b, "ENV MAVEN_ARGS=--settings %s ${MAVEN_ARGS}\n", injection.mavenSettingsPath)
	}
	return b.String()
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
	defer cleanupPaths(plan.CleanupPaths)
	_ = os.Remove(plan.OutputPath)
	builderEnv := withBuilderRuntimeEnv(env)
	if err := ensureBuildkitd(builderEnv); err != nil {
		return err
	}

	buildctlArgs := append([]string{"--addr", "unix://" + buildkitSocketPath}, plan.BuildctlArgs...)
	cmd := exec.Command("buildctl", buildctlArgs...)
	cmd.Env = builderEnv
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		_ = os.Remove(plan.OutputPath)
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

func withBuilderRuntimeEnv(env []string) []string {
	out := filterBuilderControlEnv(env)
	if value, ok := lookupEnvValue(env, bboxProxyArgsOnlyEnvKey); ok && strings.TrimSpace(value) == "1" {
		out = filterBuilderProxyEnv(out)
	}
	godebug, ok := lookupEnvValue(out, "GODEBUG")
	if !ok || strings.TrimSpace(godebug) == "" {
		return append(out, "GODEBUG=netdns=cgo")
	}
	if strings.Contains(godebug, "netdns=") {
		return out
	}
	return append(out, "GODEBUG="+godebug+",netdns=cgo")
}

func buildkitdReady() bool {
	conn, err := net.DialTimeout("unix", buildkitSocketPath, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func filterBuilderProxyEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnvEntry(entry)
		if !ok {
			continue
		}
		switch key {
		case "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy":
			continue
		default:
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func filterBuilderControlEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := splitEnvEntry(entry)
		if !ok {
			continue
		}
		if key == bboxProxyArgsOnlyEnvKey {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func splitEnvEntry(entry string) (string, string, bool) {
	if entry == "" {
		return "", "", false
	}
	split := strings.IndexByte(entry, '=')
	if split < 0 {
		return entry, "", true
	}
	return entry[:split], entry[split+1:], true
}

func javaProxyOptionsFromEnv(env []string) ([]string, error) {
	return nil, fmt.Errorf("java proxy options are not implemented")
}

func cleanupPaths(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		_ = os.RemoveAll(path)
	}
}
