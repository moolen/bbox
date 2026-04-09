package dockerbuild

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanForArgsTranslatesBasicBuild(t *testing.T) {
	cwd := t.TempDir()
	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"HTTP_PROXY=http://127.0.0.1:31111",
		"HTTPS_PROXY=http://127.0.0.1:31111",
		"NO_PROXY=localhost,127.0.0.1",
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}

	if plan.OutputPath == "" {
		t.Fatal("expected output path to be set")
	}
	if plan.OutputPath != "/var/lib/buildkitd-out/bbox-docker-build.oci.tar" {
		t.Fatalf("unexpected output path: got %q", plan.OutputPath)
	}
	wantContext := filepath.Clean(cwd)
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "context=" + wantContext}) {
		t.Fatalf("expected context path in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "dockerfile=" + wantContext}) {
		t.Fatalf("expected dockerfile path in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "filename=Dockerfile"}) {
		t.Fatalf("expected default Dockerfile in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "build-arg:HTTP_PROXY=http://127.0.0.1:31111"}) {
		t.Fatalf("expected HTTP_PROXY build arg in %v", plan.BuildctlArgs)
	}
	foundOutput := false
	for i := 0; i < len(plan.BuildctlArgs)-1; i++ {
		if plan.BuildctlArgs[i] == "--output" && strings.Contains(plan.BuildctlArgs[i+1], "dest=/var/lib/buildkitd-out/bbox-docker-build.oci.tar") {
			foundOutput = true
			break
		}
	}
	if !foundOutput {
		t.Fatalf("expected buildctl output path in %v", plan.BuildctlArgs)
	}
}

func TestPlanForArgsHonorsDockerfileTagAndBuildArgs(t *testing.T) {
	cwd := t.TempDir()
	plan, err := PlanForArgs([]string{
		"build",
		"-f", "docker/Dockerfile.test",
		"-t", "example:test",
		"--build-arg", "FOO=bar",
		".",
	}, nil, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}

	wantDockerfileDir := filepath.Join(cwd, "docker")
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "dockerfile=" + wantDockerfileDir}) {
		t.Fatalf("expected dockerfile dir in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "filename=Dockerfile.test"}) {
		t.Fatalf("expected dockerfile name in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "build-arg:FOO=bar"}) {
		t.Fatalf("expected custom build arg in %v", plan.BuildctlArgs)
	}
	foundName := false
	for i := 0; i < len(plan.BuildctlArgs)-1; i++ {
		if plan.BuildctlArgs[i] == "--output" && strings.Contains(plan.BuildctlArgs[i+1], "name=example:test") {
			foundName = true
			break
		}
	}
	if !foundName {
		t.Fatalf("expected output name for tag in %v", plan.BuildctlArgs)
	}
}

func TestPlanForArgsRejectsUnsupportedSubcommand(t *testing.T) {
	_, err := PlanForArgs([]string{"run", "alpine"}, nil, t.TempDir())
	if err == nil {
		t.Fatal("expected unsupported subcommand to fail")
	}
}

func TestPlanForArgsUsesAbsoluteContextAndContextRelativeDockerfile(t *testing.T) {
	cwd := t.TempDir()
	plan, err := PlanForArgs([]string{"build", "/workspace/spectre"}, nil, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "context=/workspace/spectre"}) {
		t.Fatalf("expected absolute context in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "dockerfile=/workspace/spectre"}) {
		t.Fatalf("expected default dockerfile dir to follow context in %v", plan.BuildctlArgs)
	}
}

func TestPlanForArgsForwardsTargetStage(t *testing.T) {
	plan, err := PlanForArgs([]string{"build", "--target", "builder", "."}, nil, t.TempDir())
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "target=builder"}) {
		t.Fatalf("expected target stage in %v", plan.BuildctlArgs)
	}
}

func TestPlanForArgsForwardsEqualsTargetStage(t *testing.T) {
	plan, err := PlanForArgs([]string{"build", "--target=builder", "."}, nil, t.TempDir())
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "target=builder"}) {
		t.Fatalf("expected target stage in %v", plan.BuildctlArgs)
	}
}

func TestPlanForArgsInjectsTrustBundleIntoRunStages(t *testing.T) {
	cwd := t.TempDir()
	dockerfilePath := filepath.Join(cwd, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(strings.Join([]string{
		"FROM alpine:3.18 AS builder",
		"RUN echo builder",
		"FROM scratch AS final",
		"COPY --from=builder /tmp/out /tmp/out",
		"FROM busybox:1.36",
		"RUN echo runtime",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	trustBundlePath := filepath.Join(cwd, "bbox-trust.pem")
	if err := os.WriteFile(trustBundlePath, []byte(testTrustBundlePEM), 0o644); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + trustBundlePath,
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	if len(plan.CleanupPaths) == 0 {
		t.Fatal("expected temporary shim inputs to be tracked for cleanup")
	}

	dockerfileLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "dockerfile=")
	if dockerfileLocal == "" {
		t.Fatalf("expected rewritten dockerfile local in %v", plan.BuildctlArgs)
	}
	bboxTrustLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "bbox_mitm_trust=")
	if bboxTrustLocal == "" {
		t.Fatalf("expected trust bundle local context in %v", plan.BuildctlArgs)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--opt", "context:bbox_mitm_trust=local:bbox_mitm_trust"}) {
		t.Fatalf("expected named local context mapping in %v", plan.BuildctlArgs)
	}
	if filepath.Clean(dockerfileLocal) != filepath.Clean(bboxTrustLocal) {
		t.Fatalf("expected wrapper Dockerfile and trust bundle to share staging dir, got dockerfile=%q trust=%q", dockerfileLocal, bboxTrustLocal)
	}

	filename := argValueForOpt(plan.BuildctlArgs, "filename=")
	if filename == "" {
		t.Fatalf("expected rewritten filename in %v", plan.BuildctlArgs)
	}

	rewrittenPath := filepath.Join(dockerfileLocal, filename)
	content, err := os.ReadFile(rewrittenPath)
	if err != nil {
		t.Fatalf("read rewritten Dockerfile %q: %v", rewrittenPath, err)
	}
	got := string(content)
	if strings.Count(got, "COPY --from=bbox_mitm_trust /bbox-trust-bundle.pem /etc/ssl/certs/ca-certificates.crt") != 2 {
		t.Fatalf("expected trust copy into Linux CA bundle for the two RUN stages, got:\n%s", got)
	}
	if strings.Count(got, "ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt") != 2 {
		t.Fatalf("expected SSL_CERT_FILE env injection for the two RUN stages, got:\n%s", got)
	}
	if strings.Count(got, "ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt") != 2 {
		t.Fatalf("expected NODE_EXTRA_CA_CERTS env injection for the two RUN stages, got:\n%s", got)
	}
	if strings.Count(got, "ENV NPM_CONFIG_CAFILE=/etc/ssl/certs/ca-certificates.crt") != 2 {
		t.Fatalf("expected NPM_CONFIG_CAFILE env injection for the two RUN stages, got:\n%s", got)
	}
	if strings.Count(got, "ENV JAVA_TOOL_OPTIONS ") != 2 {
		t.Fatalf("expected JAVA_TOOL_OPTIONS injection only once per stage, got:\n%s", got)
	}
	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-maven-settings.xml /etc/maven/bbox-settings.xml") {
		t.Fatalf("did not expect Maven settings copy without proxy env, got:\n%s", got)
	}
	if strings.Contains(got, "ENV MAVEN_ARGS ") {
		t.Fatalf("did not expect MAVEN_ARGS without proxy env, got:\n%s", got)
	}
	if strings.Contains(got, "FROM scratch AS final\nCOPY --from=bbox_mitm_trust /bbox-trust-bundle.pem") {
		t.Fatalf("did not expect scratch stage without RUN to receive trust injection:\n%s", got)
	}
}

func TestPlanForArgsInjectsTrustBundleBeforeEveryRun(t *testing.T) {
	cwd := t.TempDir()
	dockerfilePath := filepath.Join(cwd, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(strings.Join([]string{
		"FROM alpine:3.18 AS curl-stage",
		"RUN apk add --no-cache ca-certificates curl",
		"RUN curl -fsSL https://example.com/ -o /tmp/out",
		"FROM busybox:1.36",
		"RUN echo runtime",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	trustBundlePath := filepath.Join(cwd, "bbox-trust.pem")
	if err := os.WriteFile(trustBundlePath, []byte(testTrustBundlePEM), 0o644); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + trustBundlePath,
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}

	dockerfileLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "dockerfile=")
	filename := argValueForOpt(plan.BuildctlArgs, "filename=")
	rewrittenPath := filepath.Join(dockerfileLocal, filename)
	content, err := os.ReadFile(rewrittenPath)
	if err != nil {
		t.Fatalf("read rewritten Dockerfile %q: %v", rewrittenPath, err)
	}

	got := string(content)
	expectedPerRunSnippet := trustBundlePerRunInjectionSnippet(trustInjectionOptions{
		pemPath: injectedTrustBundlePrimaryPath,
	})
	expectedStageBootstrap := trustStageBootstrapSnippet(trustInjectionOptions{
		pemPath:            injectedTrustBundlePrimaryPath,
		javaTruststorePath: injectedJavaTruststorePath,
		javaToolOptions:    javaTruststoreOptions(generatedTruststore{Path: "staged", Type: bboxJavaTruststoreType, Password: bboxJavaTruststorePassword}),
	})
	if strings.Count(got, "COPY --from=bbox_mitm_trust /bbox-trust-bundle.pem /etc/ssl/certs/ca-certificates.crt") != 3 {
		t.Fatalf("expected trust copy before each RUN, got:\n%s", got)
	}
	if strings.Count(got, "ENV JAVA_TOOL_OPTIONS ") != 2 {
		t.Fatalf("expected JAVA_TOOL_OPTIONS injection once per stage, got:\n%s", got)
	}
	if strings.Count(got, "ENV MAVEN_ARGS ") != 0 {
		t.Fatalf("did not expect MAVEN_ARGS without proxy env, got:\n%s", got)
	}
	if !strings.Contains(got, expectedStageBootstrap+expectedPerRunSnippet+"RUN apk add --no-cache ca-certificates curl\n") {
		t.Fatalf("expected trust injection immediately before first RUN, got:\n%s", got)
	}
	if !strings.Contains(got, expectedPerRunSnippet+"RUN curl -fsSL https://example.com/ -o /tmp/out\n") {
		t.Fatalf("expected trust injection immediately before second RUN, got:\n%s", got)
	}
	if strings.Contains(got, expectedStageBootstrap+expectedPerRunSnippet+"RUN curl -fsSL https://example.com/ -o /tmp/out\n") {
		t.Fatalf("did not expect JAVA bootstrap snippet before second RUN in same stage, got:\n%s", got)
	}
	if !strings.Contains(got, expectedStageBootstrap+expectedPerRunSnippet+"RUN echo runtime\n") {
		t.Fatalf("expected trust injection immediately before each RUN, got:\n%s", got)
	}
}

func TestPlanForArgsInjectsMavenOnlyOnFirstRunPerStageWhenProxyPresent(t *testing.T) {
	cwd := t.TempDir()
	dockerfilePath := filepath.Join(cwd, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(strings.Join([]string{
		"FROM alpine:3.18",
		"RUN echo one",
		"RUN echo two",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	trustBundlePath := filepath.Join(cwd, "bbox-trust.pem")
	if err := os.WriteFile(trustBundlePath, []byte(testTrustBundlePEM), 0o644); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + trustBundlePath,
		"HTTPS_PROXY=http://127.0.0.1:3128",
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}

	dockerfileLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "dockerfile=")
	filename := argValueForOpt(plan.BuildctlArgs, "filename=")
	rewrittenPath := filepath.Join(dockerfileLocal, filename)
	content, err := os.ReadFile(rewrittenPath)
	if err != nil {
		t.Fatalf("read rewritten Dockerfile %q: %v", rewrittenPath, err)
	}

	got := string(content)
	expectedPerRunSnippet := trustBundlePerRunInjectionSnippet(trustInjectionOptions{
		pemPath: injectedTrustBundlePrimaryPath,
	})
	expectedStageBootstrap := trustStageBootstrapSnippet(trustInjectionOptions{
		javaTruststorePath: injectedJavaTruststorePath,
		javaToolOptions: append(
			javaTruststoreOptions(generatedTruststore{Path: "staged", Type: bboxJavaTruststoreType, Password: bboxJavaTruststorePassword}),
			"-Dhttps.proxyHost=127.0.0.1",
			"-Dhttps.proxyPort=3128",
		),
		mavenSettingsPath: injectedMavenSettingsPath,
	})
	if strings.Count(got, "ENV JAVA_TOOL_OPTIONS ") != 1 {
		t.Fatalf("expected single JAVA_TOOL_OPTIONS injection for one stage, got:\n%s", got)
	}
	if strings.Count(got, "ENV MAVEN_ARGS ") != 1 {
		t.Fatalf("expected single MAVEN_ARGS injection for one stage, got:\n%s", got)
	}
	if !strings.Contains(got, expectedStageBootstrap+expectedPerRunSnippet+"RUN echo one\n") {
		t.Fatalf("expected stage bootstrap before first RUN, got:\n%s", got)
	}
	if !strings.Contains(got, expectedPerRunSnippet+"RUN echo two\n") {
		t.Fatalf("expected per-run trust injection before second RUN, got:\n%s", got)
	}
	if strings.Contains(got, expectedStageBootstrap+expectedPerRunSnippet+"RUN echo two\n") {
		t.Fatalf("did not expect stage bootstrap before second RUN in same stage, got:\n%s", got)
	}
}

func TestPlanForArgsInjectsProxyOnlyMavenBootstrapWithoutTrustBundle(t *testing.T) {
	cwd := t.TempDir()
	dockerfilePath := filepath.Join(cwd, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(strings.Join([]string{
		"FROM maven:3.9.9-eclipse-temurin-21",
		"RUN mvn -v",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + filepath.Join(cwd, "missing-trust-bundle.pem"),
		"HTTPS_PROXY=http://127.0.0.1:3128",
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}

	dockerfileLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "dockerfile=")
	if dockerfileLocal == "" {
		t.Fatalf("expected rewritten dockerfile local in %v", plan.BuildctlArgs)
	}
	bboxTrustLocal := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "bbox_mitm_trust=")
	if bboxTrustLocal == "" {
		t.Fatalf("expected staged local context for Maven settings in %v", plan.BuildctlArgs)
	}

	settingsPath := filepath.Join(bboxTrustLocal, bboxMavenSettingsFileName)
	info, err := os.Stat(settingsPath)
	if err != nil {
		t.Fatalf("expected staged Maven settings without trust bundle: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected staged Maven settings to be non-empty")
	}
	if _, err := os.Stat(filepath.Join(bboxTrustLocal, bboxTrustBundleFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected no staged trust bundle without trust input, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(bboxTrustLocal, bboxJavaTruststoreFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected no staged Java truststore without trust input, got %v", err)
	}

	filename := argValueForOpt(plan.BuildctlArgs, "filename=")
	rewrittenPath := filepath.Join(dockerfileLocal, filename)
	content, err := os.ReadFile(rewrittenPath)
	if err != nil {
		t.Fatalf("read rewritten Dockerfile %q: %v", rewrittenPath, err)
	}

	got := string(content)
	if !strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-maven-settings.xml /etc/maven/bbox-settings.xml") {
		t.Fatalf("expected Maven settings copy without trust bundle, got:\n%s", got)
	}
	if !strings.Contains(got, "ENV MAVEN_ARGS --settings /etc/maven/bbox-settings.xml ${MAVEN_ARGS}") {
		t.Fatalf("expected MAVEN_ARGS injection without trust bundle, got:\n%s", got)
	}
	if !strings.Contains(got, "ENV JAVA_TOOL_OPTIONS -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=3128 ${JAVA_TOOL_OPTIONS}") {
		t.Fatalf("expected proxy-only JAVA_TOOL_OPTIONS injection without trust bundle, got:\n%s", got)
	}
	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-trust-bundle.pem") {
		t.Fatalf("did not expect PEM trust injection without trust bundle, got:\n%s", got)
	}
	if strings.Contains(got, "ENV SSL_CERT_FILE=") {
		t.Fatalf("did not expect SSL_CERT_FILE injection without trust bundle, got:\n%s", got)
	}
}

func TestPlanForArgsDoesNotStartBuildkitd(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	t.Setenv("PATH", t.TempDir())

	plan, err := PlanForArgs([]string{"build", "."}, nil, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	if len(plan.BuildctlArgs) == 0 {
		t.Fatalf("expected plan to include buildctl invocation args, got %#v", plan)
	}
	if !containsArgSequence(plan.BuildctlArgs, []string{"--local", "context=" + cwd}) {
		t.Fatalf("expected context path in plan args, got %v", plan.BuildctlArgs)
	}

	if len(plan.CleanupPaths) != 0 {
		cleanupPaths(plan.CleanupPaths)
	}
}

func TestRunCLIUsesExecutorBuiltFromPlan(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	var gotPlan Plan
	var gotEnv []string
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	oldGetwd := runCLIGetwd
	oldBuild := runCLIExecutorForPlan
	defer func() {
		runCLIGetwd = oldGetwd
		runCLIExecutorForPlan = oldBuild
	}()

	runCLIGetwd = func() (string, error) { return cwd, nil }
	runCLIExecutorForPlan = func(plan Plan, env []string, stdoutWriter io.Writer, stderrWriter io.Writer) cliExecutor {
		gotPlan = plan
		gotEnv = append([]string(nil), env...)
		if stdoutWriter != &stdout {
			t.Fatalf("executor stdout writer = %T, want test buffer", stdoutWriter)
		}
		if stderrWriter != &stderr {
			t.Fatalf("executor stderr writer = %T, want test buffer", stderrWriter)
		}
		return cliExecutorFunc(func() error {
			_, _ = stdoutWriter.Write([]byte("executor ran\n"))
			return nil
		})
	}

	if err := RunCLI([]string{"build", "."}, []string{"PATH=/usr/bin"}, &stdout, &stderr); err != nil {
		t.Fatalf("RunCLI failed: %v", err)
	}
	if gotPlan.OutputPath == "" {
		t.Fatalf("expected plan to be built before executor dispatch, got %#v", gotPlan)
	}
	if !containsArgSequence(gotPlan.BuildctlArgs, []string{"--local", "context=" + cwd}) {
		t.Fatalf("expected context path in executor plan, got %v", gotPlan.BuildctlArgs)
	}
	if !containsEnvEntry(gotEnv, "PATH=/usr/bin") {
		t.Fatalf("expected executor env to include PATH, got %v", gotEnv)
	}
	if got := stdout.String(); !strings.Contains(got, "executor ran") {
		t.Fatalf("expected executor output to be forwarded, got %q", got)
	}
}

func TestWithBuilderRuntimeEnvAddsCgoResolverWhenUnset(t *testing.T) {
	got := withBuilderRuntimeEnv([]string{"PATH=/usr/bin"})
	if !containsEnvEntry(got, "GODEBUG=netdns=cgo") {
		t.Fatalf("expected GODEBUG=netdns=cgo in %v", got)
	}
}

func TestWithBuilderRuntimeEnvAppendsCgoResolverToExistingGODEBUG(t *testing.T) {
	got := withBuilderRuntimeEnv([]string{"PATH=/usr/bin", "GODEBUG=http2client=0"})
	if !containsEnvEntry(got, "GODEBUG=http2client=0,netdns=cgo") {
		t.Fatalf("expected merged GODEBUG in %v", got)
	}
}

func TestWithBuilderRuntimeEnvPreservesExistingNetdnsSetting(t *testing.T) {
	got := withBuilderRuntimeEnv([]string{"PATH=/usr/bin", "GODEBUG=http2client=0,netdns=go"})
	if !containsEnvEntry(got, "GODEBUG=http2client=0,netdns=go") {
		t.Fatalf("expected existing netdns setting in %v", got)
	}
}

func TestWithBuilderRuntimeEnvPreservesProxyEnvByDefault(t *testing.T) {
	got := withBuilderRuntimeEnv([]string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://127.0.0.1:31111",
		"HTTPS_PROXY=http://127.0.0.1:31111",
		"NO_PROXY=localhost",
		"http_proxy=http://127.0.0.1:31111",
		"https_proxy=http://127.0.0.1:31111",
		"no_proxy=localhost",
	})

	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:31111",
		"HTTPS_PROXY=http://127.0.0.1:31111",
		"NO_PROXY=localhost",
		"http_proxy=http://127.0.0.1:31111",
		"https_proxy=http://127.0.0.1:31111",
		"no_proxy=localhost",
		"GODEBUG=netdns=cgo",
	} {
		if !containsEnvEntry(got, want) {
			t.Fatalf("expected %q in %v", want, got)
		}
	}
}

func TestWithBuilderRuntimeEnvDropsProxyEnvWhenOnlyBuildArgsShouldUseProxy(t *testing.T) {
	got := withBuilderRuntimeEnv([]string{
		"PATH=/usr/bin",
		"BBOX_DOCKER_BUILD_PROXY_ARGS_ONLY=1",
		"HTTP_PROXY=http://127.0.0.1:31111",
		"HTTPS_PROXY=http://127.0.0.1:31111",
		"NO_PROXY=localhost",
		"http_proxy=http://127.0.0.1:31111",
		"https_proxy=http://127.0.0.1:31111",
		"no_proxy=localhost",
	})

	if containsEnvKey(got, "HTTP_PROXY") {
		t.Fatalf("expected HTTP_PROXY to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, "HTTPS_PROXY") {
		t.Fatalf("expected HTTPS_PROXY to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, "NO_PROXY") {
		t.Fatalf("expected NO_PROXY to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, "http_proxy") {
		t.Fatalf("expected http_proxy to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, "https_proxy") {
		t.Fatalf("expected https_proxy to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, "no_proxy") {
		t.Fatalf("expected no_proxy to be stripped from builder runtime env: %v", got)
	}
	if containsEnvKey(got, bboxProxyArgsOnlyEnvKey) {
		t.Fatalf("expected internal proxy-only control env to be stripped from builder runtime env: %v", got)
	}
}

func containsArgSequence(args []string, want []string) bool {
	if len(want) == 0 || len(args) < len(want) {
		return false
	}
	for start := 0; start <= len(args)-len(want); start++ {
		match := true
		for i := range want {
			if args[start+i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsEnvEntry(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

func containsEnvKey(env []string, key string) bool {
	for _, entry := range env {
		if strings.HasPrefix(entry, key+"=") {
			return true
		}
	}
	return false
}

func argValueForRepeatedFlag(args []string, flag string, prefix string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] != flag {
			continue
		}
		if strings.HasPrefix(args[i+1], prefix) {
			return strings.TrimPrefix(args[i+1], prefix)
		}
	}
	return ""
}

func argValueForOpt(args []string, prefix string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--opt" {
			continue
		}
		if strings.HasPrefix(args[i+1], prefix) {
			return strings.TrimPrefix(args[i+1], prefix)
		}
	}
	return ""
}

func TestTrustBundleInjectionSnippetIncludesExpandedClientEnv(t *testing.T) {
	const customPEMPath = "/bbox/custom-ca.pem"

	got := trustBundleInjectionSnippet(trustInjectionOptions{
		pemPath: customPEMPath,
	})
	for _, want := range []string{
		"ENV CURL_CA_BUNDLE=/bbox/custom-ca.pem",
		"ENV REQUESTS_CA_BUNDLE=/bbox/custom-ca.pem",
		"ENV PIP_CERT=/bbox/custom-ca.pem",
		"ENV GIT_SSL_CAINFO=/bbox/custom-ca.pem",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestTrustBundleInjectionSnippetInjectsJavaTrustWithoutMaven(t *testing.T) {
	got := trustBundleInjectionSnippet(trustInjectionOptions{
		pemPath:            injectedTrustBundlePrimaryPath,
		javaTruststorePath: injectedJavaTruststorePath,
		javaToolOptions:    javaTruststoreOptions(generatedTruststore{Path: "staged", Type: bboxJavaTruststoreType, Password: bboxJavaTruststorePassword}),
	})

	if !strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-truststore.p12 /etc/ssl/certs/bbox-truststore.p12") {
		t.Fatalf("expected truststore copy in %s", got)
	}
	if !strings.Contains(got, "ENV JAVA_TOOL_OPTIONS -Djavax.net.ssl.trustStore=/etc/ssl/certs/bbox-truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit ${JAVA_TOOL_OPTIONS}") {
		t.Fatalf("expected JAVA_TOOL_OPTIONS truststore config preserving existing values in %s", got)
	}
	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-maven-settings.xml /etc/maven/bbox-settings.xml") {
		t.Fatalf("did not expect Maven settings copy in %s", got)
	}
	if strings.Contains(got, "ENV MAVEN_ARGS ") {
		t.Fatalf("did not expect MAVEN_ARGS injection in %s", got)
	}
}

func TestTrustBundleInjectionSnippetInjectsJavaProxyWithoutTruststore(t *testing.T) {
	got := trustBundleInjectionSnippet(trustInjectionOptions{
		javaToolOptions: []string{
			"-Dhttps.proxyHost=proxy.internal",
			"-Dhttps.proxyPort=8443",
		},
	})

	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-truststore.p12 /etc/ssl/certs/bbox-truststore.p12") {
		t.Fatalf("did not expect truststore copy in %s", got)
	}
	if !strings.Contains(got, "ENV JAVA_TOOL_OPTIONS -Dhttps.proxyHost=proxy.internal -Dhttps.proxyPort=8443 ${JAVA_TOOL_OPTIONS}") {
		t.Fatalf("expected proxy JAVA_TOOL_OPTIONS injection in %s", got)
	}
	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-trust-bundle.pem") {
		t.Fatalf("did not expect PEM trust injection in %s", got)
	}
}

func TestTrustBundleInjectionSnippetInjectsMavenWithoutJavaTrust(t *testing.T) {
	got := trustBundleInjectionSnippet(trustInjectionOptions{
		pemPath:           injectedTrustBundlePrimaryPath,
		mavenSettingsPath: injectedMavenSettingsPath,
	})

	if strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-truststore.p12 /etc/ssl/certs/bbox-truststore.p12") {
		t.Fatalf("did not expect truststore copy in %s", got)
	}
	if strings.Contains(got, "ENV JAVA_TOOL_OPTIONS ") {
		t.Fatalf("did not expect JAVA_TOOL_OPTIONS injection in %s", got)
	}
	if !strings.Contains(got, "COPY --from=bbox_mitm_trust /bbox-maven-settings.xml /etc/maven/bbox-settings.xml") {
		t.Fatalf("expected Maven settings copy in %s", got)
	}
	if !strings.Contains(got, "ENV MAVEN_ARGS --settings /etc/maven/bbox-settings.xml ${MAVEN_ARGS}") {
		t.Fatalf("expected MAVEN_ARGS injection preserving existing values in %s", got)
	}
}
