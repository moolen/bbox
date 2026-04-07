package dockerbuild

import (
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
