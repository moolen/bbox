package dockerbuild

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareBuildInputsStagesJavaTruststoreAndMavenSettings(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "Dockerfile"), []byte("FROM alpine:3.18\nRUN echo test\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	trustBundlePath := filepath.Join(cwd, "bbox-trust.pem")
	if err := os.WriteFile(trustBundlePath, []byte("test trust bundle\n"), 0o644); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}

	plan, err := PlanForArgs([]string{"build", "."}, []string{
		"BBOX_TRUST_BUNDLE_PATH=" + trustBundlePath,
		"HTTPS_PROXY=http://127.0.0.1:3128",
	}, cwd)
	if err != nil {
		t.Fatalf("PlanForArgs failed: %v", err)
	}
	stagingDir := argValueForRepeatedFlag(plan.BuildctlArgs, "--local", "bbox_mitm_trust=")
	if stagingDir == "" {
		t.Fatal("expected trust staging dir")
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "bbox-truststore.p12")); err != nil {
		t.Fatalf("expected staged JVM truststore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "bbox-maven-settings.xml")); err != nil {
		t.Fatalf("expected staged Maven settings: %v", err)
	}
}
