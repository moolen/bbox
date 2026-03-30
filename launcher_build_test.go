package bbox

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSeccompLauncherBuildsForLinuxARM64(t *testing.T) {
	compiler, err := exec.LookPath("aarch64-linux-gnu-gcc")
	if err != nil {
		t.Skip("aarch64-linux-gnu-gcc not available")
	}

	moduleRoot, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bbox-seccomp-launcher")
	cmd := exec.Command(compiler, "-O2", "-o", out, "./cmd/bbox-seccomp-launcher/main.c")
	cmd.Dir = moduleRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile launcher for linux/arm64: %v\n%s", err, output)
	}
}

func TestGeneratedEmbeddedLaunchersAreUpToDate(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}
	if _, err := exec.LookPath("aarch64-linux-gnu-gcc"); err != nil {
		t.Skip("aarch64-linux-gnu-gcc not available")
	}

	moduleRoot, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("./scripts/generate-embedded-launchers.sh", "--verify")
	cmd.Dir = moduleRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify generated embedded launchers: %v\n%s", err, output)
	}
}
