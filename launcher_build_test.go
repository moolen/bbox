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
