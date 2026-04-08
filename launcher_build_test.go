package bbox

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestGeneratedEmbeddedLaunchersRecordCurrentInputs(t *testing.T) {
	moduleRoot, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}

	sourceHash, err := fileSHA256(filepath.Join(moduleRoot, "cmd/bbox-seccomp-launcher/main.c"))
	if err != nil {
		t.Fatalf("hash launcher source: %v", err)
	}
	scriptHash, err := fileSHA256(filepath.Join(moduleRoot, "scripts/generate-embedded-launchers.sh"))
	if err != nil {
		t.Fatalf("hash generator script: %v", err)
	}

	for _, name := range []string{
		"internal/embeddedlauncher/generated_linux_amd64.go",
		"internal/embeddedlauncher/generated_linux_arm64.go",
	} {
		path := filepath.Join(moduleRoot, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(content)
		if !strings.Contains(text, "// Launcher source SHA256: "+sourceHash) {
			t.Fatalf("%s does not record current launcher source hash", name)
		}
		if !strings.Contains(text, "// Generator script SHA256: "+scriptHash) {
			t.Fatalf("%s does not record current generator script hash", name)
		}
	}
}

func TestArchitectureScriptDoesNotRequireRipgrep(t *testing.T) {
	moduleRoot, err := packageRoot()
	if err != nil {
		t.Fatal(err)
	}

	toolDir := t.TempDir()
	for _, name := range []string{"bash", "dirname", "git", "go", "grep", "sort"} {
		target, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s not available", name)
		}
		if err := os.Symlink(target, filepath.Join(toolDir, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}

	cmd := exec.Command("bash", "./scripts/check-architecture.sh")
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "PATH="+toolDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run architecture script without rg in PATH: %v\n%s", err, output)
	}
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
