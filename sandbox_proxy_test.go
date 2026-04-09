package bbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProxySandboxCanRunDateWithDefaultSeccomp(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("proxy sandbox integration test requires linux")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}

	datePath, err := exec.LookPath("date")
	if err != nil {
		t.Skip("date not available")
	}

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sandbox, err := manager.NewSandbox(ctx, SandboxOptions{
		Binaries: []string{datePath},
		WorkDir:  "/tmp",
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{datePath}, RunOptions{})
	if err != nil {
		t.Fatalf("run date: %v helperlog=%q", err, sandbox.helperLogContents())
	}
	if result.ExitCode != 0 {
		t.Fatalf("date exit=%d stdout=%q stderr=%q helperlog=%q", result.ExitCode, string(result.Stdout), string(result.Stderr), sandbox.helperLogContents())
	}
}

func TestProxySandboxCanCreateThreadsWithDefaultSeccomp(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("proxy sandbox integration test requires linux")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}

	probePath, probeDir := buildPthreadProbe(t)
	sandboxProbeDir := "/opt/pthread-probe"
	sandboxProbePath := filepath.Join(sandboxProbeDir, filepath.Base(probePath))

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sandbox, err := manager.NewSandbox(ctx, SandboxOptions{
		Binaries: []string{probePath},
		Mounts: []Mount{
			{Type: MountTypeBind, Source: probeDir, Target: sandboxProbeDir, ReadOnly: true},
		},
		WorkDir: "/tmp",
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{sandboxProbePath}, RunOptions{})
	if err != nil {
		t.Fatalf("run pthread probe: %v helperlog=%q", err, sandbox.helperLogContents())
	}
	if result.ExitCode != 0 {
		t.Fatalf("pthread probe exit=%d stdout=%q stderr=%q helperlog=%q", result.ExitCode, string(result.Stdout), string(result.Stderr), sandbox.helperLogContents())
	}
	if got := strings.TrimSpace(string(result.Stdout)); got != "pthread-ok" {
		t.Fatalf("unexpected pthread probe stdout=%q stderr=%q helperlog=%q", got, string(result.Stderr), sandbox.helperLogContents())
	}
}

func buildPthreadProbe(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "pthread_probe.c")
	source := `#include <errno.h>
#include <pthread.h>
#include <stdio.h>

static void* run(void* arg) {
  return arg;
}

int main(void) {
  pthread_t thread;
  int rc = pthread_create(&thread, NULL, run, NULL);
  if (rc != 0) {
    errno = rc;
    perror("pthread_create");
    return 2;
  }
  pthread_join(thread, NULL);
  puts("pthread-ok");
  return 0;
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write pthread probe source: %v", err)
	}

	binaryPath := filepath.Join(dir, "pthread-probe")
	cmd := exec.Command("cc", "-O2", "-pthread", "-o", binaryPath, sourcePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build pthread probe: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return binaryPath, dir
}
