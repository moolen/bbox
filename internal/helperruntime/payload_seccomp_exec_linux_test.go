//go:build linux

package helperruntime

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/moolen/bbox/internal/embeddedlauncher"
)

func TestPreparePayloadSeccompExecWrapsCommandWithInternalLauncher(t *testing.T) {
	prevTargetFactory := payloadSeccompExecTargetFactory
	prevBootstrapFactory := payloadSeccompExecBootstrap
	t.Cleanup(func() {
		payloadSeccompExecTargetFactory = prevTargetFactory
		payloadSeccompExecBootstrap = prevBootstrapFactory
	})

	launcherFile, err := os.CreateTemp(t.TempDir(), "launcher-*")
	if err != nil {
		t.Fatalf("create launcher temp file: %v", err)
	}
	t.Cleanup(func() { _ = launcherFile.Close() })

	payloadSeccompExecTargetFactory = func() (embeddedlauncher.ExecTarget, error) {
		return embeddedlauncher.ExecTarget{
			File: launcherFile,
			Close: func() error {
				return launcherFile.Close()
			},
		}, nil
	}
	payloadSeccompExecBootstrap = func() (string, []string, error) {
		return "/app/bbox", []string{"internal-launcher"}, nil
	}

	cmd := exec.Command("/bin/date", "+%s")
	cleanup, err := preparePayloadSeccompExec(cmd, "/app/bbox-payload-seccomp.bpf")
	if err != nil {
		t.Fatalf("preparePayloadSeccompExec() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected cleanup function")
	}

	wantArgs := []string{
		"/app/bbox",
		"internal-launcher",
		"--launcher-fd", "3",
		"--",
		"bbox-seccomp-launcher",
		"--payload-seccomp-bpf", "/app/bbox-payload-seccomp.bpf",
		"/bin/date",
		"--",
		"/bin/date",
		"+%s",
	}
	if got := strings.Join(cmd.Args, "\x00"); got != strings.Join(wantArgs, "\x00") {
		t.Fatalf("wrapped argv = %q, want %q", cmd.Args, wantArgs)
	}
	if cmd.Path != "/app/bbox" {
		t.Fatalf("wrapped path = %q want %q", cmd.Path, "/app/bbox")
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != launcherFile {
		t.Fatalf("wrapped extra files = %#v", cmd.ExtraFiles)
	}
}
