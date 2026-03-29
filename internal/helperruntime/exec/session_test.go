package hrexec

import (
	stdexec "os/exec"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
)

func TestStartExecSessionInteractiveUsesPTY(t *testing.T) {
	session, streams, err := StartSession(stdexec.Command("sh"), helperproto.ExecRequest{
		Interactive: true,
		Terminal:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("expected session")
	}
	if len(streams) == 0 {
		t.Fatal("expected output streams")
	}
	if session.ptyFile == nil {
		t.Fatal("expected PTY-backed session")
	}
	if err := session.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill shell: %v", err)
	}
	_, _ = session.cmd.Process.Wait()
	if err := session.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
}
