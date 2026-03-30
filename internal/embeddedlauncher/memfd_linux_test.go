//go:build linux

package embeddedlauncher

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenExecMemfdCreatesExecutableTarget(t *testing.T) {
	payload := []byte{0x7f, 0x45, 0x4c, 0x46}

	backingFile, err := os.CreateTemp(t.TempDir(), "embedded-launcher-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	t.Cleanup(func() {
		_ = backingFile.Close()
	})

	prevPayloadLookup := forRuntimeArchPayload
	prevMemfdCreate := memfdCreate
	prevMemfdFchmod := memfdFchmod
	prevSealExecFD := sealExecFD
	t.Cleanup(func() {
		forRuntimeArchPayload = prevPayloadLookup
		memfdCreate = prevMemfdCreate
		memfdFchmod = prevMemfdFchmod
		sealExecFD = prevSealExecFD
	})

	forRuntimeArchPayload = func() ([]byte, error) {
		return append([]byte(nil), payload...), nil
	}
	memfdCreate = func(name string, flags int) (int, error) {
		fd, err := unix.Dup(int(backingFile.Fd()))
		if err != nil {
			return -1, err
		}
		return fd, nil
	}

	var chmodFD int
	var chmodMode uint32
	memfdFchmod = func(fd int, mode uint32) error {
		chmodFD = fd
		chmodMode = mode
		return nil
	}

	sealedFD := -1
	sealExecFD = func(fd int) error {
		sealedFD = fd
		return nil
	}

	target, err := OpenExecTarget()
	if err != nil {
		t.Fatalf("OpenExecTarget() error = %v", err)
	}
	t.Cleanup(func() {
		_ = target.Close()
	})

	if target.File == nil {
		t.Fatal("OpenExecTarget() returned nil file")
	}
	if got := target.PathForChildFD(7); got != "/proc/self/fd/7" {
		t.Fatalf("PathForChildFD(7) = %q, want %q", got, "/proc/self/fd/7")
	}
	if chmodFD != int(target.File.Fd()) {
		t.Fatalf("chmod fd = %d, want %d", chmodFD, target.File.Fd())
	}
	if chmodMode != 0o500 {
		t.Fatalf("chmod mode = %#o, want %#o", chmodMode, 0o500)
	}
	if sealedFD != int(target.File.Fd()) {
		t.Fatalf("sealed fd = %d, want %d", sealedFD, target.File.Fd())
	}

	if _, err := backingFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek backing file: %v", err)
	}
	gotPayload, err := io.ReadAll(backingFile)
	if err != nil {
		t.Fatalf("read backing file: %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %x, want %x", gotPayload, payload)
	}
}

func TestSealExecMemfdAddsExpectedSeals(t *testing.T) {
	prevFcntlInt := memfdFcntlInt
	t.Cleanup(func() {
		memfdFcntlInt = prevFcntlInt
	})

	called := false
	memfdFcntlInt = func(fd uintptr, cmd int, arg int) (int, error) {
		called = true
		if fd != 17 {
			t.Fatalf("fd = %d, want 17", fd)
		}
		if cmd != unix.F_ADD_SEALS {
			t.Fatalf("cmd = %d, want %d", cmd, unix.F_ADD_SEALS)
		}
		wantSeals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
		if arg != wantSeals {
			t.Fatalf("arg = %#x, want %#x", arg, wantSeals)
		}
		return 0, nil
	}

	if err := sealExecMemfd(17); err != nil {
		t.Fatalf("sealExecMemfd(17) error = %v", err)
	}
	if !called {
		t.Fatal("expected sealExecMemfd to invoke fcntl")
	}
}
