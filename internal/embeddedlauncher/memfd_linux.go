//go:build linux

package embeddedlauncher

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const execMemfdMode = 0o500

type ExecTarget struct {
	Path  string
	File  *os.File
	Args  []string
	Close func() error
}

func (t ExecTarget) PathForChildFD(fd int) string {
	if t.Path != "" {
		return t.Path
	}
	return fmt.Sprintf("/proc/self/fd/%d", fd)
}

var (
	forRuntimeArchPayload = ForRuntimeArch
	memfdCreate           = unix.MemfdCreate
	memfdFchmod           = unix.Fchmod
	memfdFcntlInt         = unix.FcntlInt
	sealExecFD            = sealExecMemfd
)

func OpenExecTarget() (ExecTarget, error) {
	payload, err := forRuntimeArchPayload()
	if err != nil {
		return ExecTarget{}, err
	}

	fd, err := memfdCreate("bbox-seccomp-launcher", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return ExecTarget{}, fmt.Errorf("memfd_create launcher: %w", err)
	}

	file := os.NewFile(uintptr(fd), "bbox-seccomp-launcher")
	if file == nil {
		_ = unix.Close(fd)
		return ExecTarget{}, fmt.Errorf("wrap launcher memfd")
	}

	closeFile := func() error {
		return file.Close()
	}
	defer func() {
		if err != nil {
			_ = closeFile()
		}
	}()

	if err = writeExecMemfd(file, payload); err != nil {
		return ExecTarget{}, fmt.Errorf("write launcher memfd: %w", err)
	}
	if err = memfdFchmod(fd, execMemfdMode); err != nil {
		return ExecTarget{}, fmt.Errorf("chmod launcher memfd: %w", err)
	}
	if err = sealExecFD(fd); err != nil {
		return ExecTarget{}, fmt.Errorf("seal launcher memfd: %w", err)
	}

	return ExecTarget{
		File:  file,
		Close: closeFile,
	}, nil
}

func writeExecMemfd(file *os.File, payload []byte) error {
	for len(payload) > 0 {
		n, err := file.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func sealExecMemfd(fd int) error {
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := memfdFcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		return err
	}
	return nil
}
