//go:build linux

package launcherentrypoint

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

var execLauncherFromFD = execveatLauncherFromFD

type launcherFlags struct {
	launcherFD int
}

func parseFlags(args []string) (launcherFlags, []string, error) {
	var parsed launcherFlags
	fs := flag.NewFlagSet("bbox-internal-launcher", flag.ContinueOnError)
	fs.IntVar(&parsed.launcherFD, "launcher-fd", 3, "file descriptor carrying the embedded launcher image")
	if err := fs.Parse(args); err != nil {
		return parsed, nil, err
	}
	if parsed.launcherFD < 0 {
		return parsed, nil, fmt.Errorf("launcher fd must be non-negative")
	}
	launcherArgv := fs.Args()
	if len(launcherArgv) == 0 {
		return parsed, nil, fmt.Errorf("launcher argv is required after --")
	}
	return parsed, launcherArgv, nil
}

func Run(args []string) error {
	parsed, launcherArgv, err := parseFlags(args)
	if err != nil {
		return err
	}
	return execLauncherFromFD(parsed.launcherFD, launcherArgv, os.Environ())
}

func execveatLauncherFromFD(fd int, argv, env []string) error {
	if fd < 0 {
		return fmt.Errorf("launcher fd must be non-negative")
	}
	if len(argv) == 0 {
		return fmt.Errorf("launcher argv is required")
	}

	argvPtrs, argvKeepalive, err := cStringArray(argv)
	if err != nil {
		return err
	}
	envPtrs, envKeepalive, err := cStringArray(env)
	if err != nil {
		return err
	}
	emptyPath := []byte{0}

	_, _, errno := unix.Syscall6(
		unix.SYS_EXECVEAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&emptyPath[0])),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envPtrs[0])),
		uintptr(unix.AT_EMPTY_PATH),
		0,
	)

	runtime.KeepAlive(argvPtrs)
	runtime.KeepAlive(argvKeepalive)
	runtime.KeepAlive(envPtrs)
	runtime.KeepAlive(envKeepalive)
	runtime.KeepAlive(emptyPath)

	if errno != 0 {
		return errno
	}
	return nil
}

func cStringArray(values []string) ([]*byte, []*byte, error) {
	ptrs := make([]*byte, 0, len(values)+1)
	keepalive := make([]*byte, 0, len(values))
	for _, value := range values {
		ptr, err := unix.BytePtrFromString(value)
		if err != nil {
			return nil, nil, err
		}
		ptrs = append(ptrs, ptr)
		keepalive = append(keepalive, ptr)
	}
	ptrs = append(ptrs, nil)
	return ptrs, keepalive, nil
}
