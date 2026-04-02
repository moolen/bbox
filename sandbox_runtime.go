package bbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type sandboxRuntime interface {
	Run(context.Context, []string, RunOptions) (*RunResult, error)
	Close() error
	ProxyAddr() string
}

type sandboxRuntimeBootstrap struct {
	runtime sandboxRuntime
	root    string
}

var sandboxPlatform = runtime.GOOS

func (m *ProxyManager) newSandboxRuntime(ctx context.Context, sandboxID string, opts SandboxOptions, mode TrafficMode) (*sandboxRuntimeBootstrap, error) {
	switch sandboxPlatform {
	case "linux":
		return m.newLinuxSandboxRuntime(ctx, sandboxID, opts, mode)
	case "darwin":
		return m.newDarwinSandboxRuntime(ctx, sandboxID, opts, mode)
	default:
		return nil, fmt.Errorf("bbox sandbox is not supported on %s", sandboxPlatform)
	}
}

func openBridgePair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create sandbox bridge socketpair: %w", err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])

	parent := os.NewFile(uintptr(fds[0]), "bbox-bridge-parent")
	child := os.NewFile(uintptr(fds[1]), "bbox-bridge-child")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		}
		if child != nil {
			_ = child.Close()
		}
		return nil, nil, errors.New("wrap sandbox bridge socketpair")
	}
	return parent, child, nil
}
