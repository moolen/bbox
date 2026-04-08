package helperruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"
)

var (
	runProxyModeFn       = runProxyMode
	runTransparentModeFn = runTransparentMode
)

// OpenBridgeFromFD adopts the already-open control bridge passed into the
// helper process by the parent launcher.
func OpenBridgeFromFD(fd int) (io.ReadWriteCloser, error) {
	if fd < 0 {
		return nil, fmt.Errorf("bridge fd must be non-negative")
	}

	syscall.CloseOnExec(fd)

	file := os.NewFile(uintptr(fd), fmt.Sprintf("bbox-helper-bridge-%d", fd))
	if file == nil {
		return nil, fmt.Errorf("bridge fd %d is invalid", fd)
	}

	return file, nil
}

// Run is the narrow helper entrypoint. It validates the shared config, applies
// defaults, and dispatches into the selected traffic-mode implementation.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Bridge == nil {
		return fmt.Errorf("bridge is required")
	}
	cfg = withDefaults(cfg)

	switch cfg.TrafficMode {
	case TrafficModeProxy:
		return runProxyModeFn(ctx, cfg)
	case TrafficModeTransparent:
		return runTransparentModeFn(ctx, cfg)
	default:
		return fmt.Errorf("unsupported traffic mode %q", cfg.TrafficMode)
	}
}
