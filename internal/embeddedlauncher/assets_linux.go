package embeddedlauncher

import (
	"fmt"
	"runtime"
)

func ForArch(goarch string) ([]byte, error) {
	switch goarch {
	case "amd64":
		return payloadForArch(goarch, launcherLinuxAMD64)
	case "arm64":
		return payloadForArch(goarch, launcherLinuxARM64)
	default:
		return nil, fmt.Errorf("unsupported launcher arch %q", goarch)
	}
}

func ForRuntimeArch() ([]byte, error) {
	return ForArch(runtime.GOARCH)
}

func payloadForArch(goarch string, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("unsupported launcher arch %q", goarch)
	}
	return append([]byte(nil), payload...), nil
}
