//go:build !linux

package embeddedlauncher

import (
	"fmt"
	"runtime"
)

func ForArch(goarch string) ([]byte, error) {
	return nil, fmt.Errorf("embedded launcher is only supported on linux (requested %s)", goarch)
}

func ForRuntimeArch() ([]byte, error) {
	return ForArch(runtime.GOARCH)
}
