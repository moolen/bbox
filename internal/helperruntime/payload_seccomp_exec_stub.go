//go:build !linux

package helperruntime

import (
	"fmt"
	"os/exec"
)

func preparePayloadSeccompExec(_ *exec.Cmd, payloadSeccompBPFPath string) (func() error, error) {
	if payloadSeccompBPFPath == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("payload seccomp launcher is only supported on linux")
}
