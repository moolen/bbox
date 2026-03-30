//go:build !linux || !cgo

package seccompnotify

import (
	"context"
	"fmt"
	"os/exec"
)

func (s *Supervisor) Prepare(_ context.Context, cmd *exec.Cmd) error {
	if cmd == nil {
		return fmt.Errorf("command is required")
	}
	return nil
}

func (s *Supervisor) Start(_ context.Context, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("pid must be positive")
	}
	return nil
}

func (s *Supervisor) Close() error {
	return nil
}
