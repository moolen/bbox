//go:build linux && amd64

package seccompnotify

import "golang.org/x/sys/unix"

const (
	optionalDup2Syscall = unix.SYS_DUP2
	optionalPollSyscall = unix.SYS_POLL
)
