//go:build linux && !amd64 && !arm64

package seccompnotify

const (
	optionalDup2Syscall = unsupportedSyscall
	optionalPollSyscall = unsupportedSyscall
)
