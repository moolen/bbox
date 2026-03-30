//go:build linux && arm64

package seccompnotify

const (
	optionalDup2Syscall = unsupportedSyscall
	optionalPollSyscall = unsupportedSyscall
)
