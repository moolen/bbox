//go:build linux

package seccompnotify

import "golang.org/x/sys/unix"

const unsupportedSyscall = -1

func isDupLikeSyscall(syscallNum int) bool {
	if syscallNum == unix.SYS_DUP || syscallNum == unix.SYS_DUP3 || syscallNum == unix.SYS_FCNTL {
		return true
	}
	return optionalDup2Syscall >= 0 && syscallNum == optionalDup2Syscall
}

func isPollSyscall(syscallNum int) bool {
	return optionalPollSyscall >= 0 && syscallNum == optionalPollSyscall
}

func managedNotifySyscallNames() []string {
	names := []string{
		"socket",
		"connect",
		"sendto",
		"recvfrom",
		"sendmsg",
		"recvmsg",
		"sendmmsg",
		"recvmmsg",
		"ppoll",
		"close",
		"dup",
		"dup3",
		"fcntl",
	}
	if optionalPollSyscall >= 0 {
		names = append(names[:8], append([]string{"poll"}, names[8:]...)...)
	}
	if optionalDup2Syscall >= 0 {
		names = append(names[:12], append([]string{"dup2"}, names[12:]...)...)
	}
	return names
}
