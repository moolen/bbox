package seccompnotify

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

type seccompNotifAddFD struct {
	ID         uint64
	Flags      uint32
	SrcFD      uint32
	NewFD      uint32
	NewFDFlags uint32
}

// AddFD issues SECCOMP_IOCTL_NOTIF_ADDFD using the fixed Task 2 signature.
// It currently does not expose kernel-assigned newfd/newfd_flags behavior.
func AddFD(notifyFD int, reqID uint64, srcFD int, newFD uint32, flags uint32, newFDFlags uint32) error {
	_, err := addFDWithResult(notifyFD, reqID, srcFD, newFD, flags, newFDFlags)
	return err
}

func addFDWithResult(notifyFD int, reqID uint64, srcFD int, newFD uint32, flags uint32, newFDFlags uint32) (int, error) {
	if notifyFD < 0 {
		return -1, fmt.Errorf("notify fd must be non-negative")
	}
	if srcFD < 0 {
		return -1, fmt.Errorf("source fd must be non-negative")
	}

	request := seccompNotifAddFD{
		ID:         reqID,
		Flags:      flags,
		SrcFD:      uint32(srcFD),
		NewFD:      newFD,
		NewFDFlags: newFDFlags,
	}

	r1, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifyFD),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_ADDFD),
		uintptr(unsafe.Pointer(&request)),
	)
	if errno != 0 {
		return -1, errno
	}

	if request.NewFD != 0 {
		return int(request.NewFD), nil
	}

	return int(r1), nil
}
