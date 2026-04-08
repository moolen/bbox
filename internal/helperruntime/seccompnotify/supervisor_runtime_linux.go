//go:build linux && cgo

package seccompnotify

const (
	maxSockaddrBytes = 128
	ioctlFIONREAD    = 0x541B
)
