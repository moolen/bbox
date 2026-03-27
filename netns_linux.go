//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func listenInNetNS(pid int, addr string) (net.Listener, error) {
	origin, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, fmt.Errorf("open current netns: %w", err)
	}
	defer origin.Close()

	targetPath := filepath.Join("/proc", fmt.Sprint(pid), "ns/net")
	target, err := os.Open(targetPath)
	if err != nil {
		return nil, fmt.Errorf("open target netns %s: %w", targetPath, err)
	}
	defer target.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, fmt.Errorf("setns target: %w", err)
	}

	listener, listenErr := net.Listen("tcp", addr)
	restoreErr := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET)
	if restoreErr != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return nil, fmt.Errorf("restore original netns: %w", restoreErr)
	}
	if listenErr != nil {
		return nil, fmt.Errorf("listen on %s in child netns: %w", addr, listenErr)
	}

	return listener, nil
}
