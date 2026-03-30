//go:build linux && cgo

package seccompnotify

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
)

type FilterArtifacts struct {
	Filter          *seccomp.ScmpFilter
	ManagedSyscalls map[string]seccomp.ScmpSyscall
}

func (f *FilterArtifacts) Release() {
	if f == nil || f.Filter == nil {
		return
	}
	f.Filter.Release()
	f.Filter = nil
}

func BuildFilter() (*FilterArtifacts, error) {
	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("create seccomp notify filter: %w", err)
	}

	managedSyscalls := []string{
		"socket",
		"connect",
		"sendto",
		"recvfrom",
		"sendmsg",
		"recvmsg",
		"sendmmsg",
		"recvmmsg",
		"poll",
		"ppoll",
		"close",
		"dup",
		"dup2",
		"dup3",
		"fcntl",
	}

	artifacts := &FilterArtifacts{
		Filter:          filter,
		ManagedSyscalls: make(map[string]seccomp.ScmpSyscall, len(managedSyscalls)),
	}
	for _, name := range managedSyscalls {
		syscallNum, err := seccomp.GetSyscallFromName(name)
		if err != nil {
			artifacts.Release()
			return nil, fmt.Errorf("resolve syscall %q: %w", name, err)
		}
		if err := filter.AddRule(syscallNum, seccomp.ActNotify); err != nil {
			artifacts.Release()
			return nil, fmt.Errorf("add seccomp notify rule for %q: %w", name, err)
		}
		artifacts.ManagedSyscalls[name] = syscallNum
	}

	return artifacts, nil
}
