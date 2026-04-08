//go:build linux && cgo

package seccompnotify

import seccomp "github.com/seccomp/libseccomp-golang"

func minChildFDForSocketKind(kind SocketKind) int {
	if kind == KindUDP {
		return minManagedUDPChildFD
	}
	return minManagedTCPChildFD
}

func minDupFDForState(state SocketState, requestedMin int) int {
	if state.Kind == KindUDP && requestedMin < minManagedUDPChildFD {
		return minManagedUDPChildFD
	}
	return requestedMin
}

func (s *Supervisor) reserveChildFD(kind SocketKind, requestedMin int) int {
	if s == nil {
		return -1
	}

	s.childFDMu.Lock()
	defer s.childFDMu.Unlock()

	minFD := minChildFDForSocketKind(kind)
	if requestedMin > minFD {
		minFD = requestedMin
	}

	next := s.nextTCPChildFD
	if kind == KindUDP {
		next = s.nextUDPChildFD
	}
	if next < minFD {
		next = minFD
	}

	for fd := next; fd < next+4096; fd++ {
		if _, ok := s.reservedChildFDs[fd]; ok {
			continue
		}
		s.reservedChildFDs[fd] = struct{}{}
		if kind == KindUDP {
			s.nextUDPChildFD = fd + 1
		} else {
			s.nextTCPChildFD = fd + 1
		}
		return fd
	}
	return -1
}

func (s *Supervisor) releaseChildFD(fd int) {
	if s == nil || fd < 0 {
		return
	}
	s.childFDMu.Lock()
	delete(s.reservedChildFDs, fd)
	s.childFDMu.Unlock()
}

func (s *Supervisor) lookupManagedUDPSocket(pid int, req *seccomp.ScmpNotifReq) (SocketState, bool) {
	if s == nil || req == nil {
		return SocketState{}, false
	}
	childFD := int(req.Data.Args[0])
	if childFD < 0 {
		return SocketState{}, false
	}
	state, ok := s.registry.LookupForPID(pid, childFD)
	if !ok || state.Kind != KindUDP {
		return SocketState{}, false
	}
	return state, true
}
