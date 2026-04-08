//go:build linux && cgo

package seccompnotify

import (
	"errors"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func (s *Supervisor) processNotification(pid int, req *seccomp.ScmpNotifReq) *seccomp.ScmpNotifResp {
	if req == nil {
		return errorResp(0, unix.EINVAL)
	}
	if notificationTraceHook != nil {
		notificationTraceHook(req)
	}
	targetPID := notificationPID(pid, req)

	switch int(req.Data.Syscall) {
	case unix.SYS_SOCKET:
		fd, managed, err := s.injectSocket(req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !managed {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(fd))
	case unix.SYS_CONNECT:
		handled, err := s.redirectConnect(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, 0)
	case unix.SYS_GETPEERNAME:
		handled, err := s.emulateGetpeername(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, 0)
	case unix.SYS_READ:
		n, handled, err := s.emulateDNSRead(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_SENDTO:
		n, handled, err := s.emulateDNSSendTo(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_WRITE:
		n, handled, err := s.emulateDNSWrite(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVFROM:
		n, handled, err := s.emulateDNSRecvFrom(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_SENDMSG:
		n, handled, err := s.emulateDNSSendMsg(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVMSG:
		n, handled, err := s.emulateDNSRecvMsg(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_SENDMMSG:
		n, handled, err := s.emulateDNSSendMMsg(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVMMSG:
		n, handled, err := s.emulateDNSRecvMMsg(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_PPOLL:
		n, handled, err := s.emulateDNSPPoll(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_IOCTL:
		handled, err := s.emulateDNSIoctl(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, 0)
	case unix.SYS_CLOSE:
		fd := int(req.Data.Args[0])
		if fd >= 0 {
			s.registry.CloseForPID(targetPID, fd)
			s.releaseChildFD(fd)
		}
		return continueResp(req.ID)
	case unix.SYS_DUP, unix.SYS_DUP3, unix.SYS_FCNTL:
		fd, handled, err := s.duplicateSocket(targetPID, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(fd))
	default:
		if isPollSyscall(int(req.Data.Syscall)) {
			n, handled, err := s.emulateDNSPoll(targetPID, req)
			if err != nil {
				return errorResp(req.ID, errnoFromError(err))
			}
			if !handled {
				return continueResp(req.ID)
			}
			return successResp(req.ID, uint64(n))
		}
		if isDupLikeSyscall(int(req.Data.Syscall)) {
			fd, handled, err := s.duplicateSocket(targetPID, req)
			if err != nil {
				return errorResp(req.ID, errnoFromError(err))
			}
			if !handled {
				return continueResp(req.ID)
			}
			return successResp(req.ID, uint64(fd))
		}
		return continueResp(req.ID)
	}
}

func notificationPID(fallback int, req *seccomp.ScmpNotifReq) int {
	if req != nil && req.Pid > 0 {
		return int(req.Pid)
	}
	return fallback
}

func (s *Supervisor) injectSocket(req *seccomp.ScmpNotifReq) (int, bool, error) {
	if s == nil || req == nil {
		return -1, false, unix.EINVAL
	}

	family := int(req.Data.Args[0])
	socketType := int(req.Data.Args[1])
	protocol := int(req.Data.Args[2])

	kind, managed, err := classifyManagedSocket(s.targets, family, socketType, protocol)
	if err != nil {
		return -1, false, err
	}
	if !managed {
		return -1, false, nil
	}

	helperFD, err := unix.Socket(family, socketType, protocol)
	if err != nil {
		return -1, false, err
	}

	childFD := -1
	for {
		childFD = s.reserveChildFD(kind, minChildFDForSocketKind(kind))
		if childFD < 0 {
			_ = unix.Close(helperFD)
			return -1, false, unix.EMFILE
		}
		_, err = s.addFDWithResult(req.ID, helperFD, uint32(childFD), unix.SECCOMP_ADDFD_FLAG_SETFD, 0)
		if err == nil {
			break
		}
		s.releaseChildFD(childFD)
		if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(helperFD)
			return -1, false, err
		}
	}

	pid := notificationPID(0, req)
	s.registry.CloseForPID(pid, childFD)
	s.registry.InsertForPID(pid, SocketState{
		ChildPID:   pid,
		Kind:       kind,
		ChildFD:    childFD,
		HelperFD:   helperFD,
		Family:     family,
		SocketType: socketType,
		Protocol:   protocol,
		Blocking:   socketType&unix.SOCK_NONBLOCK == 0,
	})
	return childFD, true, nil
}

func (s *Supervisor) redirectConnect(pid int, req *seccomp.ScmpNotifReq) (bool, error) {
	if s == nil || req == nil {
		return false, unix.EINVAL
	}

	childFD := int(req.Data.Args[0])
	state, ok := s.registry.LookupForPID(pid, childFD)
	if !ok {
		return false, nil
	}

	addrPtr := uintptr(req.Data.Args[1])
	addrLen := int(req.Data.Args[2])
	if addrPtr == 0 || addrLen <= 0 || addrLen > maxSockaddrBytes {
		return false, unix.EINVAL
	}

	rawAddr, err := readProcessMemory(pid, addrPtr, addrLen)
	if err != nil {
		return false, err
	}
	decoded, err := DecodeSockaddr(rawAddr)
	if err != nil {
		return false, err
	}
	if decoded.Family == unix.AF_UNSPEC {
		if state.Kind == KindUDP {
			return false, s.handleDNSDisconnect(childFD, state)
		}
		return false, nil
	}

	switch state.Kind {
	case KindTCP:
		if err := s.handleConnect(connectRequest{ChildFD: childFD, Destination: decoded}); err != nil {
			return true, err
		}
		updated, ok := s.registry.LookupForPID(pid, childFD)
		if !ok {
			return true, unix.EBADF
		}
		if err := s.reinstallConnectedSocket(req.ID, updated); err != nil {
			return true, err
		}
		return true, nil
	case KindUDP:
		if decoded.Port != 53 {
			s.registry.CloseForPID(pid, childFD)
			s.releaseChildFD(childFD)
			return false, nil
		}
		return true, s.handleDNSConnect(childFD, state, decoded)
	default:
		return false, nil
	}
}

func (s *Supervisor) reinstallConnectedSocket(notifID uint64, state SocketState) error {
	if s == nil {
		return unix.EINVAL
	}
	if state.ChildFD < 0 || state.HelperFD < 0 {
		return unix.EBADF
	}

	newFDFlags := uint32(0)
	if state.SocketType&unix.SOCK_CLOEXEC != 0 {
		newFDFlags = unix.O_CLOEXEC
	}
	_, err := s.addFDWithResult(notifID, state.HelperFD, uint32(state.ChildFD), unix.SECCOMP_ADDFD_FLAG_SETFD, newFDFlags)
	return err
}

func (s *Supervisor) emulateGetpeername(pid int, req *seccomp.ScmpNotifReq) (bool, error) {
	if s == nil || req == nil {
		return true, unix.EINVAL
	}

	childFD := int(req.Data.Args[0])
	if childFD < 0 {
		return true, unix.EBADF
	}
	state, ok := s.registry.LookupForPID(pid, childFD)
	if !ok {
		return false, nil
	}
	if state.OriginalHost == "" || state.OriginalPort <= 0 {
		return true, unix.ENOTCONN
	}

	return true, writeSockaddr(pid, uintptr(req.Data.Args[1]), uintptr(req.Data.Args[2]), DecodedSockaddr{
		Family: peernameFamily(state.OriginalHost, state.Family),
		Host:   state.OriginalHost,
		Port:   state.OriginalPort,
	})
}

func (s *Supervisor) emulateDNSIoctl(pid int, req *seccomp.ScmpNotifReq) (bool, error) {
	state, ok := s.lookupManagedUDPSocket(pid, req)
	if !ok {
		return false, nil
	}
	if uintptr(req.Data.Args[1]) != ioctlFIONREAD {
		return false, nil
	}

	argPtr := uintptr(req.Data.Args[2])
	if argPtr == 0 {
		return true, unix.EFAULT
	}

	pendingBytes := int32(0)
	if len(state.PendingDNSResponses) > 0 {
		pendingBytes = int32(len(state.PendingDNSResponses[0].Payload))
	}
	return true, writeProcessValue(pid, argPtr, pendingBytes)
}

func (s *Supervisor) handleDNSConnect(childFD int, state SocketState, destination DecodedSockaddr) error {
	if s == nil {
		return unix.EINVAL
	}
	if s.targets.DNSRoundTrip == nil {
		return unix.EHOSTUNREACH
	}

	state.ChildFD = childFD
	state.DNSManaged = true
	state.ConnectedHost = destination.Host
	state.ConnectedPort = destination.Port
	state.OriginalHost = destination.Host
	state.OriginalPort = destination.Port
	state.RedirectAddr = ""
	s.registry.Insert(state)
	return nil
}

func (s *Supervisor) handleDNSDisconnect(childFD int, state SocketState) error {
	if s == nil {
		return unix.EINVAL
	}

	state.ChildFD = childFD
	state.DNSManaged = false
	state.ConnectedHost = ""
	state.ConnectedPort = 0
	state.OriginalHost = ""
	state.OriginalPort = 0
	state.RedirectAddr = ""
	s.registry.Insert(state)
	return nil
}

func classifyManagedSocket(targets RuntimeTargets, family, socketType, protocol int) (SocketKind, bool, error) {
	if !isManagedSocketFamily(family) {
		return KindUnknown, false, nil
	}
	switch baseSocketType(socketType) {
	case unix.SOCK_STREAM:
		if !targetsSupportFamilyIngress(targets, family) {
			return KindUnknown, false, nil
		}
		return KindTCP, true, nil
	case unix.SOCK_DGRAM:
		if protocol != 0 && protocol != unix.IPPROTO_UDP {
			return KindUnknown, false, nil
		}
		if targets.DNSRoundTrip == nil {
			return KindUnknown, false, unix.EHOSTUNREACH
		}
		return KindUDP, true, nil
	default:
		return KindUnknown, false, nil
	}
}

func (s *Supervisor) duplicateSocket(pid int, req *seccomp.ScmpNotifReq) (int, bool, error) {
	if s == nil || req == nil {
		return -1, false, unix.EINVAL
	}

	oldFD := int(req.Data.Args[0])
	if oldFD < 0 {
		return -1, false, unix.EBADF
	}
	state, ok := s.registry.LookupForPID(pid, oldFD)
	if !ok {
		return -1, false, nil
	}

	switch int(req.Data.Syscall) {
	case unix.SYS_DUP:
		minFD := minDupFDForState(state, 0)
		if minFD <= oldFD {
			minFD = oldFD + 1
		}
		childFD, err := s.addFDAtOrAbove(req.ID, state.HelperFD, minFD, 0)
		if err != nil {
			return -1, false, err
		}
		if err := s.registry.DupForPID(pid, oldFD, childFD); err != nil {
			return -1, false, err
		}
		return childFD, true, nil
	case unix.SYS_DUP3:
		newFD := int(req.Data.Args[1])
		if newFD < 0 {
			return -1, false, unix.EBADF
		}
		if oldFD == newFD {
			return oldFD, true, nil
		}
		newFDFlags := uint32(0)
		if int(req.Data.Syscall) == unix.SYS_DUP3 && int(req.Data.Args[2])&unix.O_CLOEXEC != 0 {
			newFDFlags = unix.O_CLOEXEC
		}
		childFD, err := s.addFDWithResult(req.ID, state.HelperFD, uint32(newFD), unix.SECCOMP_ADDFD_FLAG_SETFD, newFDFlags)
		if err != nil {
			return -1, false, err
		}
		if err := s.registry.DupForPID(pid, oldFD, childFD); err != nil {
			return -1, false, err
		}
		return childFD, true, nil
	case unix.SYS_FCNTL:
		cmd := int(req.Data.Args[1])
		minFD := int(req.Data.Args[2])
		switch cmd {
		case unix.F_DUPFD:
			minFD = minDupFDForState(state, minFD)
			if minFD <= oldFD {
				minFD = oldFD + 1
			}
			childFD, err := s.addFDAtOrAbove(req.ID, state.HelperFD, minFD, 0)
			if err != nil {
				return -1, false, err
			}
			if err := s.registry.DupForPID(pid, oldFD, childFD); err != nil {
				return -1, false, err
			}
			return childFD, true, nil
		case unix.F_DUPFD_CLOEXEC:
			minFD = minDupFDForState(state, minFD)
			if minFD <= oldFD {
				minFD = oldFD + 1
			}
			childFD, err := s.addFDAtOrAbove(req.ID, state.HelperFD, minFD, unix.O_CLOEXEC)
			if err != nil {
				return -1, false, err
			}
			if err := s.registry.DupForPID(pid, oldFD, childFD); err != nil {
				return -1, false, err
			}
			return childFD, true, nil
		default:
			return -1, false, nil
		}
	default:
		if optionalDup2Syscall >= 0 && int(req.Data.Syscall) == optionalDup2Syscall {
			newFD := int(req.Data.Args[1])
			if newFD < 0 {
				return -1, false, unix.EBADF
			}
			if oldFD == newFD {
				return oldFD, true, nil
			}
			childFD, err := s.addFDWithResult(req.ID, state.HelperFD, uint32(newFD), unix.SECCOMP_ADDFD_FLAG_SETFD, 0)
			if err != nil {
				return -1, false, err
			}
			if err := s.registry.DupForPID(pid, oldFD, childFD); err != nil {
				return -1, false, err
			}
			return childFD, true, nil
		}
		return -1, false, nil
	}
}

func (s *Supervisor) addFDAtOrAbove(reqID uint64, srcFD int, minFD int, newFDFlags uint32) (int, error) {
	if minFD < 0 {
		minFD = 0
	}
	for fd := minFD; fd < minFD+4096; fd++ {
		childFD, err := s.addFDWithResult(reqID, srcFD, uint32(fd), unix.SECCOMP_ADDFD_FLAG_SETFD, newFDFlags)
		if err == nil {
			return childFD, nil
		}
		if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
			continue
		}
		return -1, err
	}
	return -1, unix.EMFILE
}

func (s *Supervisor) addFDWithResult(reqID uint64, srcFD int, newFD uint32, flags uint32, newFDFlags uint32) (int, error) {
	if s == nil {
		return -1, unix.EINVAL
	}
	s.notifyFDIOMu.Lock()
	defer s.notifyFDIOMu.Unlock()
	return addFDWithResult(s.notifyFD, reqID, srcFD, newFD, flags, newFDFlags)
}

func readProcessMemory(pid int, addr uintptr, size int) ([]byte, error) {
	if pid <= 0 || addr == 0 || size < 0 {
		return nil, unix.EINVAL
	}
	if size == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, size)
	local := []unix.Iovec{{Base: &buf[0]}}
	local[0].SetLen(size)
	remote := []unix.RemoteIovec{{Base: addr, Len: size}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func successResp(id uint64, val uint64) *seccomp.ScmpNotifResp {
	return &seccomp.ScmpNotifResp{ID: id, Error: 0, Val: val}
}

func continueResp(id uint64) *seccomp.ScmpNotifResp {
	return &seccomp.ScmpNotifResp{ID: id, Error: 0, Flags: seccomp.NotifRespFlagContinue}
}

func errorResp(id uint64, errno unix.Errno) *seccomp.ScmpNotifResp {
	return &seccomp.ScmpNotifResp{ID: id, Error: int32(errno), Val: ^uint64(0)}
}

func errnoFromError(err error) unix.Errno {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) && errno != 0 {
		return errno
	}
	return unix.EIO
}
