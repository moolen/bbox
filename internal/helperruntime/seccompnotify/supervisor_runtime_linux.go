//go:build linux && cgo

package seccompnotify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	launcherBinaryName = "bbox-seccomp-launcher"
	launcherSockFDEnv  = "BBOX_SECCOMP_NOTIFY_SOCK_FD"
	maxSockaddrBytes   = 128
)

var (
	launcherCommandOverrideMu sync.Mutex
	launcherCommandOverride   func() (string, []string, error)
	launcherExecutablePath    = os.Executable
	launcherPathExists        = func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}
)

func (s *Supervisor) Prepare(_ context.Context, cmd *exec.Cmd) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if cmd == nil {
		return fmt.Errorf("command is required")
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open launcher socketpair: %w", err)
	}

	parent := os.NewFile(uintptr(fds[0]), "seccomp-notify-parent")
	child := os.NewFile(uintptr(fds[1]), "seccomp-notify-child")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		}
		if child != nil {
			_ = child.Close()
		}
		return fmt.Errorf("wrap launcher socketpair")
	}

	launcherPath, launcherArgs, err := resolveLauncherCommand()
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		return err
	}

	originalArgs := append([]string(nil), cmd.Args...)
	targetPath := cmd.Path
	if targetPath == "" {
		_ = parent.Close()
		_ = child.Close()
		return fmt.Errorf("command path is required")
	}
	if len(originalArgs) == 0 {
		originalArgs = []string{targetPath}
	}

	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	env = filterLauncherEnv(env)
	extraFD := 3 + len(cmd.ExtraFiles)
	env = append(env,
		fmt.Sprintf("%s=%d", launcherSockFDEnv, extraFD),
	)

	cmd.Path = launcherPath
	cmd.Args = append(
		append(
			append([]string{launcherPath}, launcherArgs...),
			targetPath,
			"--",
		),
		originalArgs...,
	)
	cmd.Env = env
	cmd.ExtraFiles = append(cmd.ExtraFiles, child)

	s.notifySock = parent
	s.notifyChild = child
	s.notifyFD = -1
	return nil
}

func (s *Supervisor) Start(ctx context.Context, pid int) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if pid <= 0 {
		return fmt.Errorf("pid must be positive")
	}
	if s.notifySock == nil {
		return fmt.Errorf("supervisor is not prepared")
	}
	if s.notifyChild != nil {
		_ = s.notifyChild.Close()
		s.notifyChild = nil
	}

	notifyFD, err := receiveLauncherNotifyFD(ctx, int(s.notifySock.Fd()))
	if err != nil {
		s.launcherError = err
		return err
	}
	s.notifyFD = notifyFD

	go s.serveNotifications(pid)
	return nil
}

func (s *Supervisor) Close() error {
	if s == nil {
		return nil
	}

	var err error
	if s.notifyChild != nil {
		err = errors.Join(err, s.notifyChild.Close())
		s.notifyChild = nil
	}
	if s.notifySock != nil {
		err = errors.Join(err, s.notifySock.Close())
		s.notifySock = nil
	}
	if s.notifyFD >= minManagedHelperFD {
		err = errors.Join(err, unix.Close(s.notifyFD))
		s.notifyFD = -1
	}
	return err
}

func resolveLauncherCommand() (string, []string, error) {
	launcherCommandOverrideMu.Lock()
	override := launcherCommandOverride
	launcherCommandOverrideMu.Unlock()
	if override != nil {
		return override()
	}

	path, err := launcherExecutablePath()
	if err != nil {
		return "", nil, fmt.Errorf("resolve launcher executable: %w", err)
	}
	candidate := filepath.Join(filepath.Dir(path), launcherBinaryName)
	if !launcherPathExists(candidate) {
		return "", nil, fmt.Errorf("resolve seccomp launcher %q beside helper %q", candidate, path)
	}
	return candidate, nil, nil
}

func filterLauncherEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, launcherSockFDEnv+"=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func receiveLauncherNotifyFD(ctx context.Context, sockFD int) (int, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		fd, err := recvLauncherNotifyFD(sockFD)
		done <- result{fd: fd, err: err}
	}()

	select {
	case <-ctx.Done():
		return -1, ctx.Err()
	case res := <-done:
		return res.fd, res.err
	}
}

func recvLauncherNotifyFD(sockFD int) (int, error) {
	buf := make([]byte, 1024)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recv launcher message: %w", err)
	}
	if n == 0 {
		return -1, io.EOF
	}
	if buf[0] == 0 {
		return -1, fmt.Errorf("launcher failed: %s", string(buf[1:n]))
	}
	if buf[0] != 1 {
		return -1, fmt.Errorf("unexpected launcher status %d", buf[0])
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse launcher rights: %w", err)
	}
	for _, msg := range msgs {
		fds, parseErr := unix.ParseUnixRights(&msg)
		if parseErr == nil && len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("launcher did not pass notify fd")
}

func (s *Supervisor) serveNotifications(pid int) {
	if s == nil || s.notifyFD < minManagedHelperFD {
		return
	}

	notifyFD := seccomp.ScmpFd(s.notifyFD)
	for {
		req, err := seccomp.NotifReceive(notifyFD)
		if err != nil {
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINTR) {
				return
			}
			s.launcherError = err
			return
		}

		resp := s.processNotification(pid, req)
		if err := seccomp.NotifRespond(notifyFD, resp); err != nil && !errors.Is(err, unix.ENOENT) {
			s.launcherError = err
			return
		}
	}
}

func (s *Supervisor) processNotification(pid int, req *seccomp.ScmpNotifReq) *seccomp.ScmpNotifResp {
	if req == nil {
		return errorResp(0, unix.EINVAL)
	}

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
		handled, err := s.redirectConnect(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, 0)
	case unix.SYS_SENDTO:
		n, handled, err := s.emulateDNSSendTo(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVFROM:
		n, handled, err := s.emulateDNSRecvFrom(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_SENDMSG:
		n, handled, err := s.emulateDNSSendMsg(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVMSG:
		n, handled, err := s.emulateDNSRecvMsg(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_SENDMMSG:
		n, handled, err := s.emulateDNSSendMMsg(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_RECVMMSG:
		n, handled, err := s.emulateDNSRecvMMsg(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_POLL:
		n, handled, err := s.emulateDNSPoll(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_PPOLL:
		n, handled, err := s.emulateDNSPPoll(pid, req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(n))
	case unix.SYS_CLOSE:
		fd := int(req.Data.Args[0])
		if fd >= 0 {
			s.registry.Close(fd)
		}
		return continueResp(req.ID)
	case unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3, unix.SYS_FCNTL:
		fd, handled, err := s.duplicateSocket(req)
		if err != nil {
			return errorResp(req.ID, errnoFromError(err))
		}
		if !handled {
			return continueResp(req.ID)
		}
		return successResp(req.ID, uint64(fd))
	default:
		return continueResp(req.ID)
	}
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

	childFD, err := addFDWithResult(s.notifyFD, req.ID, helperFD, 0, 0, 0)
	if err != nil {
		_ = unix.Close(helperFD)
		return -1, false, err
	}

	s.registry.Close(childFD)
	s.registry.Insert(SocketState{
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
	state, ok := s.registry.Lookup(childFD)
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

	switch state.Kind {
	case KindTCP:
		return true, s.handleConnect(connectRequest{
			ChildFD:     childFD,
			Destination: decoded,
		})
	case KindUDP:
		if decoded.Port != 53 {
			s.registry.Close(childFD)
			return false, nil
		}
		return true, s.handleDNSConnect(childFD, state, decoded)
	default:
		return false, nil
	}
}

func (s *Supervisor) handleDNSConnect(childFD int, state SocketState, destination DecodedSockaddr) error {
	if s == nil {
		return unix.EINVAL
	}
	if s.targets.DNSRoundTrip == nil && s.targets.DNSAddr == "" {
		return unix.EHOSTUNREACH
	}

	state.ChildFD = childFD
	state.DNSManaged = true
	state.ConnectedHost = destination.Host
	state.ConnectedPort = destination.Port
	state.PendingDNSResponses = nil
	state.OriginalHost = destination.Host
	state.OriginalPort = destination.Port
	state.RedirectAddr = ""
	s.registry.Insert(state)
	return nil
}

func classifyManagedSocket(targets RuntimeTargets, family, socketType, protocol int) (SocketKind, bool, error) {
	if !isManagedSocketFamily(family) {
		return KindUnknown, false, unix.EAFNOSUPPORT
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
		if targets.DNSRoundTrip == nil && targets.DNSAddr == "" {
			return KindUnknown, false, unix.EHOSTUNREACH
		}
		return KindUDP, true, nil
	default:
		return KindUnknown, false, nil
	}
}

func (s *Supervisor) duplicateSocket(req *seccomp.ScmpNotifReq) (int, bool, error) {
	if s == nil || req == nil {
		return -1, false, unix.EINVAL
	}

	oldFD := int(req.Data.Args[0])
	if oldFD < 0 {
		return -1, false, unix.EBADF
	}
	state, ok := s.registry.Lookup(oldFD)
	if !ok {
		return -1, false, nil
	}

	switch int(req.Data.Syscall) {
	case unix.SYS_DUP:
		childFD, err := addFDWithResult(s.notifyFD, req.ID, state.HelperFD, 0, 0, 0)
		if err != nil {
			return -1, false, err
		}
		if err := s.registry.Dup(oldFD, childFD); err != nil {
			return -1, false, err
		}
		return childFD, true, nil
	case unix.SYS_DUP2, unix.SYS_DUP3:
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
		childFD, err := addFDWithResult(
			s.notifyFD,
			req.ID,
			state.HelperFD,
			uint32(newFD),
			unix.SECCOMP_ADDFD_FLAG_SETFD,
			newFDFlags,
		)
		if err != nil {
			return -1, false, err
		}
		if err := s.registry.Dup(oldFD, childFD); err != nil {
			return -1, false, err
		}
		return childFD, true, nil
	case unix.SYS_FCNTL:
		cmd := int(req.Data.Args[1])
		minFD := int(req.Data.Args[2])
		switch cmd {
		case unix.F_DUPFD:
			childFD, err := addFDWithResult(s.notifyFD, req.ID, state.HelperFD, uint32(minFD), 0, 0)
			if err != nil {
				return -1, false, err
			}
			if err := s.registry.Dup(oldFD, childFD); err != nil {
				return -1, false, err
			}
			return childFD, true, nil
		case unix.F_DUPFD_CLOEXEC:
			childFD, err := addFDWithResult(s.notifyFD, req.ID, state.HelperFD, uint32(minFD), 0, unix.O_CLOEXEC)
			if err != nil {
				return -1, false, err
			}
			if err := s.registry.Dup(oldFD, childFD); err != nil {
				return -1, false, err
			}
			return childFD, true, nil
		default:
			return -1, false, nil
		}
	default:
		return -1, false, nil
	}
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
	return &seccomp.ScmpNotifResp{
		ID:    id,
		Error: 0,
		Val:   val,
	}
}

func continueResp(id uint64) *seccomp.ScmpNotifResp {
	return &seccomp.ScmpNotifResp{
		ID:    id,
		Error: 0,
		Flags: seccomp.NotifRespFlagContinue,
	}
}

func errorResp(id uint64, errno unix.Errno) *seccomp.ScmpNotifResp {
	return &seccomp.ScmpNotifResp{
		ID:    id,
		Error: int32(errno),
		Val:   ^uint64(0),
	}
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
