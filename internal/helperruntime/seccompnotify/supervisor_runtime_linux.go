//go:build linux && cgo

package seccompnotify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/moolen/bbox/internal/embeddedlauncher"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	launcherSockFDEnv = "BBOX_SECCOMP_NOTIFY_SOCK_FD"
	maxSockaddrBytes  = 128
	sandboxBBoxPath   = "/app/bbox"
	ioctlFIONREAD     = 0x541B
)

var (
	launcherFactoryMu sync.Mutex
	launcherFactory   = func() (embeddedlauncher.ExecTarget, error) {
		return embeddedlauncher.OpenExecTarget()
	}
	launcherBootstrapFactory = func() (string, []string, error) {
		return sandboxBBoxPath, []string{"internal-launcher"}, nil
	}
	notificationTraceHook       func(*seccomp.ScmpNotifReq)
	notificationResultTraceHook func(*seccomp.ScmpNotifReq, *seccomp.ScmpNotifResp, error)
	notifReceive                = seccomp.NotifReceive
	notifRespond                = seccomp.NotifRespond
	notifPoll                   = unix.Poll
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

	target, err := resolveLauncherTarget()
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		return err
	}
	closeTarget := func() error {
		return closeLauncherTarget(target)
	}

	originalArgs := append([]string(nil), cmd.Args...)
	targetPath := cmd.Path
	if targetPath == "" {
		_ = closeTarget()
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

	launcherPath := target.Path
	if target.File != nil {
		bootstrapPath, bootstrapArgs, err := resolveLauncherBootstrap()
		if err != nil {
			_ = closeTarget()
			_ = parent.Close()
			_ = child.Close()
			return err
		}

		launcherFD := 3 + len(cmd.ExtraFiles)
		cmd.ExtraFiles = append(cmd.ExtraFiles, target.File)
		launcherPath = bootstrapPath
		launcherArgv := []string{"bbox-seccomp-launcher"}
		if s.payloadSeccompBPFPath != "" {
			launcherArgv = append(launcherArgv, "--payload-seccomp-bpf", s.payloadSeccompBPFPath)
		}
		launcherArgv = append(launcherArgv, target.Args...)
		launcherArgv = append(launcherArgv, targetPath, "--")
		launcherArgv = append(launcherArgv, originalArgs...)
		cmd.Args = append(
			append(
				append([]string{launcherPath}, bootstrapArgs...),
				"--launcher-fd", strconv.Itoa(launcherFD), "--",
			),
			launcherArgv...,
		)
	} else {
		launcherArgs := append([]string(nil), target.Args...)
		if s.payloadSeccompBPFPath != "" {
			launcherArgs = append(launcherArgs, "--payload-seccomp-bpf", s.payloadSeccompBPFPath)
		}
		cmd.Args = append(
			append(
				append([]string{launcherPath}, launcherArgs...),
				targetPath,
				"--",
			),
			originalArgs...,
		)
	}
	extraFD := 3 + len(cmd.ExtraFiles)
	env = append(env,
		fmt.Sprintf("%s=%d", launcherSockFDEnv, extraFD),
	)

	cmd.Path = launcherPath
	cmd.Env = env
	cmd.ExtraFiles = append(cmd.ExtraFiles, child)

	s.notifySock = parent
	s.notifyChild = child
	s.notifyReceiveFD = -1
	s.notifyFD = -1
	s.launcherClose = closeTarget
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
	if s.launcherClose != nil {
		_ = s.launcherClose()
		s.launcherClose = nil
	}

	controlFD, err := receiveLauncherNotifyFD(ctx, int(s.notifySock.Fd()))
	if err != nil {
		s.setLauncherError(err)
		return err
	}
	receiveFD, err := unix.Dup(controlFD)
	if err != nil {
		_ = unix.Close(controlFD)
		s.setLauncherError(err)
		return err
	}
	s.notifyFD = controlFD
	s.notifyReceiveFD = receiveFD
	s.closing.Store(false)

	s.notifyServeWG.Add(1)
	go func() {
		defer s.notifyServeWG.Done()
		s.serveNotifications(pid)
	}()
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
	s.closing.Store(true)
	s.notifyServeWG.Wait()
	if s.notifyReceiveFD >= minManagedHelperFD {
		err = errors.Join(err, unix.Close(s.notifyReceiveFD))
		s.notifyReceiveFD = -1
	}
	if s.notifyFD >= minManagedHelperFD {
		s.notifyFDIOMu.Lock()
		err = errors.Join(err, unix.Close(s.notifyFD))
		s.notifyFD = -1
		s.notifyFDIOMu.Unlock()
	}
	if s.launcherClose != nil {
		err = errors.Join(err, s.launcherClose())
		s.launcherClose = nil
	}
	return err
}

func resolveLauncherTarget() (embeddedlauncher.ExecTarget, error) {
	launcherFactoryMu.Lock()
	factory := launcherFactory
	launcherFactoryMu.Unlock()
	if factory == nil {
		return embeddedlauncher.ExecTarget{}, fmt.Errorf("launcher factory is not configured")
	}
	return factory()
}

func resolveLauncherBootstrap() (string, []string, error) {
	launcherFactoryMu.Lock()
	factory := launcherBootstrapFactory
	launcherFactoryMu.Unlock()
	if factory == nil {
		return "", nil, fmt.Errorf("launcher bootstrap factory is not configured")
	}
	return factory()
}

func closeLauncherTarget(target embeddedlauncher.ExecTarget) error {
	if target.Close != nil {
		return target.Close()
	}
	if target.File != nil {
		return target.File.Close()
	}
	return nil
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
	if s == nil || s.notifyReceiveFD < minManagedHelperFD {
		return
	}

	notifyFD := seccomp.ScmpFd(s.notifyReceiveFD)
	var wg sync.WaitGroup
	defer wg.Wait()
	pollFDs := []unix.PollFd{{
		Fd:     int32(s.notifyReceiveFD),
		Events: unix.POLLIN,
	}}

	for {
		if s.closing.Load() {
			return
		}

		n, pollErr := notifPoll(pollFDs, 100)
		if pollErr == unix.EINTR {
			continue
		}
		if pollErr != nil {
			if s.closing.Load() {
				return
			}
			s.setLauncherError(fmt.Errorf("poll: %w", pollErr))
			return
		}
		if n == 0 {
			continue
		}

		req, err := notifReceive(notifyFD)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ECANCELED) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return
			}
			s.setLauncherError(fmt.Errorf("receive: %w", err))
			return
		}

		waitForTurn, releaseTurn := s.enqueueNotificationTurn(pid, req)
		wg.Add(1)
		go func(req *seccomp.ScmpNotifReq, waitForTurn <-chan struct{}, releaseTurn func()) {
			defer wg.Done()
			defer releaseTurn()
			if waitForTurn != nil {
				<-waitForTurn
			}
			s.respondNotification(notifyFD, pid, req)
		}(req, waitForTurn, releaseTurn)
	}
}

func (s *Supervisor) respondNotification(_ seccomp.ScmpFd, pid int, req *seccomp.ScmpNotifReq) {
	resp := s.processNotification(pid, req)
	s.notifyFDIOMu.Lock()
	err := notifRespond(seccomp.ScmpFd(s.notifyFD), resp)
	s.notifyFDIOMu.Unlock()
	if notificationResultTraceHook != nil {
		notificationResultTraceHook(req, resp, err)
	}
	if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINTR) {
		s.setLauncherError(fmt.Errorf("respond: %w", err))
	}
}

func (s *Supervisor) setLauncherError(err error) {
	if s == nil || err == nil {
		return
	}
	s.launcherErrorMu.Lock()
	if s.launcherError == nil {
		s.launcherError = err
	}
	s.launcherErrorMu.Unlock()
}

func (s *Supervisor) enqueueNotificationTurn(pid int, req *seccomp.ScmpNotifReq) (<-chan struct{}, func()) {
	if s == nil || req == nil {
		return nil, func() {}
	}

	key, ok := s.notificationOpKey(pid, req)
	if !ok {
		return nil, func() {}
	}

	s.notifyQueueMu.Lock()
	waitForTurn := s.notifyQueueTails[key]
	doneCh := make(chan struct{})
	s.notifyQueueTails[key] = doneCh
	s.notifyQueueRefs[key]++
	s.notifyQueueMu.Unlock()

	return waitForTurn, func() {
		close(doneCh)

		s.notifyQueueMu.Lock()
		s.notifyQueueRefs[key]--
		if s.notifyQueueRefs[key] == 0 {
			delete(s.notifyQueueRefs, key)
			if tail, ok := s.notifyQueueTails[key]; ok && tail == doneCh {
				delete(s.notifyQueueTails, key)
			}
		}
		s.notifyQueueMu.Unlock()
	}
}

func (s *Supervisor) notificationOpKey(pid int, req *seccomp.ScmpNotifReq) (fdRegistryKey, bool) {
	return fdRegistryKey{pid: normalizeRegistryPID(notificationPID(pid, req)), fd: -1}, true
}

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
		_, err = s.addFDWithResult(
			req.ID,
			helperFD,
			uint32(childFD),
			unix.SECCOMP_ADDFD_FLAG_SETFD,
			0,
		)
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
		if err := s.handleConnect(connectRequest{
			ChildFD:     childFD,
			Destination: decoded,
		}); err != nil {
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
	_, err := s.addFDWithResult(
		notifID,
		state.HelperFD,
		uint32(state.ChildFD),
		unix.SECCOMP_ADDFD_FLAG_SETFD,
		newFDFlags,
	)
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
		childFD, err := s.addFDAtOrAbove(req.ID, state.HelperFD, minDupFDForState(state, 0), 0)
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
		childFD, err := s.addFDWithResult(
			req.ID,
			state.HelperFD,
			uint32(newFD),
			unix.SECCOMP_ADDFD_FLAG_SETFD,
			newFDFlags,
		)
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
			childFD, err := s.addFDWithResult(
				req.ID,
				state.HelperFD,
				uint32(newFD),
				unix.SECCOMP_ADDFD_FLAG_SETFD,
				0,
			)
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
		childFD, err := s.addFDWithResult(
			reqID,
			srcFD,
			uint32(fd),
			unix.SECCOMP_ADDFD_FLAG_SETFD,
			newFDFlags,
		)
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
