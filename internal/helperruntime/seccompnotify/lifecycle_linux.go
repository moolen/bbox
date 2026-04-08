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
	sandboxBBoxPath   = "/app/bbox"
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
	env = append(env, fmt.Sprintf("%s=%d", launcherSockFDEnv, extraFD))

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
	pollFDs := []unix.PollFd{{Fd: int32(s.notifyReceiveFD), Events: unix.POLLIN}}

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
