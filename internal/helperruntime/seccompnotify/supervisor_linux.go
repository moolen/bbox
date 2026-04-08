package seccompnotify

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type tcpRouteKind string

const (
	routeHTTPIngress   tcpRouteKind = "http"
	routeHTTPSIngress  tcpRouteKind = "https"
	routeRawTCPIngress tcpRouteKind = "raw_tcp"
)

type tcpRoute struct {
	Kind     tcpRouteKind
	Addr     string
	Sockaddr unix.Sockaddr
}

func (s *Supervisor) handleSyscall(req syscallRequest) error {
	switch req.Data.Syscall {
	case unix.SYS_SOCKET:
		return s.handleSocket(req.Socket)
	case unix.SYS_CONNECT:
		return s.handleConnect(req.Connect)
	case unix.SYS_CLOSE:
		return s.handleClose(req)
	case unix.SYS_DUP, unix.SYS_DUP3, unix.SYS_FCNTL:
		return s.handleDupLike(req)
	case unix.SYS_GETPEERNAME:
		return s.handleGetpeername(req)
	default:
		if isDupLikeSyscall(req.Data.Syscall) {
			return s.handleDupLike(req)
		}
		return nil
	}
}

func (s *Supervisor) handleSocket(req socketRequest) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if req.ChildFD < 0 {
		return fmt.Errorf("child fd must be non-negative")
	}

	// Always clear prior state for reused child fds before any bypass path.
	s.registry.Close(req.ChildFD)

	if !isManagedSocketFamily(req.Family) {
		return nil
	}
	if !targetsSupportFamilyIngress(s.targets, req.Family) {
		// Graceful fallback: if helper ingress for this family is unavailable,
		// leave the socket unmanaged so connect can proceed natively.
		return nil
	}
	if baseSocketType(req.SocketType) != unix.SOCK_STREAM {
		return nil
	}

	helperFD, err := unix.Socket(req.Family, req.SocketType, req.Protocol)
	if err != nil {
		return err
	}

	s.registry.Insert(SocketState{
		Kind:       KindTCP,
		ChildFD:    req.ChildFD,
		HelperFD:   helperFD,
		Family:     req.Family,
		SocketType: req.SocketType,
		Protocol:   req.Protocol,
		Blocking:   req.SocketType&unix.SOCK_NONBLOCK == 0,
	})
	return nil
}

func (s *Supervisor) handleConnect(req connectRequest) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if req.ChildFD < 0 {
		return unix.EBADF
	}

	state, ok := s.registry.Lookup(req.ChildFD)
	if !ok {
		// Unmanaged socket: allow native connect path.
		return nil
	}
	if state.HelperFD < 0 {
		return nil
	}
	if state.Kind != KindTCP {
		return nil
	}

	route, err := routeTCPDestination(s.targets, state.Family, req.Destination.Host, req.Destination.Port)
	if err != nil {
		return err
	}

	state.OriginalHost = req.Destination.Host
	state.OriginalPort = req.Destination.Port
	state.RedirectAddr = route.Addr
	connectErr := unix.Connect(state.HelperFD, route.Sockaddr)
	if connectErr != nil && connectErr != unix.EINPROGRESS && connectErr != unix.EALREADY {
		return connectErr
	}
	if connectErr == unix.EINPROGRESS || connectErr == unix.EALREADY {
		if err := waitForConnectComplete(state.HelperFD, 2*time.Second); err != nil {
			return err
		}
	}
	s.registry.Insert(state)

	if route.Kind == routeRawTCPIngress && s.targets.RecordRawTCPOrigin != nil {
		localAddr, err := getsocknameStringWithRetry(state.HelperFD, 50*time.Millisecond)
		if err == nil && localAddr != "" {
			s.targets.RecordRawTCPOrigin(localAddr, req.Destination.Host, req.Destination.Port)
		}
	}
	return nil
}

func waitForConnectComplete(fd int, timeout time.Duration) error {
	if fd < 0 {
		return unix.EBADF
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	deadline := time.Now().Add(timeout)
	pollFDs := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLOUT | unix.POLLERR | unix.POLLHUP,
	}}

	for {
		socketErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err == nil {
			switch errno := unix.Errno(socketErr); errno {
			case 0:
				return nil
			case unix.EINPROGRESS, unix.EALREADY, unix.EWOULDBLOCK:
			default:
				return errno
			}
		} else if err != unix.EINTR {
			return err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return unix.ETIMEDOUT
		}
		timeoutMs := int(remaining / time.Millisecond)
		if timeoutMs < 1 {
			timeoutMs = 1
		}

		n, pollErr := unix.Poll(pollFDs, timeoutMs)
		if pollErr == unix.EINTR {
			continue
		}
		if pollErr != nil {
			return pollErr
		}
		if n == 0 {
			return unix.ETIMEDOUT
		}
	}
}

func (s *Supervisor) handleClose(req syscallRequest) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if req.Close.ChildFD < 0 {
		return unix.EBADF
	}

	s.registry.Close(req.Close.ChildFD)
	return nil
}

func (s *Supervisor) handleDupLike(req syscallRequest) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}

	var (
		oldFD int
		newFD int
	)
	switch req.Data.Syscall {
	case unix.SYS_DUP, unix.SYS_DUP3:
		oldFD = req.Dup.OldFD
		if oldFD < 0 {
			oldFD = req.Dup.FD
		}
		newFD = req.Dup.NewFD
	case unix.SYS_FCNTL:
		switch req.Dup.Cmd {
		case unix.F_DUPFD, unix.F_DUPFD_CLOEXEC:
			oldFD = req.Dup.FD
			newFD = req.Dup.NewFD
		default:
			return nil
		}
	default:
		if optionalDup2Syscall >= 0 && req.Data.Syscall == optionalDup2Syscall {
			oldFD = req.Dup.OldFD
			if oldFD < 0 {
				oldFD = req.Dup.FD
			}
			newFD = req.Dup.NewFD
			break
		}
		return nil
	}

	if oldFD < 0 || newFD < 0 {
		return unix.EBADF
	}
	if oldFD == newFD {
		return nil
	}
	return s.registry.Dup(oldFD, newFD)
}

func (s *Supervisor) handleGetpeername(req syscallRequest) error {
	if s == nil {
		return fmt.Errorf("supervisor is required")
	}
	if req.Getpeername.ChildFD < 0 {
		return unix.EBADF
	}

	state, ok := s.registry.Lookup(req.Getpeername.ChildFD)
	if !ok {
		return nil
	}
	if state.RedirectAddr == "" {
		return nil
	}

	return writeOriginalPeername(req.Getpeername, state.OriginalHost, state.OriginalPort, state.Family)
}

func writeOriginalPeername(req getpeernameRequest, host string, port int, fallbackFamily int) error {
	if req.WritePeername == nil {
		return nil
	}
	if host == "" || port <= 0 {
		return nil
	}
	return req.WritePeername(DecodedSockaddr{
		Family: peernameFamily(host, fallbackFamily),
		Host:   host,
		Port:   port,
	})
}

func peernameFamily(host string, fallbackFamily int) int {
	switch fallbackFamily {
	case unix.AF_INET, unix.AF_INET6:
		return fallbackFamily
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fallbackFamily
	}
	if ip.To4() != nil {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func routeTCPDestination(targets RuntimeTargets, family int, host string, port int) (tcpRoute, error) {
	_ = host
	if port == 53 {
		return tcpRoute{}, unix.EPERM
	}

	addr := selectIngressAddrForFamily(family, targets.RawTCPAddr, targets.RawTCPAddrV6)
	if addr == "" {
		return tcpRoute{}, fmt.Errorf("missing ingress address for route %q", routeRawTCPIngress)
	}
	sockaddr, err := parseTCPAddr(addr)
	if err != nil {
		return tcpRoute{}, err
	}
	if !sockaddrMatchesFamily(sockaddr, family) {
		return tcpRoute{}, unix.EAFNOSUPPORT
	}
	return tcpRoute{
		Kind:     routeRawTCPIngress,
		Addr:     addr,
		Sockaddr: sockaddr,
	}, nil
}

func selectIngressAddrForFamily(family int, addr4, addr6 string) string {
	if family == unix.AF_INET6 {
		return addr6
	}
	return addr4
}

func parseTCPAddr(addr string) (unix.Sockaddr, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split ingress address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid ingress port %q", portText)
	}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		var raw [4]byte
		copy(raw[:], ip4)
		return &unix.SockaddrInet4{Port: port, Addr: raw}, nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		var raw [16]byte
		copy(raw[:], ip16)
		return &unix.SockaddrInet6{Port: port, Addr: raw}, nil
	}
	return nil, fmt.Errorf("ingress host %q is not an IP address", host)
}

func getsocknameString(fd int) (string, error) {
	sockaddr, err := unix.Getsockname(fd)
	if err != nil {
		return "", err
	}

	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		return net.JoinHostPort(net.IP(addr.Addr[:]).String(), strconv.Itoa(addr.Port)), nil
	case *unix.SockaddrInet6:
		return net.JoinHostPort(net.IP(addr.Addr[:]).String(), strconv.Itoa(addr.Port)), nil
	default:
		return "", fmt.Errorf("unsupported getsockname sockaddr %T", sockaddr)
	}
}

func getsocknameStringWithRetry(fd int, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return getsocknameString(fd)
	}

	deadline := time.Now().Add(timeout)
	for {
		addr, err := getsocknameString(fd)
		if err == nil && addr != "" {
			return addr, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "", err
			}
			return "", nil
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func isManagedSocketFamily(family int) bool {
	switch family {
	case unix.AF_INET, unix.AF_INET6:
		return true
	default:
		return false
	}
}

func baseSocketType(socketType int) int {
	const sockTypeMask = 0xf
	return socketType & sockTypeMask
}

func sockaddrMatchesFamily(sockaddr unix.Sockaddr, family int) bool {
	switch sockaddr.(type) {
	case *unix.SockaddrInet4:
		return family == unix.AF_INET
	case *unix.SockaddrInet6:
		return family == unix.AF_INET6
	default:
		return false
	}
}

func targetsSupportFamilyIngress(targets RuntimeTargets, family int) bool {
	switch family {
	case unix.AF_INET:
		return targets.RawTCPAddr != ""
	case unix.AF_INET6:
		return targets.RawTCPAddrV6 != ""
	default:
		return false
	}
}
