//go:build linux

package seccompnotify

import (
	"errors"
	"net"
	"testing"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func TestClassifyManagedSocketBypassesICMPDatagramProtocols(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		family   int
		sockType int
		protocol int
	}{
		{name: "icmp-dgram", family: unix.AF_INET, sockType: unix.SOCK_DGRAM, protocol: unix.IPPROTO_ICMP},
		{name: "icmpv6-dgram", family: unix.AF_INET6, sockType: unix.SOCK_DGRAM, protocol: unix.IPPROTO_ICMPV6},
		{name: "icmp-raw", family: unix.AF_INET, sockType: unix.SOCK_RAW, protocol: unix.IPPROTO_ICMP},
		{name: "icmpv6-raw", family: unix.AF_INET6, sockType: unix.SOCK_RAW, protocol: unix.IPPROTO_ICMPV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, managed, err := classifyManagedSocket(RuntimeTargets{}, tc.family, tc.sockType, tc.protocol)
			if err != nil {
				t.Fatalf("classifyManagedSocket() error = %v", err)
			}
			if managed {
				t.Fatal("expected ICMP datagram socket to bypass seccomp management")
			}
			if kind != KindUnknown {
				t.Fatalf("unexpected socket kind: got %q want %q", kind, KindUnknown)
			}
		})
	}
}

func TestClassifyManagedSocketBypassesUnsupportedFamilies(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		family int
	}{
		{name: "unix", family: unix.AF_UNIX},
		{name: "netlink", family: unix.AF_NETLINK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, managed, err := classifyManagedSocket(
				RuntimeTargets{RawTCPAddr: "127.0.0.1:39001"},
				tc.family,
				unix.SOCK_DGRAM,
				0,
			)
			if err != nil {
				t.Fatalf("classifyManagedSocket() error = %v", err)
			}
			if managed {
				t.Fatal("expected unsupported socket family to bypass seccomp management")
			}
			if kind != KindUnknown {
				t.Fatalf("unexpected socket kind: got %q want %q", kind, KindUnknown)
			}
		})
	}
}

func TestClassifyManagedSocketRequiresDNSRoundTripForUDP(t *testing.T) {
	t.Parallel()

	kind, managed, err := classifyManagedSocket(
		RuntimeTargets{RawTCPAddr: "127.0.0.1:39001"},
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_UDP,
	)
	if !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("classifyManagedSocket() error = %v, want %v", err, unix.EHOSTUNREACH)
	}
	if managed {
		t.Fatal("expected UDP socket to remain unmanaged without DNSRoundTrip")
	}
	if kind != KindUnknown {
		t.Fatalf("unexpected socket kind: got %q want %q", kind, KindUnknown)
	}
}

func TestSupervisorConnectRedirectsManagedTCPFD(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr:   rawListener.Addr().String(),
		RawTCPAddrV6: "[::1]:39001",
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 7
	if err := s.handleSocket(socketRequest{
		ChildFD:    childFD,
		Family:     unix.AF_INET,
		SocketType: unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	}); err != nil {
		t.Fatalf("handle socket: %v", err)
	}
	state, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleSocket")
	}
	t.Cleanup(func() {
		_ = unix.Close(state.HelperFD)
		s.Registry().Close(childFD)
	})

	err = s.handleConnect(connectRequest{
		ChildFD: childFD,
		Destination: DecodedSockaddr{
			Family: unix.AF_INET,
			Host:   "93.184.216.34",
			Port:   8443,
		},
	})
	if err != nil {
		t.Fatalf("handle connect: %v", err)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for redirected raw ingress accept")
	}

	got, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleConnect")
	}
	if got.OriginalHost != "93.184.216.34" || got.OriginalPort != 8443 {
		t.Fatalf("unexpected original destination metadata: %+v", got)
	}
	if got.RedirectAddr != rawListener.Addr().String() {
		t.Fatalf("redirect address mismatch: got=%q want=%q", got.RedirectAddr, rawListener.Addr().String())
	}
}

func TestSupervisorConnectRecordsRawTCPOriginForNonblockingSocket(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	type originRecord struct {
		localAddr string
		host      string
		port      int
	}
	recorded := make(chan originRecord, 1)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
		RecordRawTCPOrigin: func(localAddr, host string, port int) {
			recorded <- originRecord{
				localAddr: localAddr,
				host:      host,
				port:      port,
			}
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 41
	if err := s.handleSocket(socketRequest{
		ChildFD:    childFD,
		Family:     unix.AF_INET,
		SocketType: unix.SOCK_STREAM | unix.SOCK_NONBLOCK,
		Protocol:   unix.IPPROTO_TCP,
	}); err != nil {
		t.Fatalf("handle socket: %v", err)
	}
	state, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleSocket")
	}
	t.Cleanup(func() {
		_ = unix.Close(state.HelperFD)
		s.Registry().Close(childFD)
	})

	err = s.handleConnect(connectRequest{
		ChildFD: childFD,
		Destination: DecodedSockaddr{
			Family: unix.AF_INET,
			Host:   "93.184.216.34",
			Port:   8443,
		},
	})
	if err != nil && err != unix.EINPROGRESS && err != unix.EALREADY {
		t.Fatalf("handle connect: %v", err)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for redirected raw ingress accept")
	}

	select {
	case record := <-recorded:
		if record.localAddr == "" {
			t.Fatal("expected local address to be recorded")
		}
		if record.host != "93.184.216.34" || record.port != 8443 {
			t.Fatalf("unexpected origin record: %+v", record)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for raw TCP origin record")
	}

	got, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleConnect")
	}
	if got.OriginalHost != "93.184.216.34" || got.OriginalPort != 8443 {
		t.Fatalf("unexpected original destination metadata: %+v", got)
	}
}

func TestSupervisorConnectRedirectsManagedTCPFDIPv6(t *testing.T) {
	rawListener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr:   "127.0.0.1:39001",
		RawTCPAddrV6: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 11
	if err := s.handleSocket(socketRequest{
		ChildFD:    childFD,
		Family:     unix.AF_INET6,
		SocketType: unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	}); err != nil {
		t.Fatalf("handle socket: %v", err)
	}

	state, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleSocket")
	}
	t.Cleanup(func() {
		_ = unix.Close(state.HelperFD)
		s.Registry().Close(childFD)
	})

	err = s.handleConnect(connectRequest{
		ChildFD: childFD,
		Destination: DecodedSockaddr{
			Family: unix.AF_INET6,
			Host:   "2001:db8::1",
			Port:   9443,
		},
	})
	if err != nil {
		t.Fatalf("handle connect: %v", err)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for redirected raw ingress accept")
	}

	got, ok := s.Registry().Lookup(childFD)
	if !ok {
		t.Fatal("managed socket state missing after handleConnect")
	}
	if got.OriginalHost != "2001:db8::1" || got.OriginalPort != 9443 {
		t.Fatalf("unexpected original destination metadata: %+v", got)
	}
	if got.RedirectAddr != rawListener.Addr().String() {
		t.Fatalf("redirect address mismatch: got=%q want=%q", got.RedirectAddr, rawListener.Addr().String())
	}
}

func TestRouteTCPDestinationUsesFamilySpecificIngress(t *testing.T) {
	route, err := routeTCPDestination(RuntimeTargets{
		RawTCPAddr:   "127.0.0.1:39001",
		RawTCPAddrV6: "[::1]:39002",
	}, unix.AF_INET6, "example.com", 8443)
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if route.Addr != "[::1]:39002" {
		t.Fatalf("route.Addr=%q", route.Addr)
	}
}

func TestRouteTCPDestinationPortRoutingBothFamilies(t *testing.T) {
	targets := RuntimeTargets{
		RawTCPAddr:   "127.0.0.1:39001",
		RawTCPAddrV6: "[::1]:39002",
	}
	tests := []struct {
		name     string
		family   int
		port     int
		wantKind tcpRouteKind
		wantAddr string
	}{
		{name: "ipv4-http", family: unix.AF_INET, port: 80, wantKind: routeRawTCPIngress, wantAddr: "127.0.0.1:39001"},
		{name: "ipv4-https", family: unix.AF_INET, port: 443, wantKind: routeRawTCPIngress, wantAddr: "127.0.0.1:39001"},
		{name: "ipv4-raw", family: unix.AF_INET, port: 9000, wantKind: routeRawTCPIngress, wantAddr: "127.0.0.1:39001"},
		{name: "ipv6-http", family: unix.AF_INET6, port: 80, wantKind: routeRawTCPIngress, wantAddr: "[::1]:39002"},
		{name: "ipv6-https", family: unix.AF_INET6, port: 443, wantKind: routeRawTCPIngress, wantAddr: "[::1]:39002"},
		{name: "ipv6-raw", family: unix.AF_INET6, port: 9000, wantKind: routeRawTCPIngress, wantAddr: "[::1]:39002"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route, err := routeTCPDestination(targets, tc.family, "example.com", tc.port)
			if err != nil {
				t.Fatalf("route: %v", err)
			}
			if route.Kind != tc.wantKind || route.Addr != tc.wantAddr {
				t.Fatalf("route=%#v want kind=%q addr=%q", route, tc.wantKind, tc.wantAddr)
			}
		})
	}
}

func TestSupervisorSocketIPv6FallbackWhenIngressUnavailable(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: "127.0.0.1:39001",
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 23
	if err := s.handleSocket(socketRequest{
		ChildFD:    childFD,
		Family:     unix.AF_INET6,
		SocketType: unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	}); err != nil {
		t.Fatalf("handle socket: %v", err)
	}
	if _, ok := s.Registry().Lookup(childFD); ok {
		t.Fatal("expected AF_INET6 socket to remain unmanaged when ipv6 ingress is unavailable")
	}

	// Unmanaged sockets must bypass redirection logic rather than hard-failing.
	if err := s.handleConnect(connectRequest{
		ChildFD: childFD,
		Destination: DecodedSockaddr{
			Family: unix.AF_INET6,
			Host:   "2001:db8::1",
			Port:   443,
		},
	}); err != nil {
		t.Fatalf("handle connect should bypass unmanaged socket: %v", err)
	}
}

func TestSupervisorSocketIPv6FallbackClearsStaleManagedStateOnFDReuse(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
		// intentionally no IPv6 ingress targets
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 29
	staleHelperFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("create stale helper fd: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(staleHelperFD) })
	s.Registry().Insert(SocketState{
		Kind:       KindTCP,
		ChildFD:    childFD,
		HelperFD:   staleHelperFD,
		Family:     unix.AF_INET,
		SocketType: unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	})

	// Reusing the same child fd for AF_INET6 without v6 ingress should clear stale state.
	if err := s.handleSocket(socketRequest{
		ChildFD:    childFD,
		Family:     unix.AF_INET6,
		SocketType: unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	}); err != nil {
		t.Fatalf("handle socket: %v", err)
	}
	if _, ok := s.Registry().Lookup(childFD); ok {
		t.Fatal("expected stale managed state to be cleared on fd reuse fallback")
	}

	// Connect must bypass redirection and must not hit old raw ingress target.
	if err := s.handleConnect(connectRequest{
		ChildFD: childFD,
		Destination: DecodedSockaddr{
			Family: unix.AF_INET6,
			Host:   "2001:db8::2",
			Port:   9443,
		},
	}); err != nil {
		t.Fatalf("handle connect should bypass unmanaged reused fd: %v", err)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("unexpected redirected connection to stale raw ingress")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestSupervisorCloseRemovesManagedFDState(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	s.Registry().Insert(SocketState{
		Kind:         KindTCP,
		ChildFD:      12,
		OriginalHost: "api2.cursor.sh",
		OriginalPort: 443,
	})

	if err := s.handleSyscall(syscallRequest{
		Data:  syscallData{Syscall: unix.SYS_CLOSE},
		Close: closeRequest{ChildFD: 12},
	}); err != nil {
		t.Fatalf("handle close: %v", err)
	}

	if _, ok := s.Registry().Lookup(12); ok {
		t.Fatal("expected state to be removed after close")
	}
}

func TestProcessNotificationBypassesUnsupportedSocketFamily(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	resp := s.processNotification(0, &seccomp.ScmpNotifReq{
		ID: 1,
		Data: seccomp.ScmpNotifData{
			Syscall: unix.SYS_SOCKET,
			Args:    []uint64{uint64(unix.AF_UNIX), uint64(unix.SOCK_STREAM), 0},
		},
	})
	if resp == nil {
		t.Fatal("processNotification() response = nil")
	}
	if resp.Flags != seccomp.NotifRespFlagContinue || resp.Error != 0 {
		t.Fatalf("processNotification() = %#v, want kernel continue", resp)
	}
}

func TestSupervisorDupCopiesManagedFDState(t *testing.T) {
	if optionalDup2Syscall < 0 {
		t.Skip("dup2 syscall is not available on this architecture")
	}

	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	s.Registry().Insert(SocketState{
		Kind:         KindTCP,
		ChildFD:      5,
		OriginalHost: "api2.cursor.sh",
		OriginalPort: 443,
	})

	if err := s.handleSyscall(syscallRequest{
		Data: syscallData{Syscall: optionalDup2Syscall},
		Dup: dupRequest{
			OldFD: 5,
			NewFD: 9,
		},
	}); err != nil {
		t.Fatalf("handle dup2: %v", err)
	}

	got, ok := s.Registry().Lookup(9)
	if !ok {
		t.Fatal("expected duplicated state for new fd")
	}
	if got.OriginalHost != "api2.cursor.sh" || got.OriginalPort != 443 {
		t.Fatalf("got %#v", got)
	}
}

func TestSupervisorDup3CopiesManagedFDState(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	s.Registry().Insert(SocketState{
		Kind:         KindTCP,
		ChildFD:      5,
		OriginalHost: "api2.cursor.sh",
		OriginalPort: 443,
	})

	if err := s.handleSyscall(syscallRequest{
		Data: syscallData{Syscall: unix.SYS_DUP3},
		Dup: dupRequest{
			OldFD: 5,
			NewFD: 10,
		},
	}); err != nil {
		t.Fatalf("handle dup3: %v", err)
	}

	got, ok := s.Registry().Lookup(10)
	if !ok {
		t.Fatal("expected duplicated state for dup3")
	}
	if got.OriginalHost != "api2.cursor.sh" || got.OriginalPort != 443 {
		t.Fatalf("got %#v", got)
	}
}

func TestSupervisorFcntlDupCopiesManagedFDState(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	s.Registry().Insert(SocketState{
		Kind:         KindTCP,
		ChildFD:      7,
		OriginalHost: "api2.cursor.sh",
		OriginalPort: 443,
	})

	if err := s.handleSyscall(syscallRequest{
		Data: syscallData{Syscall: unix.SYS_FCNTL},
		Dup: dupRequest{
			FD:    7,
			Cmd:   unix.F_DUPFD_CLOEXEC,
			Arg:   20,
			NewFD: 21,
		},
	}); err != nil {
		t.Fatalf("handle fcntl dup: %v", err)
	}

	got, ok := s.Registry().Lookup(21)
	if !ok {
		t.Fatal("expected duplicated state for fcntl result fd")
	}
	if got.OriginalHost != "api2.cursor.sh" || got.OriginalPort != 443 {
		t.Fatalf("got %#v", got)
	}
}

func TestSupervisorGetpeernameReturnsOriginalDestination(t *testing.T) {
	s, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	const childFD = 15
	s.Registry().Insert(SocketState{
		Kind:         KindTCP,
		ChildFD:      childFD,
		Family:       unix.AF_INET,
		OriginalHost: "93.184.216.34",
		OriginalPort: 443,
		RedirectAddr: "127.0.0.1:30443",
	})

	var rewritten DecodedSockaddr
	if err := s.handleSyscall(syscallRequest{
		Data: syscallData{Syscall: unix.SYS_GETPEERNAME},
		Getpeername: getpeernameRequest{
			ChildFD: childFD,
			WritePeername: func(addr DecodedSockaddr) error {
				rewritten = addr
				return nil
			},
		},
	}); err != nil {
		t.Fatalf("handle getpeername: %v", err)
	}

	if rewritten.Host != "93.184.216.34" || rewritten.Port != 443 {
		t.Fatalf("rewritten=%#v", rewritten)
	}
}
