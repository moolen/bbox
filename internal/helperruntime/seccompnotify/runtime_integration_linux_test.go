//go:build linux

package seccompnotify

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSupervisorStartRedirectsTCPConnectRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 2); s.close()",
		"198.51.100.77",
		"8443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected raw tcp accept")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsConnectedUDPDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query := []byte{0xde, 0xad, 0xbe, 0xef}
	reply := []byte{0xca, 0xfe, 0xba, 0xbe}

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			if !bytes.Equal(payload, query) {
				return nil, fmt.Errorf("payload=%x want=%x", payload, query)
			}
			return append([]byte(nil), reply...), nil
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys,binascii; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect((sys.argv[1], int(sys.argv[2]))); s.send(bytes.fromhex(sys.argv[3])); data=s.recv(512); sys.exit(0 if data == bytes.fromhex(sys.argv[4]) else 1)",
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsSendToDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query := []byte{0xde, 0xad, 0xfa, 0xce}
	reply := []byte{0xca, 0xfe, 0xba, 0xbe}

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			if !bytes.Equal(payload, query) {
				return nil, fmt.Errorf("payload=%x want=%x", payload, query)
			}
			return append([]byte(nil), reply...), nil
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; q=bytes.fromhex(sys.argv[3]); r=bytes.fromhex(sys.argv[4]); s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); sent=s.sendto(q, (sys.argv[1], int(sys.argv[2]))); data, addr=s.recvfrom(512); sys.exit(0 if sent == len(q) and data == r and addr[0] == sys.argv[1] and addr[1] == int(sys.argv[2]) else 1)",
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsSendMsgDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query := []byte{0xde, 0xad, 0xbe, 0xef}
	reply := []byte{0xba, 0xdc, 0x0f, 0xfe}

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			if !bytes.Equal(payload, query) {
				return nil, fmt.Errorf("payload=%x want=%x", payload, query)
			}
			return append([]byte(nil), reply...), nil
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; q=bytes.fromhex(sys.argv[3]); r=bytes.fromhex(sys.argv[4]); s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); sent=s.sendmsg([q], [], 0, (sys.argv[1], int(sys.argv[2]))); data, anc, flags, addr=s.recvmsg(512); sys.exit(0 if sent == len(q) and data == r and addr[0] == sys.argv[1] and addr[1] == int(sys.argv[2]) else 1)",
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsRecvMsgPeekDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query := []byte{0xde, 0xad, 0xbe, 0xef}
	reply := []byte{0xba, 0xdc, 0x0f, 0xfe}

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			if !bytes.Equal(payload, query) {
				return nil, fmt.Errorf("payload=%x want=%x", payload, query)
			}
			return append([]byte(nil), reply...), nil
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; q=bytes.fromhex(sys.argv[3]); r=bytes.fromhex(sys.argv[4]); s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sent=s.sendmsg([q], [], 0, (sys.argv[1], int(sys.argv[2]))); d1, a1, f1, addr1=s.recvmsg(512, 0, socket.MSG_PEEK); d2, a2, f2, addr2=s.recvmsg(512); sys.exit(0 if sent == len(q) and d1 == r and d2 == r and addr1[0] == sys.argv[1] and addr1[1] == int(sys.argv[2]) and addr2[0] == sys.argv[1] and addr2[1] == int(sys.argv[2]) else 1)",
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsSendMMsgDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query1 := []byte{0xde, 0xad, 0xfa, 0xce}
	reply1 := []byte{0xca, 0xfe, 0xba, 0xbe}
	query2 := []byte{0xde, 0xad, 0xbe, 0xef}
	reply2 := []byte{0xba, 0xdc, 0x0f, 0xfe}

	var calls int
	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			calls++
			switch {
			case bytes.Equal(payload, query1):
				return append([]byte(nil), reply1...), nil
			case bytes.Equal(payload, query2):
				return append([]byte(nil), reply2...), nil
			default:
				return nil, fmt.Errorf("payload=%x did not match expected queries", payload)
			}
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
		if calls != 2 {
			t.Fatalf("dns round trips=%d want=2", calls)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		`import ctypes, socket, sys
class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
class MsgHdr(ctypes.Structure):
    _fields_ = [("msg_name", ctypes.c_void_p), ("msg_namelen", ctypes.c_uint32), ("_pad0", ctypes.c_uint32), ("msg_iov", ctypes.POINTER(IOVec)), ("msg_iovlen", ctypes.c_size_t), ("msg_control", ctypes.c_void_p), ("msg_controllen", ctypes.c_size_t), ("msg_flags", ctypes.c_int), ("_pad1", ctypes.c_int)]
class MMsgHdr(ctypes.Structure):
    _fields_ = [("msg_hdr", MsgHdr), ("msg_len", ctypes.c_uint32), ("_pad", ctypes.c_uint32)]
class SockaddrIn(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ushort), ("sin_port", ctypes.c_ushort), ("sin_addr", ctypes.c_ubyte * 4), ("sin_zero", ctypes.c_ubyte * 8)]
libc = ctypes.CDLL(None, use_errno=True)
sendmmsg = libc.sendmmsg
sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_uint]
sendmmsg.restype = ctypes.c_int
recvmmsg = libc.recvmmsg
recvmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
recvmmsg.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fd = s.fileno()
host = sys.argv[1]
port = int(sys.argv[2])
queries = [bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4])]
replies = [bytes.fromhex(sys.argv[5]), bytes.fromhex(sys.argv[6])]
addr_bytes = socket.inet_aton(host)
sockaddr = SockaddrIn()
sockaddr.sin_family = socket.AF_INET
sockaddr.sin_port = socket.htons(port)
for i, b in enumerate(addr_bytes):
    sockaddr.sin_addr[i] = b
sockaddr_ptr = ctypes.cast(ctypes.pointer(sockaddr), ctypes.c_void_p)
send_vec = (MMsgHdr * 2)()
send_bufs = []
send_iovs = []
for i, payload in enumerate(queries):
    buf = ctypes.create_string_buffer(payload)
    send_bufs.append(buf)
    iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    send_iovs.append(iov)
    send_vec[i].msg_hdr.msg_name = sockaddr_ptr
    send_vec[i].msg_hdr.msg_namelen = ctypes.sizeof(sockaddr)
    send_vec[i].msg_hdr.msg_iov = ctypes.pointer(send_iovs[i])
    send_vec[i].msg_hdr.msg_iovlen = 1
    send_vec[i].msg_hdr.msg_control = None
    send_vec[i].msg_hdr.msg_controllen = 0
    send_vec[i].msg_hdr.msg_flags = 0
sent = sendmmsg(fd, send_vec, 2, 0)
if sent != 2:
    sys.exit(1)
recv_vec = (MMsgHdr * 2)()
recv_bufs = []
recv_iovs = []
recv_names = []
for i in range(2):
    buf = ctypes.create_string_buffer(512)
    recv_bufs.append(buf)
    iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), 512)
    recv_iovs.append(iov)
    name = ctypes.create_string_buffer(ctypes.sizeof(sockaddr))
    recv_names.append(name)
    recv_vec[i].msg_hdr.msg_name = ctypes.cast(name, ctypes.c_void_p)
    recv_vec[i].msg_hdr.msg_namelen = ctypes.sizeof(sockaddr)
    recv_vec[i].msg_hdr.msg_iov = ctypes.pointer(recv_iovs[i])
    recv_vec[i].msg_hdr.msg_iovlen = 1
received = recvmmsg(fd, recv_vec, 2, 0, None)
if received != 2:
    sys.exit(1)
for i in range(2):
    if recv_bufs[i].raw[:recv_vec[i].msg_len] != replies[i]:
        sys.exit(1)
    got = SockaddrIn.from_buffer_copy(recv_names[i].raw[:ctypes.sizeof(sockaddr)])
    if socket.inet_ntoa(bytes(got.sin_addr)) != host or socket.ntohs(got.sin_port) != port:
        sys.exit(1)
sys.exit(0)`,
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query1),
		fmt.Sprintf("%x", query2),
		fmt.Sprintf("%x", reply1),
		fmt.Sprintf("%x", reply2),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsPPollDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query := []byte{0xde, 0xad, 0xfa, 0xce}
	reply := []byte{0xca, 0xfe, 0xba, 0xbe}

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			if !bytes.Equal(payload, query) {
				return nil, fmt.Errorf("payload=%x want=%x", payload, query)
			}
			return append([]byte(nil), reply...), nil
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		`import ctypes, socket, sys
class PollFD(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_int), ("events", ctypes.c_short), ("revents", ctypes.c_short)]
class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
libc = ctypes.CDLL(None, use_errno=True)
ppoll = libc.ppoll
ppoll.argtypes = [ctypes.POINTER(PollFD), ctypes.c_ulong, ctypes.POINTER(Timespec), ctypes.c_void_p]
ppoll.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
q = bytes.fromhex(sys.argv[3])
r = bytes.fromhex(sys.argv[4])
sent = s.sendto(q, (sys.argv[1], int(sys.argv[2])))
pfd = PollFD(s.fileno(), 0x0001, 0)
timeout = Timespec(2, 0)
ready = ppoll(ctypes.byref(pfd), 1, ctypes.byref(timeout), None)
data, addr = s.recvfrom(512)
sys.exit(0 if sent == len(q) and ready == 1 and (pfd.revents & 0x0001) and data == r and addr[0] == sys.argv[1] and addr[1] == int(sys.argv[2]) else 1)`,
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorAllowsNonDNSUDPConnectRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			return nil, fmt.Errorf("unexpected dns round trip for %s %s:%d", network, host, port)
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect((sys.argv[1], int(sys.argv[2]))); sent=s.send(b'x'); sys.exit(0 if sent == 1 else 1)",
		"127.0.0.1",
		"1025",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorRejectsDNSTCPRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2); ok=False\ntry:\n s.connect((sys.argv[1], int(sys.argv[2]))); ok=True\nexcept OSError:\n ok=False\nsys.exit(1 if ok else 0)",
		"192.0.2.53",
		"53",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("unexpected raw tcp accept for dns over tcp")
	case <-time.After(250 * time.Millisecond):
	}
}

func TestSupervisorStartRedirectsTCPConnectAfterDupRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import os,socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); dup_fd=os.dup(s.fileno()); s.close(); d=socket.socket(fileno=dup_fd); d.connect((sys.argv[1], int(sys.argv[2]))); d.close()",
		"198.51.100.88",
		"9443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected raw tcp accept after dup")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsNCConnectRuntime(t *testing.T) {
	ncPath, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		ncPath,
		"-n",
		"-z",
		"-v",
		"-w",
		"2",
		"198.51.100.77",
		"8443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected nc accept")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsTCPConnectRuntimeWithDNSRoundTripOnly(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw ingress: %v", err)
	}
	t.Cleanup(func() { _ = rawListener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := rawListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	s, err := NewSupervisor(RuntimeTargets{
		RawTCPAddr: rawListener.Addr().String(),
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			return nil, fmt.Errorf("unexpected dns round trip for %s %s:%d", network, host, port)
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		"import socket,sys; s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 2); s.close()",
		"198.51.100.77",
		"8443",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected tcp accept with dns round trip only")
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestLauncherNoopWithoutEnv(t *testing.T) {}

func TestResolveLauncherCommandUsesSiblingLauncher(t *testing.T) {
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "bbox-helper")
	launcherPath := filepath.Join(dir, "bbox-seccomp-launcher")
	if err := os.WriteFile(launcherPath, []byte("launcher"), 0o755); err != nil {
		t.Fatalf("write launcher: %v", err)
	}

	prevExecutablePath := launcherExecutablePath
	prevPathExists := launcherPathExists
	launcherExecutablePath = func() (string, error) { return helperPath, nil }
	launcherPathExists = func(path string) bool { return path == launcherPath }
	t.Cleanup(func() {
		launcherExecutablePath = prevExecutablePath
		launcherPathExists = prevPathExists
	})

	got, args, err := resolveLauncherCommand()
	if err != nil {
		t.Fatalf("resolveLauncherCommand() error = %v", err)
	}
	if got != launcherPath {
		t.Fatalf("resolveLauncherCommand() = %q, want %q", got, launcherPath)
	}
	if len(args) != 0 {
		t.Fatalf("resolveLauncherCommand() args = %#v, want nil", args)
	}
}

func setLauncherCommandForTest(t *testing.T, fn func() (string, []string, error)) func() {
	t.Helper()
	launcherCommandOverrideMu.Lock()
	prev := launcherCommandOverride
	launcherCommandOverride = fn
	launcherCommandOverrideMu.Unlock()
	return func() {
		launcherCommandOverrideMu.Lock()
		launcherCommandOverride = prev
		launcherCommandOverrideMu.Unlock()
	}
}

var (
	launcherBuildOnce sync.Once
	launcherBuildPath string
	launcherBuildErr  error
)

func buildLauncherBinary(t *testing.T) string {
	t.Helper()
	launcherBuildOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			launcherBuildErr = err
			return
		}
		repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
		buildDir, err := os.MkdirTemp("", "bbox-seccompnotify-launcher-")
		if err != nil {
			launcherBuildErr = err
			return
		}
		launcherBuildPath = filepath.Join(buildDir, "bbox-seccomp-launcher")

		cmd := exec.Command(
			"cc",
			"-O2",
			"-static",
			"-o", launcherBuildPath,
			"./cmd/bbox-seccomp-launcher/main.c",
		)
		cmd.Dir = repoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			launcherBuildErr = fmt.Errorf("build launcher: %w: %s", err, strings.TrimSpace(string(output)))
			return
		}

		fileOutput, err := exec.Command("file", launcherBuildPath).CombinedOutput()
		if err != nil {
			launcherBuildErr = fmt.Errorf("inspect launcher binary: %w: %s", err, strings.TrimSpace(string(fileOutput)))
			return
		}
		if !strings.Contains(string(fileOutput), "statically linked") && !strings.Contains(string(fileOutput), "static-pie linked") {
			launcherBuildErr = fmt.Errorf("launcher binary is not static: %s", strings.TrimSpace(string(fileOutput)))
		}
	})
	if launcherBuildErr != nil {
		t.Fatalf("build launcher: %v", launcherBuildErr)
	}
	return launcherBuildPath
}
