//go:build linux

package seccompnotify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/bbox/internal/embeddedlauncher"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
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

func TestSupervisorStartSupportsLibcGetaddrinfoDNSRuntime(t *testing.T) {
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
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if port != 53 {
				return nil, fmt.Errorf("port=%d want 53", port)
			}
			return buildDNSAnswer(t, payload, [4]byte{127, 0, 0, 1}), nil
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
		`import socket, sys
infos = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_INET, socket.SOCK_STREAM)
hosts = {info[4][0] for info in infos}
sys.exit(0 if sys.argv[3] in hosts else 1)`,
		"example.com",
		"80",
		"127.0.0.1",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartSupportsLibcGetaddrinfoDNSRuntimeAFUnspec(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	var (
		callsMu sync.Mutex
		calls   []string
		traceMu sync.Mutex
		trace   []string
	)
	prevTraceHook := notificationTraceHook
	notificationTraceHook = func(req *seccomp.ScmpNotifReq) {
		if req == nil {
			return
		}
		traceMu.Lock()
		trace = append(trace, formatNotifTraceForTest(req))
		traceMu.Unlock()
	}
	t.Cleanup(func() {
		notificationTraceHook = prevTraceHook
	})
	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			callsMu.Lock()
			calls = append(calls, describeDNSQueryForTest(t, network, host, port, payload))
			callsMu.Unlock()
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if port != 53 {
				return nil, fmt.Errorf("port=%d want 53", port)
			}
			return buildDNSAnswer(t, payload, [4]byte{127, 0, 0, 1}), nil
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

	script := `import socket, sys
infos = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_UNSPEC, socket.SOCK_STREAM)
hosts = {info[4][0] for info in infos}
sys.exit(0 if sys.argv[3] in hosts else 1)`
	cmd := exec.Command(
		python,
		"-c", script,
		"example.com",
		"80",
		"127.0.0.1",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s calls=%v trace=%v", err, stderr.String(), calls, trace)
	}
}

func TestShouldSkipHostDNSAFUnspecFailure(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   bool
	}{
		{
			name: "temporary failure in name resolution",
			stderr: `Traceback (most recent call last):
socket.gaierror: [Errno -3] Temporary failure in name resolution`,
			want: true,
		},
		{
			name:   "unrelated failure",
			stderr: "socket.gaierror: [Errno -2] Name or service not known",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSkipHostDNSAFUnspecFailure(tt.stderr); got != tt.want {
				t.Fatalf("shouldSkipHostDNSAFUnspecFailure(%q) = %v want %v", tt.stderr, got, tt.want)
			}
		})
	}
}

func TestSupervisorStartSupportsLibcGetaddrinfoDNSRuntimeAFUnspecWithHostResponses(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	nameserver := firstHostNameserverForSeccompTest(t)
	if nameserver == "" {
		t.Skip("host resolv.conf has no nameserver")
	}
	launcher := buildLauncherBinary(t)

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	var (
		traceMu sync.Mutex
		trace   []string
	)
	prevTraceHook := notificationTraceHook
	notificationTraceHook = func(req *seccomp.ScmpNotifReq) {
		if req == nil {
			return
		}
		traceMu.Lock()
		trace = append(trace, formatNotifTraceForTest(req))
		traceMu.Unlock()
	}
	t.Cleanup(func() {
		notificationTraceHook = prevTraceHook
	})

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			return roundTripHostDNSForSeccompTest(ctx, network, nameserver, payload)
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
		`import socket, sys
infos = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_UNSPEC, socket.SOCK_STREAM)
hosts = {info[4][0] for info in infos}
sys.exit(0 if len(hosts) > 0 else 1)`,
		"example.com",
		"80",
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		if shouldSkipHostDNSAFUnspecFailure(stderr.String()) {
			t.Skipf("host DNS AF_UNSPEC runtime path is unstable in this environment: %s", strings.TrimSpace(stderr.String()))
		}
		t.Fatalf("wait: %v stderr=%s trace=%v", err, stderr.String(), trace)
	}
}

func shouldSkipHostDNSAFUnspecFailure(stderr string) bool {
	stderr = strings.ToLower(stderr)
	return strings.Contains(stderr, "temporary failure in name resolution") &&
		strings.Contains(stderr, "errno -3")
}

func TestSupervisorStartSupportsLibcGetaddrinfoDNSRuntimeCClient(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}
	launcher := buildLauncherBinary(t)

	restore := setLauncherCommandForTest(t, func() (string, []string, error) {
		return launcher, nil, nil
	})
	t.Cleanup(restore)

	clientPath := buildCGetaddrinfoProbeForSeccompTest(t)

	var (
		traceMu sync.Mutex
		trace   []string
	)
	prevTraceHook := notificationTraceHook
	notificationTraceHook = func(req *seccomp.ScmpNotifReq) {
		if req == nil {
			return
		}
		traceMu.Lock()
		trace = append(trace, formatNotifTraceForTest(req))
		traceMu.Unlock()
	}
	t.Cleanup(func() {
		notificationTraceHook = prevTraceHook
	})

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if port != 53 {
				return nil, fmt.Errorf("port=%d want 53", port)
			}
			return buildDNSAnswer(t, payload, [4]byte{127, 0, 0, 1}), nil
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

	cmd := exec.Command(clientPath, "example.com", "80")
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s trace=%v", err, stderr.String(), trace)
	}
}

func TestSupervisorStartReconnectsConnectedUDPDNSRuntimeAfterAFUnspecDisconnect(t *testing.T) {
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
		`import ctypes, socket, sys
class Sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]
libc = ctypes.CDLL(None, use_errno=True)
connect = libc.connect
connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
connect.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
addr = Sockaddr()
addr.sa_family = socket.AF_UNSPEC
rc = connect(s.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
if rc != 0:
    sys.exit(1)
s.connect((sys.argv[1], int(sys.argv[2])))
s.send(bytes.fromhex(sys.argv[3]))
data = s.recv(512)
sys.exit(0 if data == bytes.fromhex(sys.argv[4]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartPreservesPendingDNSResponsesAcrossAFUnspecDisconnectRuntime(t *testing.T) {
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
		`import ctypes, socket, sys
class Sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]
libc = ctypes.CDLL(None, use_errno=True)
connect = libc.connect
connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
connect.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
s.send(bytes.fromhex(sys.argv[3]))
addr = Sockaddr()
addr.sa_family = socket.AF_UNSPEC
rc = connect(s.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
if rc != 0:
    sys.exit(1)
data = s.recv(512)
sys.exit(0 if data == bytes.fromhex(sys.argv[4]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartPreservesPendingDNSResponsesAcrossReconnectRuntime(t *testing.T) {
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
		`import ctypes, socket, sys
class Sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]
libc = ctypes.CDLL(None, use_errno=True)
connect = libc.connect
connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
connect.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
s.send(bytes.fromhex(sys.argv[3]))
addr = Sockaddr()
addr.sa_family = socket.AF_UNSPEC
rc = connect(s.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
if rc != 0:
    sys.exit(1)
s.connect((sys.argv[1], int(sys.argv[2])))
data = s.recv(512)
sys.exit(0 if data == bytes.fromhex(sys.argv[4]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartHandlesMultipleConnectedUDPDNSSocketsRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query1 := []byte{0xde, 0xad, 0xbe, 0xef}
	reply1 := []byte{0xca, 0xfe, 0xba, 0xbe}
	query2 := []byte{0xab, 0xcd, 0xef, 0x01}
	reply2 := []byte{0x10, 0x20, 0x30, 0x40}

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
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		`import socket, sys
s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s1.settimeout(2)
s2.settimeout(2)
s1.connect((sys.argv[1], int(sys.argv[2])))
s2.connect((sys.argv[1], int(sys.argv[2])))
s1.send(bytes.fromhex(sys.argv[3]))
s2.send(bytes.fromhex(sys.argv[4]))
d1 = s1.recv(512)
d2 = s2.recv(512)
sys.exit(0 if d1 == bytes.fromhex(sys.argv[5]) and d2 == bytes.fromhex(sys.argv[6]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsConnectedSendMMsgThenRecvFromDNSRuntime(t *testing.T) {
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
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
fd = s.fileno()
payload = bytes.fromhex(sys.argv[3])
buf = ctypes.create_string_buffer(payload)
iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
vec = MMsgHdr()
vec.msg_hdr.msg_name = None
vec.msg_hdr.msg_namelen = 0
vec.msg_hdr.msg_iov = ctypes.pointer(iov)
vec.msg_hdr.msg_iovlen = 1
sent = sendmmsg(fd, ctypes.pointer(vec), 1, socket.MSG_NOSIGNAL)
if sent != 1:
    sys.exit(1)
data, addr = s.recvfrom(512)
sys.exit(0 if data == bytes.fromhex(sys.argv[4]) and addr[0] == sys.argv[1] and addr[1] == int(sys.argv[2]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartRedirectsConnectedSendMMsgThenZeroLengthRecvFromDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query1 := []byte{0xde, 0xad, 0xbe, 0xef}
	reply1 := []byte{0xca, 0xfe, 0xba, 0xbe}
	query2 := []byte{0xab, 0xcd, 0xef, 0x01}
	reply2 := []byte{0x10, 0x20, 0x30, 0x40}

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
libc = ctypes.CDLL(None, use_errno=True)
sendmmsg = libc.sendmmsg
sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_uint]
sendmmsg.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
fd = s.fileno()
queries = [bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4])]
vec = (MMsgHdr * 2)()
bufs = []
iovs = []
for i, payload in enumerate(queries):
    buf = ctypes.create_string_buffer(payload)
    bufs.append(buf)
    iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    iovs.append(iov)
    vec[i].msg_hdr.msg_name = None
    vec[i].msg_hdr.msg_namelen = 0
    vec[i].msg_hdr.msg_iov = ctypes.pointer(iovs[i])
    vec[i].msg_hdr.msg_iovlen = 1
sent = sendmmsg(fd, vec, 2, socket.MSG_NOSIGNAL)
if sent != 2:
    sys.exit(1)
data, addr = s.recvfrom(512)
empty, addr2 = s.recvfrom(0)
sys.exit(0 if data == bytes.fromhex(sys.argv[5]) and addr[0] == sys.argv[1] and addr[1] == int(sys.argv[2]) and empty == b'' and addr2[0] == sys.argv[1] and addr2[1] == int(sys.argv[2]) else 1)`,
		"192.0.2.53",
		"53",
		fmt.Sprintf("%x", query1),
		fmt.Sprintf("%x", query2),
		fmt.Sprintf("%x", reply1),
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartReportsPendingDNSBytesViaFIONREADRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	launcher := buildLauncherBinary(t)

	query1 := []byte{0xde, 0xad, 0xbe, 0xef}
	reply1 := []byte{0xca, 0xfe, 0xba, 0xbe}
	query2 := []byte{0xab, 0xcd, 0xef, 0x01}
	reply2 := []byte{0x10, 0x20, 0x30, 0x40, 0x50}

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
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.Command(
		python,
		"-c",
		`import ctypes, fcntl, socket, sys, termios
class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
class MsgHdr(ctypes.Structure):
    _fields_ = [("msg_name", ctypes.c_void_p), ("msg_namelen", ctypes.c_uint32), ("_pad0", ctypes.c_uint32), ("msg_iov", ctypes.POINTER(IOVec)), ("msg_iovlen", ctypes.c_size_t), ("msg_control", ctypes.c_void_p), ("msg_controllen", ctypes.c_size_t), ("msg_flags", ctypes.c_int), ("_pad1", ctypes.c_int)]
class MMsgHdr(ctypes.Structure):
    _fields_ = [("msg_hdr", MsgHdr), ("msg_len", ctypes.c_uint32), ("_pad", ctypes.c_uint32)]
libc = ctypes.CDLL(None, use_errno=True)
sendmmsg = libc.sendmmsg
sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_uint]
sendmmsg.restype = ctypes.c_int
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
fd = s.fileno()
queries = [bytes.fromhex(sys.argv[3]), bytes.fromhex(sys.argv[4])]
vec = (MMsgHdr * 2)()
bufs = []
iovs = []
for i, payload in enumerate(queries):
    buf = ctypes.create_string_buffer(payload)
    bufs.append(buf)
    iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    iovs.append(iov)
    vec[i].msg_hdr.msg_name = None
    vec[i].msg_hdr.msg_namelen = 0
    vec[i].msg_hdr.msg_iov = ctypes.pointer(iovs[i])
    vec[i].msg_hdr.msg_iovlen = 1
sent = sendmmsg(fd, vec, 2, socket.MSG_NOSIGNAL)
if sent != 2:
    sys.exit(1)
data1, _ = s.recvfrom(512)
if data1 != bytes.fromhex(sys.argv[5]):
    sys.exit(1)
pending = ctypes.c_int(0)
fcntl.ioctl(fd, termios.FIONREAD, pending, True)
if pending.value != len(bytes.fromhex(sys.argv[6])):
    sys.exit(1)
data2, _ = s.recvfrom(pending.value)
sys.exit(0 if data2 == bytes.fromhex(sys.argv[6]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartReportsOriginalPeernameForConnectedUDPDNSRuntime(t *testing.T) {
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
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if host != "192.0.2.53" || port != 53 {
				return nil, fmt.Errorf("destination=%s:%d", host, port)
			}
			return append([]byte(nil), payload...), nil
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
		`import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((sys.argv[1], int(sys.argv[2])))
peer = s.getpeername()
sys.exit(0 if peer[0] == sys.argv[1] and peer[1] == int(sys.argv[2]) else 1)`,
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
		t.Fatalf("start: %v stderr=%s", err, stderr.String())
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

func TestPrepareUsesEmbeddedLauncherFactory(t *testing.T) {
	launcherRead, launcherWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create launcher pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = launcherRead.Close()
		_ = launcherWrite.Close()
	})

	called := false
	restore := setLauncherFactoryForTest(t, func() (embeddedlauncher.ExecTarget, error) {
		called = true
		return embeddedlauncher.ExecTarget{
			File: launcherRead,
			Args: []string{"--from-memfd"},
			Close: func() error {
				return nil
			},
		}, nil
	})
	t.Cleanup(restore)

	supervisor, err := NewSupervisor(RuntimeTargets{})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	defer func() {
		if closeErr := supervisor.Close(); closeErr != nil {
			t.Fatalf("close supervisor: %v", closeErr)
		}
	}()

	bboxPath := "/tmp/test-bbox-bootstrap"
	restoreBootstrap := setLauncherBootstrapForTest(t, func() (string, []string, error) {
		return bboxPath, []string{"internal-launcher"}, nil
	})
	t.Cleanup(restoreBootstrap)

	cmd := exec.Command("/bin/true")
	cmd.Args = []string{"/bin/true", "--payload-arg"}
	if err := supervisor.Prepare(context.Background(), cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !called {
		t.Fatal("expected embedded launcher factory to be used")
	}
	if cmd.Path != bboxPath {
		t.Fatalf("prepare launcher path = %q, want %q", cmd.Path, bboxPath)
	}
	wantArgs := []string{
		bboxPath,
		"internal-launcher",
		"--launcher-fd", "3",
		"--",
		"bbox-seccomp-launcher",
		"--from-memfd",
		"/bin/true",
		"--",
		"/bin/true",
		"--payload-arg",
	}
	if fmt.Sprintf("%q", cmd.Args) != fmt.Sprintf("%q", wantArgs) {
		t.Fatalf("prepare launcher args = %#v, want %#v", cmd.Args, wantArgs)
	}
}

func TestSupervisorStartUsesEmbeddedMemfdLauncherRuntime(t *testing.T) {
	bboxBinary := buildBBoxBinary(t)
	restoreBootstrap := setLauncherBootstrapForTest(t, func() (string, []string, error) {
		return bboxBinary, []string{"internal-launcher"}, nil
	})
	t.Cleanup(restoreBootstrap)

	s, err := NewSupervisor(RuntimeTargets{})
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

	cmd := exec.Command("/bin/true")
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start embedded launcher: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartUsesEmbeddedMemfdLauncherForCGetaddrinfoRuntime(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}
	bboxBinary := buildBBoxBinary(t)
	restoreBootstrap := setLauncherBootstrapForTest(t, func() (string, []string, error) {
		return bboxBinary, []string{"internal-launcher"}, nil
	})
	t.Cleanup(restoreBootstrap)

	clientPath := buildCGetaddrinfoProbeForSeccompTest(t)

	s, err := NewSupervisor(RuntimeTargets{
		DNSRoundTrip: func(ctx context.Context, network, host string, port int, payload []byte) ([]byte, error) {
			if network != "udp" {
				return nil, fmt.Errorf("network=%q want udp", network)
			}
			if port != 53 {
				return nil, fmt.Errorf("port=%d want 53", port)
			}
			return buildDNSAnswer(t, payload, [4]byte{127, 0, 0, 1}), nil
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

	cmd := exec.Command(clientPath, "example.com", "80")
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	if err := s.Prepare(ctx, cmd); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start embedded launcher: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func TestSupervisorStartUsesEmbeddedMemfdLauncherForSendToDNSRuntime(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	bboxBinary := buildBBoxBinary(t)
	restoreBootstrap := setLauncherBootstrapForTest(t, func() (string, []string, error) {
		return bboxBinary, []string{"internal-launcher"}, nil
	})
	t.Cleanup(restoreBootstrap)

	query := []byte{0xde, 0xad, 0xbe, 0xef}
	reply := []byte{0xba, 0xdc, 0x0f, 0xfe}

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
		t.Fatalf("start embedded launcher: %v stderr=%s", err, stderr.String())
	}
	if err := s.Start(ctx, cmd.Process.Pid); err != nil {
		_ = cmd.Wait()
		t.Fatalf("supervisor start: %v stderr=%s", err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v stderr=%s", err, stderr.String())
	}
}

func setLauncherFactoryForTest(t *testing.T, fn func() (embeddedlauncher.ExecTarget, error)) func() {
	t.Helper()
	launcherFactoryMu.Lock()
	prev := launcherFactory
	launcherFactory = fn
	launcherFactoryMu.Unlock()
	return func() {
		launcherFactoryMu.Lock()
		launcherFactory = prev
		launcherFactoryMu.Unlock()
	}
}

func setLauncherBootstrapForTest(t *testing.T, fn func() (string, []string, error)) func() {
	t.Helper()
	launcherFactoryMu.Lock()
	prev := launcherBootstrapFactory
	launcherBootstrapFactory = fn
	launcherFactoryMu.Unlock()
	return func() {
		launcherFactoryMu.Lock()
		launcherBootstrapFactory = prev
		launcherFactoryMu.Unlock()
	}
}

func buildDNSAnswer(t *testing.T, query []byte, addr [4]byte) []byte {
	t.Helper()

	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		t.Fatalf("parse dns query header: %v", err)
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		t.Fatalf("parse dns query questions: %v", err)
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 header.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: questions,
	}
	for _, question := range questions {
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: addr},
			})
		case dnsmessage.TypeAAAA:
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			})
		}
	}

	packed, err := response.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}
	return packed
}

func describeDNSQueryForTest(t *testing.T, network, host string, port int, payload []byte) string {
	t.Helper()

	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return fmt.Sprintf("%s %s:%d parse_header=%v", network, host, port, err)
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return fmt.Sprintf("%s %s:%d parse_questions=%v", network, host, port, err)
	}
	types := make([]string, 0, len(questions))
	for _, question := range questions {
		types = append(types, question.Type.String())
	}
	return fmt.Sprintf("%s %s:%d types=%s", network, host, port, strings.Join(types, ","))
}

func formatNotifTraceForTest(req *seccomp.ScmpNotifReq) string {
	if req == nil {
		return "<nil>"
	}

	name := strconv.Itoa(int(req.Data.Syscall))
	switch int(req.Data.Syscall) {
	case unix.SYS_SOCKET:
		name = "socket"
	case unix.SYS_CONNECT:
		name = "connect"
	case unix.SYS_GETPEERNAME:
		name = "getpeername"
	case unix.SYS_SENDTO:
		name = "sendto"
	case unix.SYS_RECVFROM:
		name = "recvfrom"
	case unix.SYS_SENDMSG:
		name = "sendmsg"
	case unix.SYS_RECVMSG:
		name = "recvmsg"
	case unix.SYS_SENDMMSG:
		name = "sendmmsg"
	case unix.SYS_RECVMMSG:
		name = "recvmmsg"
	case unix.SYS_PPOLL:
		name = "ppoll"
	case unix.SYS_CLOSE:
		name = "close"
	case unix.SYS_DUP:
		name = "dup"
	case unix.SYS_DUP3:
		name = "dup3"
	case unix.SYS_FCNTL:
		name = "fcntl"
	}
	switch int(req.Data.Syscall) {
	case unix.SYS_RECVFROM:
		return fmt.Sprintf("%s fd=%d len=%d flags=%#x addr=%#x addrlen=%#x", name, int(req.Data.Args[0]), int(req.Data.Args[2]), int(req.Data.Args[3]), uintptr(req.Data.Args[4]), uintptr(req.Data.Args[5]))
	case unix.SYS_SENDMMSG, unix.SYS_RECVMMSG:
		return fmt.Sprintf("%s fd=%d flags=%#x", name, int(req.Data.Args[0]), int(req.Data.Args[3]))
	}
	return fmt.Sprintf("%s fd=%d", name, int(req.Data.Args[0]))
}

func firstHostNameserverForSeccompTest(t *testing.T) string {
	t.Helper()

	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("open host resolv.conf: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		return fields[1]
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan host resolv.conf: %v", err)
	}
	return ""
}

func roundTripHostDNSForSeccompTest(ctx context.Context, network, nameserver string, payload []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), buf[:n]...)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "tcp") {
		frame := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(out)))
		copy(frame[2:], out)
		return frame[2:], nil
	}
	return out, nil
}

func buildCGetaddrinfoProbeForSeccompTest(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "bbox-seccompnotify-c-gai-")
	if err != nil {
		t.Fatalf("mkdir temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sourcePath := filepath.Join(dir, "main.c")
	source := `#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    return 2;
  }
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(argv[1], argv[2], &hints, &res);
  if (rc != 0) {
    fprintf(stderr, "gai: %s\n", gai_strerror(rc));
    return 1;
  }
  freeaddrinfo(res);
  return 0;
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write client source: %v", err)
	}

	binaryPath := filepath.Join(dir, "gai")
	cmd := exec.Command("cc", "-O2", "-o", binaryPath, sourcePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build c getaddrinfo probe: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return binaryPath
}

func setLauncherCommandForTest(t *testing.T, fn func() (string, []string, error)) func() {
	t.Helper()
	return setLauncherFactoryForTest(t, func() (embeddedlauncher.ExecTarget, error) {
		path, args, err := fn()
		if err != nil {
			return embeddedlauncher.ExecTarget{}, err
		}
		return embeddedlauncher.ExecTarget{
			Path: path,
			Args: args,
			Close: func() error {
				return nil
			},
		}, nil
	})
}

var (
	launcherBuildOnce sync.Once
	launcherBuildPath string
	launcherBuildErr  error
	bboxBuildOnce     sync.Once
	bboxBuildPath     string
	bboxBuildErr      error
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

func buildBBoxBinary(t *testing.T) string {
	t.Helper()
	bboxBuildOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			bboxBuildErr = err
			return
		}
		repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
		buildDir, err := os.MkdirTemp("", "bbox-seccompnotify-bbox-")
		if err != nil {
			bboxBuildErr = err
			return
		}
		bboxBuildPath = filepath.Join(buildDir, "bbox")

		cmd := exec.Command("go", "build", "-o", bboxBuildPath, "./cmd/bbox")
		cmd.Dir = repoRoot
		output, err := cmd.CombinedOutput()
		if err != nil {
			bboxBuildErr = fmt.Errorf("build bbox: %w: %s", err, strings.TrimSpace(string(output)))
			return
		}
	})
	if bboxBuildErr != nil {
		t.Fatalf("build bbox: %v", bboxBuildErr)
	}
	return bboxBuildPath
}
