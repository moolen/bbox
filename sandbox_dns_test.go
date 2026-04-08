package bbox

import (
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

	"golang.org/x/net/dns/dnsmessage"
)

func TestTransparentSandboxLibcGetaddrinfoUsesManagedDNS(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}

	dnsAddr, dnsTrace := startStubDNSServer(t)

	originalNewManagerDNSService := newManagerDNSService
	newManagerDNSService = func() *managerDNSService {
		return &managerDNSService{
			dialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
			servers:     []string{dnsAddr},
			timeout:     time.Second,
		}
	}
	t.Cleanup(func() {
		newManagerDNSService = originalNewManagerDNSService
	})

	hostClientPath, clientDir := buildLibcGetaddrinfoClient(t)
	sandboxClientDir := "/opt/libc-gai"
	sandboxClientPath := filepath.Join(sandboxClientDir, filepath.Base(hostClientPath))

	manager, err := NewProxyManager(ProxyOptions{
		MITM: MITMOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sandbox, err := manager.NewSandbox(ctx, SandboxOptions{
		Binaries:    []string{hostClientPath},
		Mounts:      []Mount{{Type: MountTypeBind, Source: clientDir, Target: sandboxClientDir, ReadOnly: true}},
		TrafficMode: TrafficModeTransparent,
		WorkDir:     "/tmp",
		Policy: NetworkPolicy{
			Rules: []PolicyRule{
				{HostPatterns: []string{`^example[.]com$`}},
				{IPCIDRs: []string{"127.0.0.0/8", "::1/128"}},
			},
		},
	})
	if err != nil {
		skipIfLoopbackSetupUnsupported(t, err)
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close sandbox: %v", err)
		}
	}()

	result, err := sandbox.Run(ctx, []string{sandboxClientPath, "example.com", "80"}, RunOptions{})
	if err != nil {
		t.Fatalf("run client: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected getaddrinfo client to succeed, exit=%d stdout=%q stderr=%q helperlog=%q dnstrace=%v", result.ExitCode, string(result.Stdout), string(result.Stderr), sandbox.helperLogContents(), dnsTrace.Snapshot())
	}
	if !strings.Contains(string(result.Stdout), "127.0.0.1") {
		t.Fatalf("expected IPv4 answer in stdout, got %q", string(result.Stdout))
	}
}

func TestTransparentSandboxAuditModeAllowsPolicyDeniedDNS(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("cc not available")
	}

	dnsAddr, _ := startStubDNSServer(t)

	originalNewManagerDNSService := newManagerDNSService
	newManagerDNSService = func() *managerDNSService {
		return &managerDNSService{
			dialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
			servers:     []string{dnsAddr},
			timeout:     time.Second,
		}
	}
	t.Cleanup(func() {
		newManagerDNSService = originalNewManagerDNSService
	})

	clientPath, clientDir := buildLibcGetaddrinfoClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	manager, err := NewProxyManager(ProxyOptions{
		MITM: MITMOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer func() {
		if closeErr := manager.Close(); closeErr != nil {
			t.Fatalf("close manager: %v", closeErr)
		}
	}()

	sandboxClientDir := "/workspace"
	sandboxClientPath := filepath.Join(sandboxClientDir, filepath.Base(clientPath))
	sandbox, err := manager.NewSandbox(ctx, SandboxOptions{
		Name:        "audit-dns-mode",
		Binaries:    []string{clientPath},
		Mounts:      []Mount{{Type: MountTypeBind, Source: clientDir, Target: sandboxClientDir, ReadOnly: true}},
		TrafficMode: TrafficModeTransparent,
		PolicyMode:  PolicyModeAudit,
		Policy: NetworkPolicy{
			Rules: []PolicyRule{
				{HostPatterns: []string{`^allowed[.]test$`}},
			},
		},
	})
	if err != nil {
		skipIfLoopbackSetupUnsupported(t, err)
		t.Fatalf("create sandbox: %v", err)
	}
	defer func() {
		if closeErr := sandbox.Close(); closeErr != nil {
			t.Fatalf("close sandbox: %v", closeErr)
		}
	}()

	result, err := sandbox.Run(ctx, []string{sandboxClientPath, "example.test", "80"}, RunOptions{})
	if err != nil {
		waitErr := "pending"
		select {
		case doneErr := <-sandbox.runtimeDone():
			waitErr = fmt.Sprintf("%v", doneErr)
		default:
		}
		processState := "<nil>"
		if state := sandbox.runtimeProcessState(); state != nil {
			processState = state.String()
		}
		t.Fatalf("run audit dns client: %v helperlog=%q helperwait=%s helperstate=%s", err, sandbox.helperLogContents(), waitErr, processState)
	}
	if result.ExitCode != 0 {
		t.Fatalf(
			"expected audit dns client to succeed, exit=%d stdout=%q stderr=%q helperlog=%q",
			result.ExitCode,
			string(result.Stdout),
			string(result.Stderr),
			sandbox.helperLogContents(),
		)
	}
	if !strings.Contains(string(result.Stdout), "127.0.0.1") {
		t.Fatalf("expected IPv4 answer in stdout, got %q helperlog=%q", string(result.Stdout), sandbox.helperLogContents())
	}
}

func buildLibcGetaddrinfoClient(t *testing.T) (string, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "libc-gai-")
	if err != nil {
		t.Fatalf("mkdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

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
  struct addrinfo *it = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(argv[1], argv[2], &hints, &res);
  if (rc != 0) {
    fprintf(stderr, "gai: %s\n", gai_strerror(rc));
    return 1;
  }
  char host[INET6_ADDRSTRLEN];
  for (it = res; it != NULL; it = it->ai_next) {
    void *addr = NULL;
    if (it->ai_family == AF_INET) {
      addr = &((struct sockaddr_in *)it->ai_addr)->sin_addr;
    } else if (it->ai_family == AF_INET6) {
      addr = &((struct sockaddr_in6 *)it->ai_addr)->sin6_addr;
    }
    if (addr != NULL && inet_ntop(it->ai_family, addr, host, sizeof(host)) != NULL) {
      puts(host);
    }
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
		t.Fatalf("build getaddrinfo client: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return binaryPath, dir
}

func skipIfLoopbackSetupUnsupported(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		return
	}
	message := err.Error()
	if strings.Contains(message, "loopback: Failed RTM_NEWADDR: Operation not permitted") {
		t.Skipf("transparent sandbox test requires loopback RTM_NEWADDR support inside bubblewrap: %v", err)
	}
}

type dnsStubTrace struct {
	mu     sync.Mutex
	events []string
}

func (d *dnsStubTrace) Add(event string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.events = append(d.events, event)
	d.mu.Unlock()
}

func (d *dnsStubTrace) Snapshot() []string {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.events...)
}

func startStubDNSServer(t *testing.T) (string, *dnsStubTrace) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	trace := &dnsStubTrace{}

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply, ok := packStubDNSResponse(t, buf[:n])
			if !ok {
				continue
			}
			trace.Add(describeDNSPacketForSandboxTest(t, buf[:n], reply))
			_, _ = conn.WriteTo(reply, addr)
		}
	}()

	return conn.LocalAddr().String(), trace
}

func packStubDNSResponse(t *testing.T, payload []byte) ([]byte, bool) {
	t.Helper()

	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		t.Fatalf("parse dns header: %v", err)
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		t.Fatalf("parse dns questions: %v", err)
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
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
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
		default:
			response.Header.RCode = dnsmessage.RCodeRefused
		}
	}

	reply, err := response.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}
	return reply, true
}

func describeDNSPacketForSandboxTest(t *testing.T, query, reply []byte) string {
	t.Helper()

	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		return fmt.Sprintf("query_parse=%v reply_len=%d", err, len(reply))
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return fmt.Sprintf("questions_parse=%v reply_len=%d", err, len(reply))
	}
	types := make([]string, 0, len(questions))
	for _, question := range questions {
		types = append(types, question.Type.String())
	}
	return fmt.Sprintf("types=%s reply_len=%d", strings.Join(types, ","), len(reply))
}
