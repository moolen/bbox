package bbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/moolen/bbox/internal/helperproto"
	"golang.org/x/net/dns/dnsmessage"
)

func TestSystemDNSServersReadsHostResolvConf(t *testing.T) {
	hostNameservers := hostNameserverAddrs(t)
	if len(hostNameservers) == 0 {
		t.Skip("host resolv.conf has no nameserver entries")
	}

	got := systemDNSServers()
	if len(got) < len(hostNameservers) {
		t.Fatalf("systemDNSServers() returned %d entries, want at least %d: %#v", len(got), len(hostNameservers), got)
	}
	for i, want := range hostNameservers {
		if got[i] != want {
			t.Fatalf("systemDNSServers()[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestProxyManagerHandleDNSRequestAppliesPolicyAndAudit(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{
			{HostPatterns: []string{"^allowed\\.example\\.com$"}},
		},
	})

	manager := newProxyManager(policy)
	sandboxID := "sandbox-dns-policy"
	if err := manager.registerSandbox(sandboxID, policy); err != nil {
		t.Fatalf("registerSandbox() error = %v", err)
	}
	t.Cleanup(func() {
		manager.unregisterSandbox(sandboxID)
		_ = manager.Close()
	})

	originalNewManagerDNSService := newManagerDNSService
	stubErr := errors.New("upstream unavailable")
	newManagerDNSService = func() *managerDNSService {
		return &managerDNSService{
			dialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, stubErr
			},
			servers: []string{"127.0.0.1:53"},
		}
	}
	t.Cleanup(func() {
		newManagerDNSService = originalNewManagerDNSService
	})

	denied := manager.handleDNSRequest(context.Background(), sandboxID, helperproto.DNSRequest{
		Network: "udp",
		Payload: mustDNSQuery(t, 1, "denied.example.com."),
	})
	if denied == nil || denied.Error == "" {
		t.Fatalf("denied DNS response = %#v, want policy error", denied)
	}

	allowed := manager.handleDNSRequest(context.Background(), sandboxID, helperproto.DNSRequest{
		Network: "udp",
		Payload: mustDNSQuery(t, 2, "allowed.example.com."),
	})
	if allowed == nil || !strings.Contains(allowed.Error, stubErr.Error()) {
		t.Fatalf("allowed DNS response = %#v, want upstream error %q", allowed, stubErr.Error())
	}

	snapshot := manager.accessedDomainsSnapshot(sandboxID)
	entries := make(map[string]AccessedDomain, len(snapshot))
	for _, entry := range snapshot {
		entries[entry.Host] = entry
	}

	if deniedEntry, ok := entries["denied.example.com"]; !ok {
		t.Fatalf("audit snapshot missing denied host: %#v", snapshot)
	} else if deniedEntry.LastResult != "denied" {
		t.Fatalf("denied entry = %#v, want denied result", deniedEntry)
	}

	if allowedEntry, ok := entries["allowed.example.com"]; !ok {
		t.Fatalf("audit snapshot missing allowed host: %#v", snapshot)
	} else if allowedEntry.LastResult == "" {
		t.Fatalf("allowed entry = %#v, want recorded result", allowedEntry)
	}
}

func TestStripAAAARecordsRemovesIPv6Answers(t *testing.T) {
	query := mustDNSQueryOfType(t, 7, "allowed.example.com.", dnsmessage.TypeAAAA)
	payload := mustDNSResponseWithAAndAAAA(t, query, [4]byte{127, 0, 0, 1}, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	filtered, err := stripAAAARecords(payload)
	if err != nil {
		t.Fatalf("stripAAAARecords() error = %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(filtered); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}
	if msg.Answers[0].Header.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want %v", msg.Answers[0].Header.Type, dnsmessage.TypeA)
	}
}

func TestProxyManagerHandleDNSRequestPreservesAAAAInProxyMode(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{{HostPatterns: []string{"^allowed\\.example\\.com$"}}},
	})
	manager := newProxyManager(policy)
	sandboxID := "sandbox-dns-proxy"
	if err := manager.registerSandbox(sandboxID, policy); err != nil {
		t.Fatalf("registerSandbox() error = %v", err)
	}
	if err := manager.attachSandbox(sandboxID, &Sandbox{trafficMode: TrafficModeProxy}); err != nil {
		t.Fatalf("attachSandbox() error = %v", err)
	}
	t.Cleanup(func() {
		manager.unregisterSandbox(sandboxID)
		_ = manager.Close()
	})

	query := mustDNSQueryOfType(t, 8, "allowed.example.com.", dnsmessage.TypeAAAA)
	reply := mustDNSResponseWithAAndAAAA(t, query, [4]byte{127, 0, 0, 1}, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	originalNewManagerDNSService := newManagerDNSService
	newManagerDNSService = func() *managerDNSService {
		return &managerDNSService{
			dialContext: func(context.Context, string, string) (net.Conn, error) {
				return stubDNSRoundTripConn(query, reply), nil
			},
			servers: []string{"127.0.0.1:53"},
		}
	}
	t.Cleanup(func() {
		newManagerDNSService = originalNewManagerDNSService
	})

	response := manager.handleDNSRequest(context.Background(), sandboxID, helperproto.DNSRequest{
		Network: "udp",
		Payload: query,
	})
	if response == nil || response.Error != "" {
		t.Fatalf("unexpected DNS response: %#v", response)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(response.Payload); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if len(msg.Answers) != 2 {
		t.Fatalf("len(Answers) = %d, want 2", len(msg.Answers))
	}
	if msg.Answers[0].Header.Type != dnsmessage.TypeA || msg.Answers[1].Header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("unexpected answer types: %v, %v", msg.Answers[0].Header.Type, msg.Answers[1].Header.Type)
	}
}

func TestProxyManagerHandleDNSRequestStripsAAAAInTransparentMode(t *testing.T) {
	policy := mustCompilePolicy(t, NetworkPolicy{
		Rules: []PolicyRule{{HostPatterns: []string{"^allowed\\.example\\.com$"}}},
	})
	manager := newProxyManager(policy)
	sandboxID := "sandbox-dns-transparent"
	if err := manager.registerSandbox(sandboxID, policy); err != nil {
		t.Fatalf("registerSandbox() error = %v", err)
	}
	if err := manager.attachSandbox(sandboxID, &Sandbox{trafficMode: TrafficModeTransparent}); err != nil {
		t.Fatalf("attachSandbox() error = %v", err)
	}
	t.Cleanup(func() {
		manager.unregisterSandbox(sandboxID)
		_ = manager.Close()
	})

	query := mustDNSQueryOfType(t, 9, "allowed.example.com.", dnsmessage.TypeAAAA)
	reply := mustDNSResponseWithAAndAAAA(t, query, [4]byte{127, 0, 0, 1}, [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	originalNewManagerDNSService := newManagerDNSService
	newManagerDNSService = func() *managerDNSService {
		return &managerDNSService{
			dialContext: func(context.Context, string, string) (net.Conn, error) {
				return stubDNSRoundTripConn(query, reply), nil
			},
			servers: []string{"127.0.0.1:53"},
		}
	}
	t.Cleanup(func() {
		newManagerDNSService = originalNewManagerDNSService
	})

	response := manager.handleDNSRequest(context.Background(), sandboxID, helperproto.DNSRequest{
		Network: "udp",
		Payload: query,
	})
	if response == nil || response.Error != "" {
		t.Fatalf("unexpected DNS response: %#v", response)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(response.Payload); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(msg.Answers))
	}
	if msg.Answers[0].Header.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want %v", msg.Answers[0].Header.Type, dnsmessage.TypeA)
	}
}

func TestHelperClientRunRoundTripPreservesStreamOrdering(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newHelperClient(nil, "sandbox-a", clientSide)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = serverSide.Close() })

	go func() {
		client.loopDone <- client.readLoop()
	}()

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	serverErrCh := make(chan error, 1)
	go func() {
		dec := gob.NewDecoder(serverSide)
		enc := gob.NewEncoder(serverSide)

		var req helperproto.Envelope
		if err := dec.Decode(&req); err != nil {
			serverErrCh <- err
			return
		}
		if req.ExecRequest == nil {
			serverErrCh <- errors.New("expected exec request")
			return
		}

		for _, frame := range []helperproto.StreamFrame{
			{Stream: helperproto.StreamStdout, Data: []byte("stdout-one\n")},
			{Stream: helperproto.StreamStdout, Data: []byte("stdout-two\n")},
			{Stream: helperproto.StreamStderr, Data: []byte("stderr-one\n")},
			{Stream: helperproto.StreamStderr, Data: []byte("stderr-two\n")},
		} {
			if err := enc.Encode(&helperproto.Envelope{ID: req.ID, StreamFrame: &frame}); err != nil {
				serverErrCh <- err
				return
			}
		}

		serverErrCh <- enc.Encode(&helperproto.Envelope{
			ID: req.ID,
			ExecResult: &helperproto.ExecResult{
				ExitCode: 0,
			},
		})
	}()

	result, err := client.Run(context.Background(), []string{"/bin/sh"}, RunOptions{
		Interactive: true,
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if result == nil || result.ExitCode != 0 {
		t.Fatalf("unexpected run result: %#v", result)
	}
	if got := stdout.String(); got != "stdout-one\nstdout-two\n" {
		t.Fatalf("stdout ordering = %q", got)
	}
	if got := stderr.String(); got != "stderr-one\nstderr-two\n" {
		t.Fatalf("stderr ordering = %q", got)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server side failed: %v", err)
	}
}

func stubDNSRoundTripConn(query []byte, response []byte) net.Conn {
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, len(query))
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		_, _ = server.Write(response)
	}()
	return client
}

func hostNameserverAddrs(t *testing.T) []string {
	t.Helper()

	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		t.Fatalf("open host resolv.conf: %v", err)
	}
	defer file.Close()

	var servers []string
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
		servers = append(servers, net.JoinHostPort(fields[1], "53"))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan host resolv.conf: %v", err)
	}
	return servers
}

func mustDNSQuery(t *testing.T, id uint16, host string) []byte {
	return mustDNSQueryOfType(t, id, host, dnsmessage.TypeA)
}

func mustDNSQueryOfType(t *testing.T, id uint16, host string, qType dnsmessage.Type) []byte {
	t.Helper()

	name, err := dnsmessage.NewName(host)
	if err != nil {
		t.Fatalf("NewName() error = %v", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qType,
			Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	return payload
}

func mustDNSResponseWithAAndAAAA(t *testing.T, query []byte, addr4 [4]byte, addr6 [16]byte) []byte {
	t.Helper()

	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: msg.Questions,
	}
	for _, question := range msg.Questions {
		response.Answers = append(response.Answers,
			dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: addr4},
			},
			dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: addr6},
			},
		)
	}

	payload, err := response.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	return payload
}
