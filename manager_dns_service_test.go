package bbox

import (
	"bufio"
	"context"
	"errors"
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
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	payload, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	return payload
}
