package integration_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/moolen/bbox"
)

type blockedProbeSpec struct {
	name string
	argv []string
}

func TestNetworkRestrictionsProxyMode(t *testing.T) {
	requireSandboxPrereqs(t)
	tools := mustRequireNetworkTools(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "network-restrictions-proxy",
		Binaries: []string{tools.curl, tools.ping, tools.dns, tools.nc},
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^example[.]com$`},
			AllowHTTPMethods:  []string{"GET"},
		},
	})
	if err != nil {
		t.Fatalf("create proxy sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close proxy sandbox: %v", err)
		}
	}()

	for _, probe := range proxyBlockedProbeSpecs(tools) {
		t.Run(probe.name, func(t *testing.T) {
			result, err := sandbox.Run(ctx, probe.argv, bbox.RunOptions{})
			assertBlockedRunResult(t, result, err)
		})
	}
}

func proxyBlockedProbeSpecs(tools networkToolPaths) []blockedProbeSpec {
	return []blockedProbeSpec{
		{name: "dns-udp", argv: dnsUDPProbeArgv(tools)},
		{name: "dns-tcp", argv: dnsTCPProbeArgv(tools)},
		{name: "icmp", argv: []string{tools.ping, "-n", "-c", "1", "-W", "1", "198.51.100.1"}},
		{name: "tcp", argv: []string{tools.nc, "-n", "-zvw", "1", "198.51.100.1", "9"}},
		{name: "udp", argv: []string{tools.nc, "-n", "-uzvw", "1", "198.51.100.1", "9"}},
		{name: "broadcast", argv: []string{tools.ping, "-n", "-b", "-c", "1", "-W", "1", "255.255.255.255"}},
	}
}

func dnsUDPProbeArgv(tools networkToolPaths) []string {
	if filepath.Base(tools.dns) == "nslookup" {
		return []string{tools.dns, "-timeout=1", "-retry=1", "example.test", "198.51.100.53"}
	}
	return []string{tools.dns, "@198.51.100.53", "example.test", "+time=1", "+tries=1"}
}

func dnsTCPProbeArgv(tools networkToolPaths) []string {
	if filepath.Base(tools.dns) == "nslookup" {
		return []string{tools.dns, "-timeout=1", "-retry=1", "-vc", "example.test", "198.51.100.53"}
	}
	return []string{tools.dns, "+tcp", "@198.51.100.53", "example.test", "+time=1", "+tries=1"}
}
