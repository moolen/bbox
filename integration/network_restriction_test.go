package integration_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moolen/bbox"
	"golang.org/x/net/dns/dnsmessage"
)

type blockedProbeSpec struct {
	name string
	argv []string
}

type networkRestrictionTargets struct {
	dnsHost       string
	dnsPort       int
	rawTCPPort    int
	rawUDPPort    int
	closedUDPPort int
	icmpHost      string
}

type hostCommandResult struct {
	exitCode int
	output   string
}

func TestProxyBlockedProbeSpecsOmitICMPWhenHostUnavailable(t *testing.T) {
	probes := proxyBlockedProbeSpecs("/bin/sh", networkToolPaths{
		curl: "/usr/bin/curl",
		ping: "/usr/bin/ping",
		dns:  "/usr/bin/dig",
		nc:   "/usr/bin/nc",
	}, networkRestrictionTargets{
		dnsHost:    "127.0.0.1",
		dnsPort:    5300,
		rawTCPPort: 1234,
		rawUDPPort: 5678,
	})

	for _, probe := range probes {
		if probe.name == "icmp" {
			t.Fatalf("expected ICMP probe to be omitted when no ICMP host is available: %#v", probes)
		}
	}
}

func TestTransparentBlockedProbeSpecsIncludeICMPWhenHostAvailable(t *testing.T) {
	probes := transparentBlockedProbeSpecs("/bin/sh", networkToolPaths{
		curl: "/usr/bin/curl",
		ping: "/usr/bin/ping",
		dns:  "/usr/bin/dig",
		nc:   "/usr/bin/nc",
	}, networkRestrictionTargets{
		dnsHost:    "127.0.0.1",
		dnsPort:    5300,
		rawTCPPort: 1234,
		rawUDPPort: 5678,
		icmpHost:   "192.0.2.10",
	})

	for _, probe := range probes {
		if probe.name == "icmp" {
			return
		}
	}
	t.Fatalf("expected ICMP probe to be present when an ICMP host is available: %#v", probes)
}

func TestNetworkRestrictionsProxyMode(t *testing.T) {
	requireSandboxPrereqs(t)
	tools := mustRequireNetworkTools(t)
	shellPath := mustRequireShellTool(t)
	targets := startNetworkRestrictionTargets(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	preflightHostRestrictionProbes(t, ctx, shellPath, tools, targets)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("proxy mode preflight ok"))
	}))
	defer server.Close()

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
		Name:        "network-restrictions-proxy",
		Binaries:    []string{tools.curl, tools.ping, tools.dns, tools.nc, shellPath},
		TrafficMode: bbox.TrafficModeProxy,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^127[.]0[.]0[.]1$`},
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

	allowedResult, err := sandbox.Run(ctx, []string{
		tools.curl,
		"-sS",
		"-o", "-",
		"-w", "\n%{http_code}\n",
		server.URL + "/ok",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("proxy HTTP preflight failed: %v", err)
	}
	if allowedResult.ExitCode != 0 {
		t.Fatalf("expected proxy HTTP preflight to succeed, exit=%d stderr=%q", allowedResult.ExitCode, string(allowedResult.Stderr))
	}
	if got := strings.TrimSpace(string(allowedResult.Stdout)); got != "proxy mode preflight ok\n200" {
		t.Fatalf("unexpected proxy HTTP preflight output: %q", got)
	}

	requireSandboxICMPPreflight(t, ctx, sandbox, tools, targets)

	for _, probe := range proxyBlockedProbeSpecs(shellPath, tools, targets) {
		t.Run(probe.name, func(t *testing.T) {
			result, err := sandbox.Run(ctx, probe.argv, bbox.RunOptions{})
			assertBlockedRunResult(t, result, err)
		})
	}
}

func TestNetworkRestrictionsTransparentMode(t *testing.T) {
	requireSandboxPrereqs(t)
	requireTransparentRuntimePortsStrict(t)
	tools := mustRequireNetworkTools(t)
	shellPath := mustRequireShellTool(t)
	targets := startNetworkRestrictionTargets(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	preflightHostRestrictionProbes(t, ctx, shellPath, tools, targets)

	httpServer := startTransparentHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "allowed.localhost" {
			t.Fatalf("unexpected transparent HTTP host: %q", r.Host)
		}
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("transparent http preflight ok"))
	}))
	defer httpServer.Close()

	httpsServer := startTransparentTLSTestServer(t, "secure.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "secure.localhost" {
			t.Fatalf("unexpected transparent HTTPS host: %q", r.Host)
		}
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("transparent https preflight ok"))
	}))
	defer httpsServer.Close()
	trustHTTPSServer(t, httpsServer)

	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{
		MITM: bbox.MITMOptions{Enabled: true, MaxRequestBodyBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Fatalf("close manager: %v", err)
		}
	}()

	sandbox, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:        "network-restrictions-transparent",
		Binaries:    []string{tools.curl, tools.ping, tools.dns, tools.nc, shellPath},
		TrafficMode: bbox.TrafficModeTransparent,
		Policy: bbox.NetworkPolicy{
			AllowHostPatterns: []string{`^allowed[.]localhost$`, `^secure[.]localhost$`},
			AllowHTTPMethods:  []string{"GET"},
			AllowPathPatterns: []string{`^/ok$`},
		},
	})
	if err != nil {
		t.Fatalf("create transparent sandbox: %v", err)
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Fatalf("close transparent sandbox: %v", err)
		}
	}()

	httpOK, err := sandbox.Run(ctx, []string{tools.curl, "-sS", "http://allowed.localhost/ok"}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("transparent HTTP preflight failed: %v", err)
	}
	if httpOK.ExitCode != 0 {
		t.Fatalf("expected transparent HTTP preflight to succeed, exit=%d stderr=%q", httpOK.ExitCode, string(httpOK.Stderr))
	}
	if got := strings.TrimSpace(string(httpOK.Stdout)); got != "transparent http preflight ok" {
		t.Fatalf("unexpected transparent HTTP preflight output: %q", got)
	}

	httpsOK, err := sandbox.Run(ctx, []string{tools.curl, "-sS", "https://secure.localhost/ok"}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("transparent HTTPS preflight failed: %v", err)
	}
	if httpsOK.ExitCode != 0 {
		t.Fatalf("expected transparent HTTPS preflight to succeed, exit=%d stderr=%q", httpsOK.ExitCode, string(httpsOK.Stderr))
	}
	if got := strings.TrimSpace(string(httpsOK.Stdout)); got != "transparent https preflight ok" {
		t.Fatalf("unexpected transparent HTTPS preflight output: %q", got)
	}

	requireSandboxICMPPreflight(t, ctx, sandbox, tools, targets)

	for _, probe := range transparentBlockedProbeSpecs(shellPath, tools, targets) {
		t.Run(probe.name, func(t *testing.T) {
			result, err := sandbox.Run(ctx, probe.argv, bbox.RunOptions{})
			assertBlockedRunResult(t, result, err)
		})
	}
}

func proxyBlockedProbeSpecs(shellPath string, tools networkToolPaths, targets networkRestrictionTargets) []blockedProbeSpec {
	probes := []blockedProbeSpec{
		{name: "dns-udp", argv: dnsUDPProbeArgv(tools, targets.dnsHost, targets.dnsPort)},
		{name: "dns-tcp", argv: dnsTCPProbeArgv(tools, targets.dnsHost, targets.dnsPort)},
		{name: "tcp", argv: []string{tools.nc, "-n", "-z", "-v", "-w", "1", "127.0.0.1", strconv.Itoa(targets.rawTCPPort)}},
		{name: "udp", argv: udpProbeArgv(shellPath, tools, targets.rawUDPPort)},
		{name: "other-curl-telnet", argv: []string{tools.curl, "-sS", "--connect-timeout", "1", "--max-time", "2", fmt.Sprintf("telnet://127.0.0.1:%d", targets.rawTCPPort)}},
	}
	if targets.icmpHost != "" {
		probes = append(probes, blockedProbeSpec{
			name: "icmp",
			argv: []string{tools.ping, "-n", "-c", "1", "-W", "1", targets.icmpHost},
		})
	}
	return probes
}

func transparentBlockedProbeSpecs(shellPath string, tools networkToolPaths, targets networkRestrictionTargets) []blockedProbeSpec {
	probes := append([]blockedProbeSpec(nil), proxyBlockedProbeSpecs(shellPath, tools, targets)...)
	probes = append(probes,
		// Transparent mode only supports hostname-based HTTPS on the default port.
		blockedProbeSpec{name: "ip-literal-https", argv: []string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://127.0.0.1/ok"}},
		// Transparent mode intentionally does not proxy arbitrary HTTPS destination ports.
		blockedProbeSpec{name: "non-default-port-https", argv: []string{tools.curl, "-sS", "--connect-timeout", "5", "--max-time", "10", "https://secure.localhost:8443/ok"}},
	)
	return probes
}

func dnsUDPProbeArgv(tools networkToolPaths, host string, port int) []string {
	if filepath.Base(tools.dns) == "nslookup" {
		return []string{
			tools.dns,
			"-timeout=1",
			"-retry=1",
			fmt.Sprintf("-port=%d", port),
			"example.test",
			host,
		}
	}
	return []string{
		tools.dns,
		"+short",
		fmt.Sprintf("@%s", host),
		"-p", strconv.Itoa(port),
		"example.test",
		"+time=1",
		"+tries=1",
	}
}

func dnsTCPProbeArgv(tools networkToolPaths, host string, port int) []string {
	if filepath.Base(tools.dns) == "nslookup" {
		return []string{
			tools.dns,
			"-timeout=1",
			"-retry=1",
			"-vc",
			fmt.Sprintf("-port=%d", port),
			"example.test",
			host,
		}
	}
	return []string{
		tools.dns,
		"+short",
		"+tcp",
		fmt.Sprintf("@%s", host),
		"-p", strconv.Itoa(port),
		"example.test",
		"+time=1",
		"+tries=1",
	}
}

func startNetworkRestrictionTargets(t *testing.T) networkRestrictionTargets {
	t.Helper()

	dnsServer := startLoopbackDNSTestServer(t)
	rawTCPPort := startLoopbackTCPProbeListener(t)
	rawUDPPort := startLoopbackUDPProbeListener(t)

	return networkRestrictionTargets{
		dnsHost:       dnsServer.host,
		dnsPort:       dnsServer.port,
		rawTCPPort:    rawTCPPort,
		rawUDPPort:    rawUDPPort,
		closedUDPPort: reserveClosedLoopbackUDPPort(t),
		icmpHost:      findNonLoopbackIPv4(t),
	}
}

func preflightHostRestrictionProbes(t *testing.T, ctx context.Context, shellPath string, tools networkToolPaths, targets networkRestrictionTargets) {
	t.Helper()

	udpDNSResult := runHostCommand(t, ctx, dnsUDPProbeArgv(tools, targets.dnsHost, targets.dnsPort))
	assertHostCommandSuccess(t, udpDNSResult)
	assertHostCommandOutputContains(t, udpDNSResult, "127.0.0.1")

	tcpDNSResult := runHostCommand(t, ctx, dnsTCPProbeArgv(tools, targets.dnsHost, targets.dnsPort))
	assertHostCommandSuccess(t, tcpDNSResult)
	assertHostCommandOutputContains(t, tcpDNSResult, "127.0.0.1")

	assertHostCommandSuccess(t, runHostCommand(t, ctx, []string{
		tools.nc, "-n", "-z", "-v", "-w", "1", "127.0.0.1", strconv.Itoa(targets.rawTCPPort),
	}))

	assertHostCommandSuccess(t, runHostCommand(t, ctx, []string{
		shellPath, "-c", `printf bbox-udp | exec "$1" -n -u -c -w 1 127.0.0.1 "$2"`, "sh", tools.nc, strconv.Itoa(targets.rawUDPPort),
	}))
	assertHostCommandFailure(t, runHostCommand(t, ctx, []string{
		shellPath, "-c", `printf bbox-udp | exec "$1" -n -u -c -w 1 127.0.0.1 "$2"`, "sh", tools.nc, strconv.Itoa(targets.closedUDPPort),
	}))

	if targets.icmpHost != "" {
		assertHostCommandSuccess(t, runHostCommand(t, ctx, []string{
			tools.ping, "-n", "-c", "1", "-W", "1", targets.icmpHost,
		}))
	}

	assertHostCommandSuccess(t, runHostCommand(t, ctx, []string{
		tools.curl, "-sS", "--connect-timeout", "1", "--max-time", "2", fmt.Sprintf("telnet://127.0.0.1:%d", targets.rawTCPPort),
	}))
}

func requireSandboxICMPPreflight(t *testing.T, ctx context.Context, sandbox *bbox.Sandbox, tools networkToolPaths, targets networkRestrictionTargets) {
	t.Helper()
	if targets.icmpHost == "" {
		return
	}

	result, err := sandbox.Run(ctx, []string{
		tools.ping, "-n", "-c", "1", "-W", "1", "127.0.0.1",
	}, bbox.RunOptions{})
	if err != nil {
		t.Fatalf("sandbox ICMP preflight failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected sandbox ICMP preflight result")
	}
	if result.ExitCode != 0 {
		t.Fatalf("sandbox ICMP preflight must succeed before blocked ICMP probes are meaningful, stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
}

func mustRequireShellTool(t *testing.T) string {
	t.Helper()

	shellPath, err := resolveFirstAvailableTool([]string{"sh"})
	if err != nil {
		t.Fatal(err)
	}
	return shellPath
}

func runHostCommand(t *testing.T, ctx context.Context, argv []string) hostCommandResult {
	t.Helper()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = hostProbeEnv()
	output, err := cmd.CombinedOutput()
	if err == nil {
		return hostCommandResult{exitCode: 0, output: string(output)}
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return hostCommandResult{exitCode: exitErr.ExitCode(), output: string(output)}
	}
	t.Fatalf("host preflight %q failed to execute: %v", strings.Join(argv, " "), err)
	return hostCommandResult{}
}

func hostProbeEnv() []string {
	filtered := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, "NO_PROXY=*")
}

func assertHostCommandSuccess(t *testing.T, result hostCommandResult) {
	t.Helper()
	if result.exitCode != 0 {
		t.Fatalf("expected host preflight command to succeed, exit=%d output=%q", result.exitCode, result.output)
	}
}

func assertHostCommandFailure(t *testing.T, result hostCommandResult) {
	t.Helper()
	if result.exitCode == 0 {
		t.Fatalf("expected host preflight command to fail, output=%q", result.output)
	}
}

func assertHostCommandOutputContains(t *testing.T, result hostCommandResult, want string) {
	t.Helper()
	if !strings.Contains(result.output, want) {
		t.Fatalf("expected host preflight output to contain %q, got %q", want, result.output)
	}
}

func findNonLoopbackIPv4(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list network interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := ipNet.IP.To4(); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func startLoopbackTCPProbeListener(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback TCP probe: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

func startLoopbackUDPProbeListener(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback UDP probe: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	return conn.LocalAddr().(*net.UDPAddr).Port
}

func reserveClosedLoopbackUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed loopback UDP port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

func udpProbeArgv(shellPath string, tools networkToolPaths, port int) []string {
	return []string{
		shellPath,
		"-c",
		`printf bbox-udp | exec "$1" -n -u -c -w 1 127.0.0.1 "$2"`,
		"sh",
		tools.nc,
		strconv.Itoa(port),
	}
}

type loopbackDNSServer struct {
	host string
	port int
	udp  net.PacketConn
	tcp  net.Listener
}

func startLoopbackDNSTestServer(t *testing.T) *loopbackDNSServer {
	t.Helper()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP DNS probe: %v", err)
	}

	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("listen UDP DNS probe: %v", err)
	}

	server := &loopbackDNSServer{
		host: "127.0.0.1",
		port: port,
		udp:  udpConn,
		tcp:  tcpListener,
	}
	t.Cleanup(func() {
		_ = server.udp.Close()
		_ = server.tcp.Close()
	})

	go server.serveUDP()
	go server.serveTCP()

	return server
}

func (s *loopbackDNSServer) serveUDP() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		response, ok := packDNSResponse(buf[:n])
		if !ok {
			continue
		}
		_, _ = s.udp.WriteTo(response, addr)
	}
}

func (s *loopbackDNSServer) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go serveDNSTCPConn(conn)
	}
}

func serveDNSTCPConn(conn net.Conn) {
	defer conn.Close()

	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		return
	}
	queryLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	query := make([]byte, queryLen)
	if _, err := io.ReadFull(conn, query); err != nil {
		return
	}

	response, ok := packDNSResponse(query)
	if !ok {
		return
	}

	frame := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(response)))
	copy(frame[2:], response)
	_, _ = conn.Write(frame)
}

func packDNSResponse(payload []byte) ([]byte, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return nil, false
	}

	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return nil, false
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 header.ID,
			Response:           true,
			OpCode:             header.OpCode,
			Authoritative:      true,
			RecursionDesired:   header.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: questions,
	}

	question := questions[0]
	if question.Class != dnsmessage.ClassINET {
		response.Header.RCode = dnsmessage.RCodeRefused
	} else {
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  question.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			}}
		default:
			response.Header.RCode = dnsmessage.RCodeRefused
		}
	}

	packed, err := response.Pack()
	if err != nil {
		return nil, false
	}
	return packed, true
}
