package bbox

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type stubAccessLogger struct {
	entries []AccessLogEntry
}

func (s *stubAccessLogger) LogAccess(entry AccessLogEntry) {
	s.entries = append(s.entries, entry)
}

type panicAccessLogger struct {
	calls int
}

func (p *panicAccessLogger) LogAccess(entry AccessLogEntry) {
	p.calls++
	panic("access logger failure")
}

func TestNewProxyManagerInstallsDefaultAccessLogger(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if manager.accessLogger == nil {
		t.Fatal("expected default access logger")
	}
}

func TestNewProxyManagerPreservesInjectedAccessLogger(t *testing.T) {
	logger := &stubAccessLogger{}
	manager, err := NewProxyManager(ProxyOptions{
		AccessLogger: logger,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if manager.accessLogger != logger {
		t.Fatal("expected injected access logger to be preserved")
	}
}

func TestNewProxyManagerCreatesDistinctDefaultAccessLoggers(t *testing.T) {
	managerA, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager A: %v", err)
	}
	defer managerA.Close()

	managerB, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager B: %v", err)
	}
	defer managerB.Close()

	if managerA.accessLogger == managerB.accessLogger {
		t.Fatal("expected default access logger instances to be manager-local")
	}
}

func TestNewProxyManagerDefaultAccessLoggerWritesToStderr(t *testing.T) {
	origStdout := os.Stdout
	origStderr := os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
		_ = stdoutR.Close()
		_ = stderrR.Close()
	}()

	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()
	if err := manager.registerSandbox("sandbox-stderr", mustCompilePolicy(t, NetworkPolicy{})); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		SandboxID:     "sandbox-stderr",
		Kind:          "http",
		Host:          "example.com",
		Port:          443,
		Result:        "allowed",
		Allowed:       true,
		PolicyAllowed: true,
	})

	os.Stdout = origStdout
	os.Stderr = origStderr
	_ = stdoutW.Close()
	_ = stderrW.Close()

	stdoutBytes, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderrBytes, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}

	if len(stdoutBytes) != 0 {
		t.Fatalf("expected default access logger to avoid stdout, got %q", string(stdoutBytes))
	}
	if !strings.Contains(string(stderrBytes), "\"SandboxID\":\"sandbox-stderr\"") {
		t.Fatalf("expected default access logger output on stderr, got %q", string(stderrBytes))
	}
}

func TestDefaultJSONAccessLoggerDefersWritesUntilFlush(t *testing.T) {
	var buf strings.Builder
	logger := newDefaultJSONAccessLoggerWithMode(&buf, true)

	logger.LogAccess(AccessLogEntry{
		SandboxID: "sandbox-tty",
		Kind:      "http",
		Host:      "example.com",
		Port:      443,
	})

	if buf.Len() != 0 {
		t.Fatalf("expected deferred logger to avoid writes before flush, got %q", buf.String())
	}

	logger.Flush()
	if !strings.Contains(buf.String(), "\"SandboxID\":\"sandbox-tty\"") {
		t.Fatalf("expected deferred logger output after flush, got %q", buf.String())
	}
}

type typedNilAccessLogger struct{}

func (t *typedNilAccessLogger) LogAccess(AccessLogEntry) {}

func TestNewProxyManagerTreatsTypedNilAccessLoggerAsNil(t *testing.T) {
	var logger *typedNilAccessLogger
	manager, err := NewProxyManager(ProxyOptions{
		AccessLogger: logger,
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	defer manager.Close()

	if manager.accessLogger == logger {
		t.Fatal("expected typed-nil access logger to be replaced")
	}
	if manager.accessLogger == nil {
		t.Fatal("expected default access logger for typed-nil input")
	}
}

type stubFlushAccessLogger struct {
	flushed bool
}

func (s *stubFlushAccessLogger) LogAccess(AccessLogEntry) {}

func (s *stubFlushAccessLogger) Flush() {
	s.flushed = true
}

func TestProxyManagerCloseFlushesAccessLogger(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	logger := &stubFlushAccessLogger{}
	manager.accessLogger = logger

	if err := manager.Close(); err != nil {
		t.Fatalf("close manager: %v", err)
	}
	if !logger.flushed {
		t.Fatal("expected manager close to flush access logger")
	}
}

func TestNilSandboxAccessedDomains(t *testing.T) {
	var sandbox Sandbox

	got := sandbox.AccessedDomains()
	if got == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d entries", len(got))
	}
}

func TestNilSandboxAccessSummary(t *testing.T) {
	var sandbox Sandbox

	got := sandbox.AccessSummary()
	if got.Hosts == nil {
		t.Fatal("expected empty hosts slice, got nil")
	}
	if got.Requests == nil {
		t.Fatal("expected empty requests slice, got nil")
	}
	if len(got.Hosts) != 0 {
		t.Fatalf("expected empty hosts slice, got %d entries", len(got.Hosts))
	}
	if len(got.Requests) != 0 {
		t.Fatalf("expected empty requests slice, got %d entries", len(got.Requests))
	}

	got.Hosts = append(got.Hosts, AccessedHostSummary{Host: "mutated"})
	got.Requests = append(got.Requests, RequestAggregate{Host: "mutated"})

	again := sandbox.AccessSummary()
	if len(again.Hosts) != 0 {
		t.Fatalf("expected empty hosts slice on second snapshot, got %d entries", len(again.Hosts))
	}
	if len(again.Requests) != 0 {
		t.Fatalf("expected empty requests slice on second snapshot, got %d entries", len(again.Requests))
	}
}

func TestSandboxAccessSummaryIsCopy(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	sandbox := &Sandbox{manager: manager, id: "sandbox-a"}
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:          time.Date(2026, 3, 31, 11, 0, 0, 0, time.UTC),
		SandboxID:     "sandbox-a",
		TrafficMode:   TrafficModeTransparent,
		Kind:          "http",
		Host:          "example.com",
		Port:          80,
		Method:        "GET",
		Path:          "/ok",
		Allowed:       true,
		StatusCode:    200,
		Result:        "allowed",
		PolicyAllowed: true,
	})

	first := sandbox.AccessSummary()
	if len(first.Hosts) != 1 {
		t.Fatalf("expected 1 host summary, got %d", len(first.Hosts))
	}
	if len(first.Requests) != 1 {
		t.Fatalf("expected 1 request summary, got %d", len(first.Requests))
	}

	first.Hosts[0].Host = "mutated.example"
	first.Hosts[0].Attempts = 99
	first.Hosts[0].PolicyAllowedCount = 99
	first.Requests[0].Host = "mutated.example"
	first.Requests[0].Attempts = 99
	first.Requests[0].PolicyAllowedCount = 99

	latest := sandbox.AccessSummary()
	if latest.Hosts[0].Host != "example.com" {
		t.Fatalf("expected original host to remain intact, got %#v", latest.Hosts[0])
	}
	if latest.Hosts[0].Attempts != 1 {
		t.Fatalf("expected original host attempts to remain 1, got %d", latest.Hosts[0].Attempts)
	}
	if latest.Hosts[0].PolicyAllowedCount != 1 {
		t.Fatalf("expected original host policy-allowed count to remain 1, got %d", latest.Hosts[0].PolicyAllowedCount)
	}
	if latest.Requests[0].Host != "example.com" {
		t.Fatalf("expected original request host to remain intact, got %#v", latest.Requests[0])
	}
	if latest.Requests[0].Attempts != 1 {
		t.Fatalf("expected original request attempts to remain 1, got %d", latest.Requests[0].Attempts)
	}
	if latest.Requests[0].PolicyAllowedCount != 1 {
		t.Fatalf("expected original request policy-allowed count to remain 1, got %d", latest.Requests[0].PolicyAllowedCount)
	}
}

func TestSandboxAccessSummaryReflectsPolicyCounters(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	sandbox := &Sandbox{manager: manager, id: "sandbox-a"}
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:          time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC),
		SandboxID:     "sandbox-a",
		TrafficMode:   TrafficModeTransparent,
		Kind:          "http",
		Host:          "example.com",
		Port:          80,
		Method:        "GET",
		Path:          "/ok",
		Allowed:       true,
		StatusCode:    200,
		Result:        "allowed",
		PolicyAllowed: true,
	})
	manager.recordAccessEvent(accessEvent{
		Time:             time.Date(2026, 3, 31, 12, 1, 0, 0, time.UTC),
		SandboxID:        "sandbox-a",
		TrafficMode:      TrafficModeTransparent,
		Kind:             "http",
		Host:             "example.com",
		Port:             80,
		Method:           "POST",
		Path:             "/ok",
		Allowed:          true,
		StatusCode:       200,
		Result:           "allowed",
		PolicyAllowed:    false,
		PolicyViolations: []string{"method POST is not allowed"},
	})

	summary := sandbox.AccessSummary()
	if len(summary.Hosts) != 1 {
		t.Fatalf("expected 1 host summary, got %d", len(summary.Hosts))
	}

	host := summary.Hosts[0]
	if host.PolicyAllowedCount != 1 {
		t.Fatalf("expected 1 policy-allowed host attempt, got %d", host.PolicyAllowedCount)
	}
	if host.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied host attempt, got %d", host.PolicyDeniedCount)
	}
	if host.PolicyViolations != 1 {
		t.Fatalf("expected 1 host policy violation, got %d", host.PolicyViolations)
	}
	if len(summary.Requests) != 2 {
		t.Fatalf("expected 2 request summaries, got %d", len(summary.Requests))
	}

	var post RequestAggregate
	foundPost := false
	for _, aggregate := range summary.Requests {
		if aggregate.Kind == "http" && aggregate.Host == "example.com" && aggregate.Port == 80 && aggregate.Method == "POST" && aggregate.Path == "/ok" {
			post = aggregate
			foundPost = true
			break
		}
	}
	if !foundPost {
		t.Fatalf("expected POST request summary in %#v", summary.Requests)
	}
	if post.Attempts != 1 {
		t.Fatalf("expected 1 POST attempt, got %d", post.Attempts)
	}
	if post.AllowedCount != 1 {
		t.Fatalf("expected 1 runtime-allowed POST attempt, got %d", post.AllowedCount)
	}
	if post.DeniedCount != 0 {
		t.Fatalf("expected 0 runtime-denied POST attempts, got %d", post.DeniedCount)
	}
	if post.PolicyAllowedCount != 0 {
		t.Fatalf("expected 0 policy-allowed POST attempts, got %d", post.PolicyAllowedCount)
	}
	if post.PolicyDeniedCount != 1 {
		t.Fatalf("expected 1 policy-denied POST attempt, got %d", post.PolicyDeniedCount)
	}
}

func TestRecordAccessEventUpdatesAttemptsAndLastResult(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	first := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)
	second := first.Add(2 * time.Minute)

	manager.recordAccessEvent(accessEvent{
		Time:      first,
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "example.com",
		Port:      443,
		Result:    "denied",
		Error:     "blocked",
	})
	manager.recordAccessEvent(accessEvent{
		Time:      second,
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "example.com",
		Port:      443,
		Result:    "allowed",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, snapshot, "example.com")
	if entry.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", entry.Attempts)
	}
	if entry.LastResult != "allowed" {
		t.Fatalf("expected last result allowed, got %q", entry.LastResult)
	}
	if entry.LastError != "" {
		t.Fatalf("expected last error cleared, got %q", entry.LastError)
	}
	if !entry.LastSeenAt.Equal(second) {
		t.Fatalf("expected last seen %v, got %v", second, entry.LastSeenAt)
	}
	if entry.LastPort != 443 {
		t.Fatalf("expected last port 443, got %d", entry.LastPort)
	}
	if !entry.HTTPSeen {
		t.Fatal("expected HTTPSeen to be true")
	}
}

func TestAccessedDomainsSnapshotIsCopy(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 13, 0, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "example.com",
		Port:      80,
		Result:    "allowed",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	if len(snapshot) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snapshot))
	}
	snapshot[0].Host = "mutated"
	snapshot[0].Attempts = 99

	latest := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, latest, "example.com")
	if entry.Attempts != 1 {
		t.Fatalf("expected attempts to remain 1, got %d", entry.Attempts)
	}
}

func TestRecordAccessEventNormalizesHostPort(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 14, 0, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "connect",
		Host:      "example.com:443",
		Result:    "allowed",
	})
	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 14, 1, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "connect",
		Host:      "example.com",
		Port:      8443,
		Result:    "allowed",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, snapshot, "example.com")
	if entry.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", entry.Attempts)
	}
	if entry.LastPort != 8443 {
		t.Fatalf("expected last port 8443, got %d", entry.LastPort)
	}
}

func TestRecordAccessEventMapsResultsToAggregate(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 15, 0, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "denied.test",
		Port:      80,
		Result:    "denied",
		Error:     "policy denied",
	})
	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 15, 1, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "connect",
		Host:      "allowed.test",
		Port:      443,
		Result:    "allowed",
	})
	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 15, 2, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "mitm",
		Host:      "upstream.test",
		Port:      443,
		Result:    "upstream_error",
		Error:     "dial tcp failed",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")

	denied := findAccessedDomain(t, snapshot, "denied.test")
	if denied.LastResult != "denied" || denied.LastError != "policy denied" {
		t.Fatalf("unexpected denied aggregate: %#v", denied)
	}
	if !denied.HTTPSeen {
		t.Fatal("expected denied HTTPSeen true")
	}

	allowed := findAccessedDomain(t, snapshot, "allowed.test")
	if allowed.LastResult != "allowed" || allowed.LastError != "" {
		t.Fatalf("unexpected allowed aggregate: %#v", allowed)
	}
	if !allowed.ConnectSeen {
		t.Fatal("expected allowed ConnectSeen true")
	}

	upstream := findAccessedDomain(t, snapshot, "upstream.test")
	if upstream.LastResult != "upstream_error" || upstream.LastError != "dial tcp failed" {
		t.Fatalf("unexpected upstream aggregate: %#v", upstream)
	}
	if !upstream.MITMSeen {
		t.Fatal("expected upstream MITMSeen true")
	}
}

func TestAccessLogEntryIncludesTrafficMode(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	logger := &stubAccessLogger{}
	manager.accessLogger = logger
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:        time.Date(2026, 3, 28, 15, 30, 0, 0, time.UTC),
		SandboxID:   "sandbox-a",
		TrafficMode: TrafficModeTransparent,
		Kind:        "http",
		Host:        "example.com",
		Port:        80,
		Result:      "allowed",
	})

	if len(logger.entries) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(logger.entries))
	}
	if got := logger.entries[0].TrafficMode; got != TrafficModeTransparent {
		t.Fatalf("expected transparent traffic mode, got %q", got)
	}
}

func TestAccessLogEntryIncludesProtocolMetadata(t *testing.T) {
	eventTime := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	event := accessEvent{
		Time:               eventTime,
		SandboxID:          "sandbox-a",
		TrafficMode:        TrafficModeTransparent,
		Kind:               "transparent_connect",
		Host:               "example.com",
		Port:               443,
		Method:             "CONNECT",
		Path:               "/",
		Allowed:            true,
		StatusCode:         200,
		Result:             "allowed",
		Error:              "",
		PolicyMode:         PolicyModeAudit,
		PolicyAllowed:      false,
		PolicyViolations:   []string{"connect denied by policy"},
		Protocol:           "https",
		ProtocolSource:     "alpn",
		ProtocolConfidence: "high",
	}

	entry := event.toAccessLogEntry()

	if !entry.Time.Equal(eventTime) {
		t.Fatalf("expected time %v, got %v", eventTime, entry.Time)
	}
	if entry.SandboxID != "sandbox-a" {
		t.Fatalf("expected sandbox-a, got %q", entry.SandboxID)
	}
	if entry.TrafficMode != TrafficModeTransparent {
		t.Fatalf("expected transparent traffic mode, got %q", entry.TrafficMode)
	}
	if entry.Kind != "transparent_connect" {
		t.Fatalf("expected kind transparent_connect, got %q", entry.Kind)
	}
	if entry.Host != "example.com" {
		t.Fatalf("expected host example.com, got %q", entry.Host)
	}
	if entry.Port != 443 {
		t.Fatalf("expected port 443, got %d", entry.Port)
	}
	if entry.Method != "CONNECT" {
		t.Fatalf("expected method CONNECT, got %q", entry.Method)
	}
	if entry.Path != "/" {
		t.Fatalf("expected path /, got %q", entry.Path)
	}
	if !entry.Allowed {
		t.Fatal("expected allowed to be true")
	}
	if entry.StatusCode != 200 {
		t.Fatalf("expected status code 200, got %d", entry.StatusCode)
	}
	if entry.Result != "allowed" {
		t.Fatalf("expected result allowed, got %q", entry.Result)
	}
	if entry.Error != "" {
		t.Fatalf("expected empty error, got %q", entry.Error)
	}
	if entry.PolicyMode != PolicyModeAudit {
		t.Fatalf("expected policy mode audit, got %q", entry.PolicyMode)
	}
	if entry.PolicyAllowed {
		t.Fatal("expected policy allowed to be false")
	}
	if len(entry.PolicyViolations) != 1 || entry.PolicyViolations[0] != "connect denied by policy" {
		t.Fatalf("expected policy violations to round-trip, got %#v", entry.PolicyViolations)
	}
	if entry.Protocol != "https" {
		t.Fatalf("expected protocol https, got %q", entry.Protocol)
	}
	if entry.ProtocolSource != "alpn" {
		t.Fatalf("expected protocol source alpn, got %q", entry.ProtocolSource)
	}
	if entry.ProtocolConfidence != "high" {
		t.Fatalf("expected protocol confidence high, got %q", entry.ProtocolConfidence)
	}

	event.PolicyViolations[0] = "mutated"
	if entry.PolicyViolations[0] != "connect denied by policy" {
		t.Fatalf("expected policy violations copy isolation, got %#v", entry.PolicyViolations)
	}
}

func TestAccessedDomainsTracksTrafficModeKinds(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:        time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC),
		SandboxID:   "sandbox-a",
		TrafficMode: TrafficModeTransparent,
		Kind:        "http",
		Host:        "example.com",
		Port:        80,
		Result:      "allowed",
	})
	manager.recordAccessEvent(accessEvent{
		Time:        time.Date(2026, 3, 28, 15, 41, 0, 0, time.UTC),
		SandboxID:   "sandbox-a",
		TrafficMode: TrafficModeTransparent,
		Kind:        "mitm",
		Host:        "example.com",
		Port:        443,
		Result:      "denied",
		Error:       "policy denied",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, snapshot, "example.com")
	if entry.TrafficMode != TrafficModeTransparent {
		t.Fatalf("expected transparent traffic mode, got %q", entry.TrafficMode)
	}
	if !entry.HTTPSeen {
		t.Fatal("expected HTTPSeen to be true")
	}
	if !entry.MITMSeen {
		t.Fatal("expected MITMSeen to be true")
	}
}

func TestAccessedDomainsTracksProtocolMetadataWithoutChangingKinds(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:               time.Date(2026, 4, 8, 11, 0, 0, 0, time.UTC),
		SandboxID:          "sandbox-a",
		TrafficMode:        TrafficModeTransparent,
		Kind:               "connect",
		Host:               "example.com",
		Port:               443,
		Result:             "allowed",
		Protocol:           "https",
		ProtocolSource:     "sni",
		ProtocolConfidence: "medium",
	})
	manager.recordAccessEvent(accessEvent{
		Time:               time.Date(2026, 4, 8, 11, 1, 0, 0, time.UTC),
		SandboxID:          "sandbox-a",
		TrafficMode:        TrafficModeTransparent,
		Kind:               "http",
		Host:               "example.com",
		Port:               80,
		Result:             "allowed",
		Protocol:           "http",
		ProtocolSource:     "method",
		ProtocolConfidence: "high",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, snapshot, "example.com")
	if entry.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", entry.Attempts)
	}
	if !entry.ConnectSeen {
		t.Fatal("expected ConnectSeen to be true")
	}
	if !entry.HTTPSeen {
		t.Fatal("expected HTTPSeen to be true")
	}
	if entry.MITMSeen {
		t.Fatal("expected MITMSeen to remain false")
	}
}

func TestRecordAccessEventSkipsEmptySandboxID(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	logger := &stubAccessLogger{}
	manager.accessLogger = logger
	t.Cleanup(func() { auditStateByManager.Delete(manager) })

	manager.recordAccessEvent(accessEvent{
		Time:   time.Date(2026, 3, 28, 16, 0, 0, 0, time.UTC),
		Host:   "example.com",
		Port:   443,
		Result: "allowed",
	})

	if len(logger.entries) != 0 {
		t.Fatalf("expected no log entries, got %d", len(logger.entries))
	}
	if _, ok := auditStateByManager.Load(manager); ok {
		t.Fatal("expected no audit state for empty sandbox ID")
	}
}

func TestRecordAccessEventNormalizesHostCase(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	if err := manager.registerSandbox("sandbox-a", nil); err != nil {
		t.Fatalf("register sandbox: %v", err)
	}

	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 17, 0, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "EXAMPLE.COM",
		Port:      80,
		Result:    "allowed",
	})
	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 17, 1, 0, 0, time.UTC),
		SandboxID: "sandbox-a",
		Kind:      "http",
		Host:      "example.com",
		Port:      80,
		Result:    "allowed",
	})

	snapshot := manager.accessedDomainsSnapshot("sandbox-a")
	entry := findAccessedDomain(t, snapshot, "example.com")
	if entry.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", entry.Attempts)
	}
}

func TestRecordAccessEventSkipsUnregisteredSandbox(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	logger := &stubAccessLogger{}
	manager.accessLogger = logger

	manager.recordAccessEvent(accessEvent{
		Time:      time.Date(2026, 3, 28, 18, 0, 0, 0, time.UTC),
		SandboxID: "missing-sandbox",
		Host:      "example.com",
		Port:      443,
		Result:    "allowed",
	})

	if len(logger.entries) != 0 {
		t.Fatalf("expected no log entries, got %d", len(logger.entries))
	}
	if _, ok := auditStateByManager.Load(manager); ok {
		t.Fatal("expected no audit state for unregistered sandbox ID")
	}
}

func findAccessedDomain(t *testing.T, entries []AccessedDomain, host string) AccessedDomain {
	t.Helper()
	for _, entry := range entries {
		if entry.Host == host {
			return entry
		}
	}
	t.Fatalf("expected host %q in snapshot: %#v", host, entries)
	return AccessedDomain{}
}
