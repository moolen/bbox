package bbox

import (
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

func TestNewProxyManagerSharesDefaultAccessLogger(t *testing.T) {
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

	if managerA.accessLogger != managerB.accessLogger {
		t.Fatal("expected default access logger to be shared across managers")
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
	if manager.accessLogger != sharedStdoutAccessLogger {
		t.Fatal("expected default access logger for typed-nil input")
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
