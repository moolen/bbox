package bbox

import "testing"

type stubAccessLogger struct {
	entries []AccessLogEntry
}

func (s *stubAccessLogger) LogAccess(entry AccessLogEntry) {
	s.entries = append(s.entries, entry)
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
