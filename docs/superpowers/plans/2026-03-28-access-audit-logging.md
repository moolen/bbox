# Access Audit And Live Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-sandbox accessed-domain auditing plus live JSON access logging for every HTTP, CONNECT, and MITM request attempt without changing sandbox or proxy behavior.

**Architecture:** Keep one internal access-event pipeline inside `ProxyManager`. Every request path emits a normalized event, the manager records it into per-sandbox aggregated audit state, and the same event is forwarded to either the default stdout JSON logger or an injected logger implementation. The public API stays narrow: `ProxyOptions.AccessLogger` configures logging and `Sandbox.AccessedDomains()` returns a snapshot for one sandbox.

**Tech Stack:** Go, existing `ProxyManager` request handlers, standard library `encoding/json`, existing unit/integration test suite

---

## File Structure

**Existing files to modify**

- `types.go`
  Public API for `AccessLogger`, `AccessLogEntry`, `AccessedDomain`, and `ProxyOptions.AccessLogger`.
- `api.go`
  Manager construction and default access logger wiring.
- `manager.go`
  Event emission from plain HTTP, CONNECT, and MITM paths plus audit snapshot access.
- `sandbox.go`
  Public `Sandbox.AccessedDomains()` snapshot accessor.
- `README.md`
  Document audit and live logging behavior.
- `example_test.go`
  Public example showing injected logging and audit snapshot access.

**New files to create**

- `accesslog.go`
  Internal access event model, default JSON logger, per-sandbox aggregation, and snapshot helpers.
- `accesslog_test.go`
  Unit tests for aggregation, result mapping, logger defaulting, and snapshot copying.
- `integration/access_audit_test.go`
  End-to-end audit/logging coverage across HTTP, CONNECT, and MITM traffic.

### Task 1: Add The Public Audit And Logging API

**Files:**
- Modify: `types.go`
- Modify: `api.go`
- Create: `accesslog_test.go`

- [ ] **Step 1: Write the failing public API tests**

Add tests for:
- `NewProxyManager` installs a default access logger when none is supplied
- `NewProxyManager` preserves an injected access logger
- `Sandbox.AccessedDomains()` on a zero-value sandbox returns an empty slice

Example skeleton:

```go
func TestNewProxyManagerInstallsDefaultAccessLogger(t *testing.T) {
	manager, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	if manager.accessLogger == nil {
		t.Fatal("expected default access logger")
	}
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./... -run 'TestNewProxyManager.*AccessLogger|TestNilSandboxAccessedDomains' -count=1`
Expected: FAIL because the public types and access logger wiring do not exist yet.

- [ ] **Step 3: Add the minimal public API**

Implement:
- `AccessLogger`
- `AccessLogEntry`
- `AccessedDomain`
- `ProxyOptions.AccessLogger`
- `Sandbox.AccessedDomains()` stub returning an empty slice when no manager is attached

- [ ] **Step 4: Wire the logger into manager construction**

Extend manager creation so:
- a nil `ProxyOptions.AccessLogger` is replaced with the default stdout JSON logger
- an injected logger is preserved unchanged

- [ ] **Step 5: Run the focused tests to verify they pass**

Run: `go test ./... -run 'TestNewProxyManager.*AccessLogger|TestNilSandboxAccessedDomains' -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add types.go api.go accesslog_test.go sandbox.go
git commit -m "feat: add access audit public api"
```

### Task 2: Build The Internal Access Event And Audit Pipeline

**Files:**
- Create: `accesslog.go`
- Create: `accesslog_test.go`
- Modify: `manager.go`
- Modify: `sandbox.go`

- [ ] **Step 1: Write the failing aggregation tests**

Add unit tests for:
- recording repeated events updates `Attempts` and last-result fields
- snapshots are returned as copies, not live internal state
- normalization aggregates `host:port` attempts under one host with the latest port
- denied, allowed, and upstream-error events map to the expected aggregate state

Example skeleton:

```go
func TestRecordAccessEventAggregatesByHost(t *testing.T) {
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{}))
	manager.recordAccessEvent(accessEvent{
		SandboxID: "sandbox-a",
		Host:      "example.com",
		Port:      443,
		Result:    "denied",
	})
	manager.recordAccessEvent(accessEvent{
		SandboxID: "sandbox-a",
		Host:      "example.com",
		Port:      443,
		Result:    "allowed",
	})

	got := manager.accessedDomains("sandbox-a")
	if len(got) != 1 || got[0].Attempts != 2 || got[0].LastResult != "allowed" {
		t.Fatalf("unexpected aggregate: %#v", got)
	}
}
```

- [ ] **Step 2: Run the aggregation tests to verify they fail**

Run: `go test ./... -run 'TestRecordAccessEvent|TestAccessedDomainsSnapshot' -count=1`
Expected: FAIL because the internal event pipeline does not exist yet.

- [ ] **Step 3: Implement the internal event model and default logger**

In `accesslog.go`, add:
- internal `accessEvent`
- default stdout JSON logger
- event-to-`AccessLogEntry` conversion
- per-sandbox aggregated audit state
- snapshot-copy helpers

- [ ] **Step 4: Add manager helpers for recording and reading audit state**

In `manager.go` and `sandbox.go`, implement:
- manager audit-state initialization and cleanup
- `recordAccessEvent(...)`
- snapshot accessor used by `Sandbox.AccessedDomains()`

- [ ] **Step 5: Run the aggregation tests to verify they pass**

Run: `go test ./... -run 'TestRecordAccessEvent|TestAccessedDomainsSnapshot' -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add accesslog.go accesslog_test.go manager.go sandbox.go
git commit -m "feat: add per-sandbox access audit state"
```

### Task 3: Emit Access Events From HTTP, CONNECT, And MITM Paths

**Files:**
- Modify: `manager.go`
- Modify: `accesslog_test.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Write the failing request-path tests**

Add tests for:
- plain HTTP denied requests emit `Allowed=false`, `Result="denied"`
- plain HTTP upstream transport failures emit `Allowed=true`, `Result="upstream_error"`
- CONNECT allowed and denied attempts emit `connect` events
- MITM CONNECT emits a `connect` event and decrypted requests emit separate `mitm` events
- logger failures do not break request handling

Example skeleton:

```go
func TestHandleConnectRequestRecordsDeniedAttempt(t *testing.T) {
	logger := &recordingAccessLogger{}
	manager := newProxyManager(mustCompilePolicy(t, NetworkPolicy{
		AllowConnect: false,
	}))
	manager.accessLogger = logger
	_ = manager.registerSandbox("sandbox-a", nil)

	resp := manager.handleConnectRequest(t.Context(), "sandbox-a", helperproto.ConnectRequest{
		Host: "example.com",
		Port: 443,
	})

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if len(logger.entries) != 1 || logger.entries[0].Kind != "connect" || logger.entries[0].Result != "denied" {
		t.Fatalf("unexpected access log entries: %#v", logger.entries)
	}
}
```

- [ ] **Step 2: Run the focused request-path tests to verify they fail**

Run: `go test ./... -run 'TestHandle.*Records.*Access|TestLoggerFailureDoesNotBreakRequest' -count=1`
Expected: FAIL because request handlers do not emit access events yet.

- [ ] **Step 3: Emit events from plain HTTP and CONNECT handlers**

Update `handleProxyRequest` and `handleConnectRequest` so each attempt records:
- normalized host and port
- method and path where applicable
- allowed / denied / upstream-error result
- status code and error text when present

- [ ] **Step 4: Emit events from MITM request handling**

Update `handleMITMRequest` so decrypted requests record:
- one `mitm` event per request
- method, path, host, and port
- distinct denied vs upstream-error vs success results

Do not move or duplicate the CONNECT event here. CONNECT remains logged by `handleConnectRequest`.

- [ ] **Step 5: Run the focused request-path tests to verify they pass**

Run: `go test ./... -run 'TestHandle.*Records.*Access|TestLoggerFailureDoesNotBreakRequest' -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add manager.go accesslog_test.go manager_test.go
git commit -m "feat: emit audit events for proxy requests"
```

### Task 4: Add End-To-End Coverage And Documentation

**Files:**
- Create: `integration/access_audit_test.go`
- Modify: `README.md`
- Modify: `example_test.go`

- [ ] **Step 1: Write the failing integration tests**

Add integration coverage for:
- allowed and denied plain HTTP requests appearing in `AccessedDomains()`
- CONNECT attempts being recorded even when later tunnel activity is denied
- MITM requests being recorded separately from CONNECT attempts
- injected logger receiving structured entries during real sandbox traffic

Example skeleton:

```go
func TestSandboxAccessedDomainsTracksAllowedAndDeniedAttempts(t *testing.T) {
	// create manager with recording logger
	// run one allowed request and one denied request
	// assert sandbox.AccessedDomains() contains both attempted hosts/results
}
```

- [ ] **Step 2: Run the focused integration tests to verify they fail**

Run: `go test ./integration -run 'TestSandbox.*AccessedDomains|TestSandbox.*InjectedAccessLogger' -count=1`
Expected: FAIL because end-to-end audit/logging behavior is not fully wired yet.

- [ ] **Step 3: Implement any missing integration glue**

Fill any remaining gaps revealed by the integration tests, keeping the public API exactly as specified.

- [ ] **Step 4: Document the feature**

Update:
- `README.md` with audit and logging behavior, default stdout JSON logging, and injected logger usage
- `example_test.go` with a minimal example showing `AccessLogger` injection and `AccessedDomains()`

- [ ] **Step 5: Run the full test suite**

Run: `go test ./... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add integration/access_audit_test.go README.md example_test.go
git commit -m "feat: add access audit logging"
```
