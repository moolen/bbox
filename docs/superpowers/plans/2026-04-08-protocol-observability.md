# Protocol Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add additive protocol metadata to bbox access logs, detect well-known opaque TCP protocols in transparent mode, and add gRPC plus MySQL-style integration coverage without changing enforcement semantics.

**Architecture:** Extend the existing access-event model with optional protocol metadata, then enrich the transparent opaque-TCP denial path and the MITM request path with best-effort classification. Keep existing `Kind` values stable and treat protocol detection as observability-only so policy and routing remain unchanged.

**Tech Stack:** Go, existing bbox integration test harness, access log JSON output, transparent TCP ingress, MITM HTTP/2 handling

---

### Task 1: Add protocol metadata to the access log model

**Files:**
- Modify: `types.go`
- Modify: `accesslog.go`
- Test: `accesslog_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests in `accesslog_test.go` that assert:

- `AccessLogEntry` preserves existing fields
- new optional protocol fields round-trip from `accessEvent`
- existing aggregates still accept events carrying protocol metadata

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestAccessLogEntryIncludesProtocolMetadata|TestAccessedDomainsTracksProtocolMetadataWithoutChangingKinds' -count=1`

Expected: FAIL because the new protocol fields do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Update `types.go` and `accesslog.go` to add optional fields:

- `Protocol string`
- `ProtocolSource string`
- `ProtocolConfidence string`

Propagate them from `accessEvent` to `AccessLogEntry` without changing any existing `Kind` values or aggregation keys.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestAccessLogEntryIncludesProtocolMetadata|TestAccessedDomainsTracksProtocolMetadataWithoutChangingKinds' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add types.go accesslog.go accesslog_test.go
git commit -m "feat: add protocol metadata to access logs"
```

### Task 2: Add a focused opaque TCP protocol classifier

**Files:**
- Create: `internal/helperruntime/ingress/protocol_detect.go`
- Create: `internal/helperruntime/ingress/protocol_detect_test.go`
- Modify: `internal/helperruntime/ingress/transparent_tcp.go`

- [ ] **Step 1: Write the failing tests**

Add table-driven tests in `internal/helperruntime/ingress/protocol_detect_test.go` for:

- MySQL greeting prefix -> `mysql`
- PostgreSQL startup or SSL request -> `postgres`
- Redis RESP prefix -> `redis`
- SSH banner -> `ssh`
- random opaque bytes -> `unknown`

Also add a small test proving TLS ClientHello can be classified as `tls_non_http` when used through the opaque classifier.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol' -count=1`

Expected: FAIL because the classifier does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `internal/helperruntime/ingress/protocol_detect.go` with:

- a small result type carrying protocol metadata
- a pure helper that inspects buffered bytes and returns protocol, source, and confidence

Keep the logic conservative:

- return `unknown` instead of over-classifying
- use `probable` for heuristic matches unless the signature is very strong

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/ingress/protocol_detect.go internal/helperruntime/ingress/protocol_detect_test.go internal/helperruntime/ingress/transparent_tcp.go
git commit -m "feat: add opaque tcp protocol classifier"
```

### Task 3: Enrich transparent-mode denied TCP events with protocol metadata

**Files:**
- Modify: `manager_connect_service.go`
- Modify: `manager.go`
- Modify: `internal/helperproto/*.go` if bridge messages need to carry metadata
- Modify: `internal/helperruntime/bridge/bridge.go`
- Modify: `internal/helperruntime/ingress/transparent_tcp.go`
- Test: `manager_test.go`
- Test: `integration/access_audit_test.go`

- [ ] **Step 1: Write the failing tests**

Add unit tests in `manager_test.go` asserting:

- a `Transparent: true` connect request can record protocol metadata while preserving `Kind=transparent_connect`
- audit-mode and enforce-mode denied transparent connects do not emit duplicate entries

Add an integration assertion path in `integration/access_audit_test.go` for a transparent denied connect entry carrying protocol metadata.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestHandleConnectRequestRecordsTransparentProtocolMetadata|TestHandleConnectRequestAvoidsDuplicateTransparentEvents' -count=1`

Expected: FAIL because connect events cannot yet carry protocol metadata from the transparent ingress path.

- [ ] **Step 3: Write minimal implementation**

Plumb protocol metadata from the transparent ingress path into the manager’s connect authorization event:

- do not change `Kind`
- enrich the existing `transparent_connect` event rather than creating a second event
- keep deny/allow behavior unchanged

If the bridge protocol needs a small shape extension, add only the minimal fields required.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestHandleConnectRequestRecordsTransparentProtocolMetadata|TestHandleConnectRequestAvoidsDuplicateTransparentEvents' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manager_connect_service.go manager.go internal/helperproto internal/helperruntime/bridge/bridge.go internal/helperruntime/ingress/transparent_tcp.go manager_test.go integration/access_audit_test.go
git commit -m "feat: log protocol metadata for transparent tcp denials"
```

### Task 4: Add a transparent fail-closed MySQL-style integration test

**Files:**
- Modify: `integration/access_audit_test.go`
- Modify: `integration/network_restriction_test.go` if shared helpers are useful
- Modify: `integration/test_helpers_test.go` if shared TCP fixtures are useful

- [ ] **Step 1: Write the failing test**

Add an integration test that:

- starts a synthetic TCP server
- uses a client or shell snippet inside the sandbox to send/receive a MySQL-like handshake prefix
- runs in `TrafficModeTransparent`
- verifies the connection fails closed
- verifies the structured access log records `Kind=transparent_connect` and `Protocol=mysql`

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./integration -run 'TestTransparentModeLogsMySQLProtocolOnDeniedOpaqueTCP' -count=1`

Expected: FAIL because the access log does not yet classify the handshake as MySQL.

- [ ] **Step 3: Write minimal implementation**

Use the classifier from Task 2 and the event enrichment from Task 3 to make the new integration test pass. Do not relax enforcement.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./integration -run 'TestTransparentModeLogsMySQLProtocolOnDeniedOpaqueTCP' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/access_audit_test.go integration/network_restriction_test.go integration/test_helpers_test.go
git commit -m "test: cover mysql-style opaque tcp denial logging"
```

### Task 5: Add gRPC over MITM integration coverage

**Files:**
- Modify: `integration/mitm_h2_test.go` or create a new `integration/mitm_grpc_test.go`
- Modify: `integration/test_helpers_test.go` if a shared cert or server helper is useful

- [ ] **Step 1: Write the failing test**

Add a gRPC integration test that:

- runs a synthetic gRPC server over TLS
- uses a sandboxed gRPC client through bbox
- enables MITM
- verifies the call succeeds
- verifies the access log contains `Kind=mitm` with `Protocol=grpc`

Prefer a small self-contained test server/client pair over introducing large external toolchains.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./integration -run 'TestSandboxMITMClassifiesGRPC' -count=1`

Expected: FAIL because MITM requests are not yet classified as gRPC.

- [ ] **Step 3: Write minimal implementation**

In the MITM request path, detect gRPC using already-visible request data:

- HTTP/2 request
- `content-type` begins with `application/grpc`

Set protocol metadata on the access event while preserving `Kind=mitm`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./integration -run 'TestSandboxMITMClassifiesGRPC' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/mitm_h2_test.go integration/mitm_grpc_test.go integration/test_helpers_test.go
git commit -m "test: cover grpc protocol classification through mitm"
```

### Task 6: Classify supported HTTP and HTTPS paths consistently

**Files:**
- Modify: `manager_proxy_service.go`
- Modify: `manager_connect_service.go`
- Modify: `internal/helperruntime/ingress/mitm.go`
- Test: `manager_test.go`
- Test: `integration/access_audit_test.go`

- [ ] **Step 1: Write the failing tests**

Add unit or integration assertions that:

- plain proxied HTTP records `Protocol=http`
- MITM HTTPS defaults to `Protocol=https` when not identified as gRPC
- transparent HTTP/HTTPS preserves existing `Kind` values but can expose protocol metadata when available

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestProxyAndMITMAccessLogsIncludeProtocolMetadata' -count=1`

Expected: FAIL because existing HTTP and MITM access events do not set the new protocol metadata.

- [ ] **Step 3: Write minimal implementation**

Populate protocol metadata in the existing access-event construction paths:

- proxied HTTP -> `http`
- MITM HTTPS -> `https` unless gRPC
- transparent authorization events -> `http` or `https` when known from transparent sniffing

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestProxyAndMITMAccessLogsIncludeProtocolMetadata' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manager_proxy_service.go manager_connect_service.go internal/helperruntime/ingress/mitm.go manager_test.go integration/access_audit_test.go
git commit -m "feat: classify http and https access events"
```

### Task 7: Run targeted and full verification

**Files:**
- Modify: any files needed to fix fallout from the earlier tasks

- [ ] **Step 1: Run focused unit tests**

Run:

```bash
go test . -run 'TestAccessLogEntryIncludesProtocolMetadata|TestHandleConnectRequestRecordsTransparentProtocolMetadata|TestProxyAndMITMAccessLogsIncludeProtocolMetadata' -count=1
go test ./internal/helperruntime/ingress -run 'TestDetectOpaqueTCPProtocol|TestServeTransparentTCPConn' -count=1
```

Expected: PASS

- [ ] **Step 2: Run focused integration tests**

Run:

```bash
go test ./integration -run 'TestTransparentModeLogsMySQLProtocolOnDeniedOpaqueTCP|TestSandboxMITMClassifiesGRPC|TestNetworkRestrictionsTransparentMode|TestConnectTunnelUsesDifferentConnectPolicies|TestSandboxMITMHTTP2ConcurrentStreams' -count=1
```

Expected: PASS

- [ ] **Step 3: Run the non-integration repository test suite**

Run:

```bash
go list ./... | grep -v '^github.com/moolen/bbox/integration$' | xargs go test -count=1 -timeout=20m
```

Expected: PASS

- [ ] **Step 4: Run the full integration package**

Run:

```bash
go test ./integration -count=1 -timeout=30m
```

Expected: PASS

- [ ] **Step 5: Commit final cleanup**

```bash
git add .
git commit -m "feat: add protocol observability for non-http traffic"
```
