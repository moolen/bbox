# Transparent Traffic Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a supported per-sandbox traffic mode switch so bbox supports both the existing explicit proxy flow and a transparent hostname-only HTTP/HTTPS flow backed by sandbox-local DNS and loopback listeners.

**Architecture:** Keep the current host-side `ProxyManager` as the only policy and egress authority. Extend sandbox creation, staging, helper startup, and helper runtime so each sandbox chooses either `proxy` ingress or `transparent` ingress, with transparent mode using helper-owned DNS, HTTP `:80`, and HTTPS MITM `:443` listeners inside the sandbox namespace. Reuse existing normalized plain HTTP and MITM request paths on the host side rather than creating a second policy engine.

**Tech Stack:** Go, bubblewrap, Linux user/net namespaces, Go `net/http`, Go `crypto/tls`, Go DNS packet handling, `golang.org/x/net/http2`, existing helper bridge protocol

---

### File Structure

Planned file ownership and responsibilities:

- `types.go`
  Public `TrafficMode` API and any helper-facing config fields needed on sandbox state.
- `api.go`
  Validate manager-wide transparent-mode prerequisites if needed by public API.
- `sandbox.go`
  Sandbox creation validation, mode-aware environment injection, and sandbox runtime metadata.
- `mounts.go`
  Mode-aware helper command-line assembly.
- `staging.go`
  Mode-aware staging of `/etc/resolv.conf` and related sandbox config.
- `staging_test.go`
  Coverage for transparent staging config output.
- `sandbox_test.go`
  Coverage for traffic-mode defaults, validation, and mode-specific env behavior.
- `cmd/bbox-helper/main.go`
  Parse traffic-mode and transparent listener configuration flags.
- `internal/helperproto/messages.go`
  Extend helper readiness metadata for mode-specific reported listeners if needed.
- `internal/helperproto/messages_test.go`
  Gob round-trip coverage for any new protocol fields.
- `internal/helperruntime/runtime.go`
  Traffic-mode runtime startup, test-safe listener address plumbing, transparent DNS responder, transparent HTTP listener, and transparent HTTPS MITM listener.
- `internal/helperruntime/runtime_test.go`
  Unit coverage for DNS behavior, transparent HTTP host extraction, transparent HTTPS SNI extraction, HTTP/2 interception, and readiness/error behavior.
- `manager.go`
  Reuse existing request handling paths while making transparent HTTPS host validation explicit and mode-aware where needed.
- `manager_test.go`
  Coverage for any host-side mode-specific request semantics.
- `accesslog.go`
  Mode-aware logging and audit event fields.
- `accesslog_test.go`
  Coverage for traffic-mode access logging and audit snapshots.
- `integration/transparent_http_test.go`
  End-to-end transparent HTTP coverage without proxy env vars.
- `integration/transparent_https_test.go`
  End-to-end transparent HTTPS MITM coverage without proxy env vars, including policy denial paths.
- `integration/test_helpers_test.go`
  Shared helpers for transparent-mode test clients and prerequisites.
- `example_test.go`
  Examples showing both `proxy` and `transparent` sandbox options.
- `README.md`
  User-facing documentation for choosing a traffic mode and the transparent-mode limitations.

### Task 1: Add public traffic-mode API and sandbox validation

**Files:**
- Modify: `types.go`
- Modify: `sandbox.go`
- Modify: `sandbox_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests in `sandbox_test.go` for:

```go
func TestTrafficModeDefaultsToProxy(t *testing.T) {
	opts := SandboxOptions{}
	if got := normalizeTrafficMode(opts.TrafficMode); got != TrafficModeProxy {
		t.Fatalf("got %q want %q", got, TrafficModeProxy)
	}
}

func TestValidateSandboxOptionsRejectsUnknownTrafficMode(t *testing.T) {
	err := validateSandboxOptions(SandboxOptions{TrafficMode: TrafficMode("bogus")}, true)
	if err == nil {
		t.Fatal("expected unknown traffic mode to fail")
	}
}

func TestValidateSandboxOptionsRejectsTransparentModeWithoutMITM(t *testing.T) {
	err := validateSandboxOptions(SandboxOptions{TrafficMode: TrafficModeTransparent}, false)
	if err == nil {
		t.Fatal("expected transparent mode without MITM to fail")
	}
}

func TestRunEnvForTrafficModeSkipsProxyEnvInTransparentMode(t *testing.T) {
	env := runEnvForTrafficMode(TrafficModeTransparent, "127.0.0.1:31111", []string{"FOO=bar"})
	for _, entry := range env {
		if strings.HasPrefix(entry, "HTTP_PROXY=") || strings.HasPrefix(entry, "HTTPS_PROXY=") {
			t.Fatalf("unexpected proxy env in transparent mode: %q", entry)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestTrafficModeDefaultsToProxy|TestValidateSandboxOptionsRejectsUnknownTrafficMode|TestValidateSandboxOptionsRejectsTransparentModeWithoutMITM|TestRunEnvForTrafficModeSkipsProxyEnvInTransparentMode'`

Expected: FAIL because `TrafficMode`, `TrafficModeProxy`, `TrafficModeTransparent`, `normalizeTrafficMode`, `runEnvForTrafficMode`, or the updated `validateSandboxOptions` signature do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Implement in `types.go`:

```go
type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)
```

Add `TrafficMode TrafficMode` to `SandboxOptions`.

Implement in `sandbox.go`:

- `normalizeTrafficMode(mode TrafficMode) TrafficMode`
- `runEnvForTrafficMode(mode TrafficMode, proxyAddr string, extraEnv []string) []string`
- update `validateSandboxOptions` to accept whether manager-wide MITM is enabled
- call the new validation from `NewSandbox`
- use mode-aware env injection instead of unconditional proxy env injection

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestTrafficModeDefaultsToProxy|TestValidateSandboxOptionsRejectsUnknownTrafficMode|TestValidateSandboxOptionsRejectsTransparentModeWithoutMITM|TestRunEnvForTrafficModeSkipsProxyEnvInTransparentMode'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add types.go sandbox.go sandbox_test.go
git commit -m "feat: add sandbox traffic mode selection"
```

### Task 2: Stage transparent sandbox DNS config and helper flags

**Files:**
- Modify: `staging.go`
- Modify: `mounts.go`
- Modify: `staging_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests in `staging_test.go` for:

```go
func TestWriteSandboxConfigWritesTransparentResolvConf(t *testing.T) {
	root := t.TempDir()
	err := writeSandboxConfig(root, nil, TrafficModeTransparent)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "etc", "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "nameserver 127.0.0.1\noptions ndots:1\n" {
		t.Fatalf("unexpected resolv.conf: %q", string(content))
	}
}

func TestBuildBwrapArgsPassesTransparentTrafficModeFlags(t *testing.T) {
	args := buildBwrapArgs("/tmp/root", "/app/bbox-helper", "127.0.0.1:31111", MITMOptions{Enabled: true}, TrafficModeTransparent, nil)
	joined := strings.Join(args, " ")
	for _, needle := range []string{"--traffic-mode", "transparent"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("missing %q in %q", needle, joined)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestWriteSandboxConfigWritesTransparentResolvConf|TestBuildBwrapArgsPassesTransparentTrafficModeFlags'`

Expected: FAIL because `writeSandboxConfig` and `buildBwrapArgs` do not yet accept traffic mode.

- [ ] **Step 3: Write the minimal implementation**

Update `staging.go`:

- extend `stageSandboxRoot` and `writeSandboxConfig` to accept `TrafficMode`
- in transparent mode, write:

```text
nameserver 127.0.0.1
options ndots:1
```

- in proxy mode, do not stage `/etc/resolv.conf`

Update `mounts.go`:

- extend `buildBwrapArgs` to accept `TrafficMode`
- pass `--traffic-mode proxy|transparent` to the helper

Update `sandbox.go` call sites to pass the selected traffic mode through staging and bwrap arg assembly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestWriteSandboxConfigWritesTransparentResolvConf|TestBuildBwrapArgsPassesTransparentTrafficModeFlags'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staging.go mounts.go sandbox.go staging_test.go
git commit -m "feat: stage transparent sandbox configuration"
```

### Task 3: Extend helper startup config and readiness metadata for traffic modes

**Files:**
- Modify: `cmd/bbox-helper/main.go`
- Modify: `internal/helperproto/messages.go`
- Modify: `internal/helperproto/messages_test.go`
- Modify: `internal/helperruntime/runtime.go`

- [ ] **Step 1: Write the failing tests**

Add protocol and runtime tests for:

```go
func TestReadyRoundTripIncludesTrafficModeAddrs(t *testing.T) {
	env := Envelope{
		Ready: &Ready{
			ProtocolVersion: ProtocolVersion,
			ProxyAddr:       "127.0.0.1:31111",
			HTTPAddr:        "127.0.0.1:80",
			HTTPSAddr:       "127.0.0.1:443",
			DNSAddr:         "127.0.0.1:53",
		},
	}
	// gob round-trip and assert fields survive
}

func TestRunTransparentRequiresAllListeners(t *testing.T) {
	cfg := Config{
		Bridge:      newTestBridge(),
		TrafficMode: TrafficModeTransparent,
		MITMEnabled: true,
		DNSAddr:     "127.0.0.1:0",
		HTTPAddr:    "127.0.0.1:0",
		HTTPSAddr:   "127.0.0.1:0",
	}
	// force one bind failure and assert Run returns an error
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperproto ./internal/helperruntime -run 'TestReadyRoundTripIncludesTrafficModeAddrs|TestRunTransparentRequiresAllListeners'`

Expected: FAIL because the extra readiness fields and traffic-mode config do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Update `internal/helperproto/messages.go`:

- extend `Ready` with optional `DNSAddr`, `HTTPAddr`, and `HTTPSAddr`
- bump `ProtocolVersion`

Update `cmd/bbox-helper/main.go`:

- add `--traffic-mode`
- add optional transparent listener flags for DNS, HTTP, and HTTPS
- pass it into `helperruntime.Config`

Update `internal/helperruntime/runtime.go`:

- add `TrafficMode` to `Config`
- add `DNSAddr`, `HTTPAddr`, and `HTTPSAddr` to `Config`
- split runtime startup into:
  - `runProxyMode`
  - `runTransparentMode`
- default transparent listener addrs to `127.0.0.1:53`, `127.0.0.1:80`, and `127.0.0.1:443` when the config fields are empty
- allow unit tests to pass `:0` addresses so test runs do not require privileged-port binds
- make readiness report the proxy addr in proxy mode and the low-port listener addrs in transparent mode

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperproto ./internal/helperruntime -run 'TestReadyRoundTripIncludesTrafficModeAddrs|TestRunTransparentRequiresAllListeners'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/bbox-helper/main.go internal/helperproto/messages.go internal/helperproto/messages_test.go internal/helperruntime/runtime.go
git commit -m "feat: add helper traffic mode startup"
```

### Task 4: Add transparent DNS responder coverage

**Files:**
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests in `internal/helperruntime/runtime_test.go` for:

```go
func TestTransparentDNSReturnsLoopbackForAQuery(t *testing.T) {}

func TestTransparentDNSReturnsEmptySuccessForAAAAQuery(t *testing.T) {}

func TestTransparentDNSRefusesUnsupportedQueryType(t *testing.T) {}

func TestTransparentDNSHandlesTCPAndUDP(t *testing.T) {}
```

The tests should assert:

- `A example.com` -> `127.0.0.1`
- `AAAA example.com` -> `NOERROR` with zero answers
- unsupported type -> `REFUSED`
- same behavior over UDP and TCP
- tests use `:0` listener addresses rather than privileged ports

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime -run 'TestTransparentDNSReturnsLoopbackForAQuery|TestTransparentDNSReturnsEmptySuccessForAAAAQuery|TestTransparentDNSRefusesUnsupportedQueryType|TestTransparentDNSHandlesTCPAndUDP'`

Expected: FAIL because no transparent DNS responder exists yet.

- [ ] **Step 3: Write the minimal implementation**

Implement in `internal/helperruntime/runtime.go`:

- a small in-process DNS responder
- UDP and TCP listeners on `cfg.DNSAddr`, defaulting to `127.0.0.1:53` when the config field is empty
- narrow request handling for `A`, `AAAA`, and unsupported query types
- no recursion, no upstream lookup

Keep the implementation in focused helper functions rather than embedding protocol parsing directly into `Run`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime -run 'TestTransparentDNSReturnsLoopbackForAQuery|TestTransparentDNSReturnsEmptySuccessForAAAAQuery|TestTransparentDNSRefusesUnsupportedQueryType|TestTransparentDNSHandlesTCPAndUDP'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go
git commit -m "feat: add transparent dns responder"
```

### Task 5: Add transparent HTTP ingress on port 80

**Files:**
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `manager.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestTransparentHTTPRejectsMissingHost(t *testing.T) {}

func TestTransparentHTTPNormalizesOriginFormRequest(t *testing.T) {}

func TestHandleProxyRequestAcceptsOriginStyleURLFromTransparentIngress(t *testing.T) {}
```

The tests should verify:

- origin-form requests require a usable host
- transparent HTTP reconstructs `http://host/path?query`
- host-side forwarding and policy evaluation behave the same as current plain HTTP proxy requests once normalized

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime ./... -run 'TestTransparentHTTPRejectsMissingHost|TestTransparentHTTPNormalizesOriginFormRequest|TestHandleProxyRequestAcceptsOriginStyleURLFromTransparentIngress'`

Expected: FAIL because there is no transparent HTTP listener or normalization path yet.

- [ ] **Step 3: Write the minimal implementation**

Implement in `internal/helperruntime/runtime.go`:

- transparent HTTP listener on `cfg.HTTPAddr`, defaulting to `127.0.0.1:80` when the config field is empty
- handler that accepts origin-form requests
- host extraction from `req.Host`
- normalization into existing `helperproto.ProxyRequest`

Adjust `manager.go` only if needed to keep host/path handling consistent after normalization. Do not create a second host-side HTTP execution path.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime ./... -run 'TestTransparentHTTPRejectsMissingHost|TestTransparentHTTPNormalizesOriginFormRequest|TestHandleProxyRequestAcceptsOriginStyleURLFromTransparentIngress'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go manager.go manager_test.go
git commit -m "feat: add transparent http ingress"
```

### Task 6: Add transparent HTTPS MITM ingress on port 443

**Files:**
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `manager.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestTransparentHTTPSRejectsMissingSNI(t *testing.T) {}

func TestTransparentHTTPSRequestsLeafCertForSNIHost(t *testing.T) {}

func TestTransparentHTTPSForwardsDecryptedRequestsThroughMITMPath(t *testing.T) {}

func TestTransparentHTTPSSupportsHTTP2MITM(t *testing.T) {}
```

The tests should verify:

- no SNI -> connection fails closed
- SNI host drives leaf-cert issuance
- decrypted HTTP/1.1 request is normalized into the same `MITMRequest` path used by proxy-mode MITM
- decrypted HTTP/2 requests over TLS are accepted and forwarded through the same MITM path

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime ./... -run 'TestTransparentHTTPSRejectsMissingSNI|TestTransparentHTTPSRequestsLeafCertForSNIHost|TestTransparentHTTPSForwardsDecryptedRequestsThroughMITMPath|TestTransparentHTTPSSupportsHTTP2MITM'`

Expected: FAIL because transparent HTTPS ingress does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Implement in `internal/helperruntime/runtime.go`:

- transparent HTTPS listener on `cfg.HTTPSAddr`, defaulting to `127.0.0.1:443` when the config field is empty
- TLS server handshake driven by SNI
- reuse of existing leaf-cert request path
- request normalization into existing `mitmRoundTrip`

Adjust `manager.go` only where needed so transparent HTTPS host validation and access logging remain explicit and correct without relying on `AllowConnect`.

Do not add any raw-tunnel fallback path for transparent HTTPS.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime ./... -run 'TestTransparentHTTPSRejectsMissingSNI|TestTransparentHTTPSRequestsLeafCertForSNIHost|TestTransparentHTTPSForwardsDecryptedRequestsThroughMITMPath|TestTransparentHTTPSSupportsHTTP2MITM'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go manager.go manager_test.go
git commit -m "feat: add transparent https mitm ingress"
```

### Task 7: Surface mode-aware helper readiness and sandbox metadata

**Files:**
- Modify: `helper_client.go`
- Modify: `sandbox.go`
- Modify: `sandbox_test.go`
- Modify: `helper_client_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestHelperClientStartAcceptsTransparentReadyEnvelope(t *testing.T) {}

func TestSandboxProxyAccessorsRemainEmptyInTransparentMode(t *testing.T) {}
```

The tests should verify:

- helper startup succeeds when readiness reports transparent listeners instead of a proxy listener
- sandbox metadata does not claim proxy env/addr semantics for transparent mode

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestHelperClientStartAcceptsTransparentReadyEnvelope|TestSandboxProxyAccessorsRemainEmptyInTransparentMode'`

Expected: FAIL because helper startup and sandbox metadata currently assume proxy-mode readiness.

- [ ] **Step 3: Write the minimal implementation**

Update `helper_client.go`:

- accept readiness envelopes for both traffic modes
- return whichever address data the sandbox needs for mode-specific startup bookkeeping

Update `sandbox.go`:

- store the selected `TrafficMode`
- keep proxy accessors meaningful only for proxy mode
- avoid injecting stale proxy metadata into transparent sandboxes

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestHelperClientStartAcceptsTransparentReadyEnvelope|TestSandboxProxyAccessorsRemainEmptyInTransparentMode'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add helper_client.go helper_client_test.go sandbox.go sandbox_test.go
git commit -m "feat: handle helper readiness for both traffic modes"
```

### Task 8: Make access logging and audit state traffic-mode aware

**Files:**
- Modify: `types.go`
- Modify: `accesslog.go`
- Modify: `accesslog_test.go`
- Modify: `manager.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestAccessLogEntryIncludesTrafficMode(t *testing.T) {}

func TestAccessedDomainsTracksTrafficModeKinds(t *testing.T) {}
```

The tests should verify:

- access events include whether the request came from proxy or transparent ingress
- transparent HTTP and transparent HTTPS attempts remain distinguishable for troubleshooting without changing allow/deny semantics

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestAccessLogEntryIncludesTrafficMode|TestAccessedDomainsTracksTrafficModeKinds'`

Expected: FAIL because access/audit logging is not yet mode-aware.

- [ ] **Step 3: Write the minimal implementation**

Update:

- `types.go` to add a traffic-mode field to `AccessLogEntry` if needed
- `accesslog.go` to emit traffic-mode metadata
- `manager.go` call sites so proxy and transparent request paths populate mode-aware events consistently

Keep the existing event model intact apart from the minimum field additions needed for troubleshooting.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestAccessLogEntryIncludesTrafficMode|TestAccessedDomainsTracksTrafficModeKinds'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add types.go accesslog.go accesslog_test.go manager.go
git commit -m "feat: add traffic mode to access logging"
```

### Task 9: Add transparent-mode integration coverage

**Files:**
- Create: `integration/transparent_http_test.go`
- Create: `integration/transparent_https_test.go`
- Modify: `integration/test_helpers_test.go`

- [ ] **Step 1: Write the failing tests**

Create `integration/transparent_http_test.go` with coverage for:

```go
func TestTransparentHTTPWithCurl(t *testing.T) {}
```

Behavior:

- create a sandbox with `TrafficModeTransparent`
- do not rely on proxy env vars
- run `curl http://hostname/path`
- assert success for allowed host/path
- assert deterministic failure for denied host/path

Create `integration/transparent_https_test.go` with coverage for:

```go
func TestTransparentHTTPSWithCurl(t *testing.T) {}

func TestTransparentModeRejectsIPLiteralAndNonDefaultPorts(t *testing.T) {}

func TestProxyAndTransparentSandboxesCanRunConcurrently(t *testing.T) {}
```

Behavior:

- create a sandbox with `TrafficModeTransparent` and manager-wide MITM enabled
- run `curl https://hostname/path`
- assert success and policy denials
- assert IP-literal and `:8443` requests fail as documented
- assert one proxy-mode sandbox and one transparent-mode sandbox can run concurrently under one manager without shared-port confusion

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./integration -run 'TestTransparentHTTPWithCurl|TestTransparentHTTPSWithCurl|TestTransparentModeRejectsIPLiteralAndNonDefaultPorts|TestProxyAndTransparentSandboxesCanRunConcurrently' -v`

Expected: FAIL because transparent mode is not implemented yet.

- [ ] **Step 3: Write the minimal implementation**

Add the integration tests and any shared helpers needed in `integration/test_helpers_test.go`, including helper logic for:

- hostname selection that exercises sandbox DNS
- environment assertions showing proxy env vars are not required
- trust setup for HTTPS transparent mode

Only add the minimum helper code needed by these new tests.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./integration -run 'TestTransparentHTTPWithCurl|TestTransparentHTTPSWithCurl|TestTransparentModeRejectsIPLiteralAndNonDefaultPorts|TestProxyAndTransparentSandboxesCanRunConcurrently' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/transparent_http_test.go integration/transparent_https_test.go integration/test_helpers_test.go
git commit -m "test: cover transparent traffic mode"
```

### Task 10: Document dual-mode usage and transparent-mode limitations

**Files:**
- Modify: `README.md`
- Modify: `doc.go`
- Modify: `example_test.go`

- [ ] **Step 1: Write the failing documentation/examples**

Add/update examples for:

```go
func ExampleProxyModeSandbox() {}

func ExampleTransparentModeSandbox() {}
```

Document in `README.md`:

- how to choose `TrafficModeProxy` vs `TrafficModeTransparent`
- that proxy mode uses `HTTP_PROXY` / `HTTPS_PROXY`
- that transparent mode supports only hostname-based `:80` / `:443`
- that transparent mode does not support IP literals, non-default ports, or QUIC/HTTP/3

- [ ] **Step 2: Run example/doc checks to verify the new examples are wired correctly**

Run: `go test ./... -run 'ExampleProxyModeSandbox|ExampleTransparentModeSandbox'`

Expected: PASS once the examples compile against the new API.

- [ ] **Step 3: Write the minimal implementation**

Update:

- `README.md`
- `doc.go`
- `example_test.go`

Keep the examples minimal and focused on mode selection, not full end-to-end setup detail.

- [ ] **Step 4: Run docs/examples to verify they pass**

Run: `go test ./... -run 'ExampleProxyModeSandbox|ExampleTransparentModeSandbox'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add README.md doc.go example_test.go
git commit -m "docs: document proxy and transparent traffic modes"
```

### Task 11: Run full verification

**Files:**
- Modify: none

- [ ] **Step 1: Run unit tests**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 2: Run focused integration coverage for both modes**

Run: `go test ./integration -run 'TestSandboxMITMHTTPSWithCurl|TestTransparentHTTPWithCurl|TestTransparentHTTPSWithCurl|TestTransparentModeRejectsIPLiteralAndNonDefaultPorts' -v`

Expected: PASS

- [ ] **Step 3: Inspect the tree**

Run: `git status --short`

Expected: clean working tree

- [ ] **Step 4: Commit**

No commit in this step. The tree should already be clean after the task commits above.
