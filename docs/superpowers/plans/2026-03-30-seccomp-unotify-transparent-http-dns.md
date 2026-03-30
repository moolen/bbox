# Seccomp-Unotify Transparent HTTP+DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current transparent listener approach with a seccomp-unotify supervised transparent HTTP+DNS path that supports HTTP/1.1, `h2c`, TLS-backed HTTP/1.1 and HTTP/2 on any TCP port, and DNS over UDP `53`, while keeping all policy enforcement on the host side.

**Architecture:** Keep the host-side `ProxyManager` as the only policy and egress authority. Add a small C launcher for payload exec, a helper-side seccomp supervisor for rewritten socket syscalls, a single helper-owned transparent TCP ingress that classifies HTTP/TLS traffic, and a bridge-backed DNS round-trip path to host resolvers from the host `/etc/resolv.conf`. Remove the raw-TCP fallback and fail closed for unsupported TCP protocols or DNS variants.

**Tech Stack:** Go, C, bubblewrap, Linux seccomp user notifications, `libseccomp-golang`, Go `net/http`, Go `crypto/tls`, Go `x/net/http2`, gob bridge protocol, existing proxy/MITM manager infrastructure

---

### File Structure

Planned file ownership and responsibilities:

- `helper_binary.go`
  Build and bundle both the helper binary and the new seccomp launcher binary.
- `helper_binary_test.go`
  Cover helper resolver behavior for launcher build and sibling lookup.
- `staging.go`
  Stage the launcher binary into the sandbox root and write host-derived `resolv.conf` for transparent mode.
- `staging_test.go`
  Cover launcher staging and transparent resolver config generation.
- `mounts.go`
  Pass launcher/helper wiring flags to bubblewrap and keep transparent mode in isolated networking.
- `sandbox.go`
  Wire transparent-mode startup around the new launcher/supervisor path and update ready-state expectations.
- `sandbox_test.go`
  Cover transparent-mode startup validation and staged runtime prerequisites.
- `cmd/bbox-seccomp-launcher/main.c`
  New small C launcher that installs the seccomp notify filter and returns the notify FD before `execve()`.
- `cmd/bbox-helper/main.go`
  Parse any new transparent runtime flags and feed them into `helperruntime.Config`.
- `internal/helperproto/messages.go`
  Add DNS request/response envelopes, exec input cancellation support, and any new ready metadata needed for the supervised runtime.
- `internal/helperproto/messages_test.go`
  Gob round-trip coverage for new helper protocol fields.
- `helper_client_bridge.go`
  Dispatch DNS requests and updated exec input/result envelopes between helper and manager.
- `manager.go`
  Route DNS bridge requests, IP-aware leaf cert requests, and updated transparent-mode events.
- `manager_dns_service.go`
  New host-side DNS forwarding service that reads upstream resolvers from the host `/etc/resolv.conf`.
- `manager_dns_service_test.go`
  Cover DNS query validation, upstream forwarding, policy denial, and audit recording.
- `policy.go`
  Extend policy compilation and checks for IP literals, CIDR rules, and DNS hostname checks.
- `policy_test.go`
  Cover IP/CIDR matching, DNS checks, and hostname-to-IP consistency rules.
- `mitm.go`
  Support IP SAN leaf certificates and cache keys for IP-literal interception.
- `mitm_test.go`
  Cover IP SAN issuance in addition to DNS SAN issuance.
- `accesslog.go`
  Record DNS events, transparent TCP denials, and IP-policy decisions without losing original destinations.
- `accesslog_test.go`
  Cover new event kinds and original-destination normalization.
- `internal/helperruntime/bridge/bridge.go`
  Add DNS round-trip support and updated exec input routing.
- `internal/helperruntime/bridge/bridge_dns_test.go`
  New bridge tests for DNS envelope round trips.
- `internal/helperruntime/runtime.go`
  Run payload execs under the seccomp supervisor in transparent mode and expose the single TCP ingress runtime targets.
- `internal/helperruntime/config.go`
  Replace the direct transparent DNS/HTTP/HTTPS listener config with single-ingress transparent runtime config.
- `internal/helperruntime/runtime_test.go`
  Cover supervised transparent exec, DNS bridge behavior, protocol classification, and HTTP/2 multi-stream behavior.
- `internal/helperruntime/transparent_mode.go`
  Replace the old DNS/HTTP/HTTPS listener trio with a single transparent TCP ingress listener.
- `internal/helperruntime/ingress/transparent.go`
  Keep shared transparent rewrite helpers and move routing to protocol-aware handling instead of port-based listeners.
- `internal/helperruntime/ingress/transparent_tcp.go`
  New TCP sniffing and dispatch entrypoint for plaintext HTTP/1.x, `h2c`, and TLS.
- `internal/helperruntime/ingress/transparent_tcp_test.go`
  New tests for protocol classification, fail-closed behavior, and non-standard ports.
- `internal/helperruntime/ingress/h2c.go`
  New cleartext HTTP/2 and upgrade handling that reuses the existing MITM request path per stream.
- `internal/helperruntime/ingress/h2c_test.go`
  New tests for prior-knowledge and upgrade `h2c`.
- `internal/helperruntime/seccompnotify/addfd_linux.go`
  Linux `SECCOMP_IOCTL_NOTIF_ADDFD` helper copied and adapted from the reference implementation.
- `internal/helperruntime/seccompnotify/fd_registry.go`
  Track managed child/helper socket pairs and destination metadata.
- `internal/helperruntime/seccompnotify/fd_registry_test.go`
  Cover socket lifecycle, dup, and close semantics.
- `internal/helperruntime/seccompnotify/sockaddr_linux.go`
  Decode intercepted socket addresses and preserve original destinations.
- `internal/helperruntime/seccompnotify/sockaddr_linux_test.go`
  Cover IPv4 and IPv6 sockaddr decoding.
- `internal/helperruntime/seccompnotify/types.go`
  Define runtime targets and per-socket state for managed TCP and DNS sockets.
- `internal/helperruntime/seccompnotify/supervisor_runtime_linux.go`
  Prepare exec commands through the launcher, receive the notify FD, and run the notification loop.
- `internal/helperruntime/seccompnotify/supervisor_linux.go`
  Emulate `socket`/`connect`/DNS send and receive syscalls and redirect managed TCP sockets to the transparent ingress listener.
- `internal/helperruntime/seccompnotify/supervisor_linux_test.go`
  Cover per-syscall supervisor behavior and fail-closed cases.
- `internal/helperruntime/seccompnotify/supervisor_runtime_stub.go`
  Non-Linux build stub for the supervisor runtime.
- `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go`
  End-to-end launcher + supervisor tests for redirected TCP and DNS syscalls.
- `integration/transparent_http_test.go`
  End-to-end transparent HTTP coverage without proxy env vars on non-standard ports.
- `integration/transparent_https_test.go`
  End-to-end transparent TLS coverage without proxy env vars on non-standard ports.
- `integration/mitm_h2_test.go`
  Expand end-to-end HTTP/2 coverage to assert multiple concurrent streams in transparent mode.
- `integration/network_restriction_test.go`
  Cover denial of unsupported TCP protocols, DNS over TCP, and IP-policy enforcement.
- `README.md`
  Document the seccomp-unotify transparent mode, supported protocols, and fail-closed limitations.

### Task 1: Bundle the seccomp launcher and stage transparent-mode runtime assets

**Files:**
- Create: `cmd/bbox-seccomp-launcher/main.c`
- Modify: `helper_binary.go`
- Modify: `helper_binary_test.go`
- Modify: `staging.go`
- Modify: `staging_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestHelperBinaryBuildsSeccompLauncher(t *testing.T)
func TestStageSandboxRootCopiesSeccompLauncher(t *testing.T)
func TestWriteSandboxConfigMirrorsHostResolvConfNameservers(t *testing.T)
```

Assert that:

- the helper resolver builds `bbox-helper` and `bbox-seccomp-launcher` into the same temp build directory
- transparent staging copies the launcher to `/app/bbox-seccomp-launcher`
- transparent `resolv.conf` keeps host `nameserver` lines instead of `127.0.0.1`

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestHelperBinaryBuildsSeccompLauncher|TestStageSandboxRootCopiesSeccompLauncher|TestWriteSandboxConfigMirrorsHostResolvConfNameservers'`

Expected: FAIL because the launcher binary does not exist and staging still writes the old loopback resolver config.

- [ ] **Step 3: Write the minimal implementation**

Implement:

- `cmd/bbox-seccomp-launcher/main.c` by adapting `~/dev/patchpilot-v2/internal/sandbox/cmd/patchpilot-seccomp-launcher/main.c`
- `helper_binary.go` so `HelperBinary()` builds both binaries into the same temp dir
- `staging.go` constants:

```go
const (
	defaultSandboxHelperPath   = "/app/bbox-helper"
	defaultSandboxLauncherPath = "/app/bbox-seccomp-launcher"
)
```

- stage the launcher binary into the root and write host-derived `resolv.conf` content for transparent mode

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestHelperBinaryBuildsSeccompLauncher|TestStageSandboxRootCopiesSeccompLauncher|TestWriteSandboxConfigMirrorsHostResolvConfNameservers'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/bbox-seccomp-launcher/main.c helper_binary.go helper_binary_test.go staging.go staging_test.go
git commit -m "feat: bundle seccomp launcher for transparent mode"
```

### Task 2: Extend the helper bridge protocol for DNS and supervised exec control

**Files:**
- Modify: `internal/helperproto/messages.go`
- Modify: `internal/helperproto/messages_test.go`
- Modify: `internal/helperruntime/bridge/bridge.go`
- Create: `internal/helperruntime/bridge/bridge_dns_test.go`
- Modify: `helper_client_bridge.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestEnvelopeKindDNSRequest(t *testing.T)
func TestEnvelopeRoundTripIncludesDNSResponse(t *testing.T)
func TestRuntimeBridgeDNSRoundTrip(t *testing.T)
```

And extend exec-envelope round-trip coverage so `ExecInput.Cancel` and ID-aware exec input routing survive gob encoding.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperproto ./internal/helperruntime/bridge ./... -run 'TestEnvelopeKindDNSRequest|TestEnvelopeRoundTripIncludesDNSResponse|TestRuntimeBridgeDNSRoundTrip'`

Expected: FAIL because DNS envelopes and bridge round trips do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Implement in `internal/helperproto/messages.go`:

```go
type DNSRequest struct {
	Network string
	Host    string
	Port    int
	Payload []byte
}

type DNSResponse struct {
	Payload []byte
	Error   string
}
```

Also:

- add `DNSRequest`/`DNSResponse` to `Envelope`
- bump `ProtocolVersion`
- add `Cancel bool` to `ExecInput`
- make `internal/helperruntime/bridge/bridge.go` support `DNSRoundTrip`
- dispatch DNS requests in `helper_client_bridge.go`

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperproto ./internal/helperruntime/bridge ./... -run 'TestEnvelopeKindDNSRequest|TestEnvelopeRoundTripIncludesDNSResponse|TestRuntimeBridgeDNSRoundTrip'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperproto/messages.go internal/helperproto/messages_test.go internal/helperruntime/bridge/bridge.go internal/helperruntime/bridge/bridge_dns_test.go helper_client_bridge.go
git commit -m "feat: add dns bridge protocol support"
```

### Task 3: Add host-side DNS forwarding and IP-aware policy primitives

**Files:**
- Create: `manager_dns_service.go`
- Create: `manager_dns_service_test.go`
- Modify: `manager.go`
- Modify: `types.go`
- Modify: `policy.go`
- Modify: `policy_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestSystemDNSServersReadsHostResolvConf(t *testing.T)
func TestProxyManagerHandleDNSRequestAppliesPolicyAndAudit(t *testing.T)
func TestCompilePolicySupportsCIDRRules(t *testing.T)
func TestPolicyCheckAllowsIPLiteralWithinCIDR(t *testing.T)
func TestPolicyCheckDNSUsesHostRules(t *testing.T)
```

Use a minimal public API extension:

```go
type NetworkPolicy struct {
	AllowIPCIDRs []string
	DenyIPCIDRs  []string
	// existing fields...
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestSystemDNSServersReadsHostResolvConf|TestProxyManagerHandleDNSRequestAppliesPolicyAndAudit|TestCompilePolicySupportsCIDRRules|TestPolicyCheckAllowsIPLiteralWithinCIDR|TestPolicyCheckDNSUsesHostRules'`

Expected: FAIL because DNS forwarding and CIDR-aware policy compilation do not exist.

- [ ] **Step 3: Write the minimal implementation**

Create `manager_dns_service.go` by adapting the reference `manager_dns_service.go`, then:

- add `handleDNSRequest` to `manager.go`
- compile `AllowIPCIDRs` and `DenyIPCIDRs` into `*net.IPNet`
- teach `compiledPolicy.Check` to accept IP literals through CIDR rules
- add `compiledPolicy.CheckDNS(host string) error` that validates DNS hostnames without requiring an HTTP method

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestSystemDNSServersReadsHostResolvConf|TestProxyManagerHandleDNSRequestAppliesPolicyAndAudit|TestCompilePolicySupportsCIDRRules|TestPolicyCheckAllowsIPLiteralWithinCIDR|TestPolicyCheckDNSUsesHostRules'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manager_dns_service.go manager_dns_service_test.go manager.go types.go policy.go policy_test.go
git commit -m "feat: add host dns forwarding and ip policy rules"
```

### Task 4: Introduce the seccomp supervisor package and launcher handshake

**Files:**
- Create: `internal/helperruntime/seccompnotify/addfd_linux.go`
- Create: `internal/helperruntime/seccompnotify/fd_registry.go`
- Create: `internal/helperruntime/seccompnotify/fd_registry_test.go`
- Create: `internal/helperruntime/seccompnotify/sockaddr_linux.go`
- Create: `internal/helperruntime/seccompnotify/sockaddr_linux_test.go`
- Create: `internal/helperruntime/seccompnotify/types.go`
- Create: `internal/helperruntime/seccompnotify/supervisor_runtime_linux.go`
- Create: `internal/helperruntime/seccompnotify/supervisor_runtime_stub.go`
- Create: `internal/helperruntime/seccompnotify/supervisor_linux.go`
- Create: `internal/helperruntime/seccompnotify/supervisor_linux_test.go`
- Create: `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go`

- [ ] **Step 1: Write the failing tests**

Port the narrowest failing tests first:

```go
func TestDecodeSockaddrIPv4(t *testing.T)
func TestFDRegistryDupClonesHelperFD(t *testing.T)
func TestResolveLauncherCommandUsesSiblingLauncher(t *testing.T)
func TestSupervisorStartRedirectsTCPConnectRuntime(t *testing.T)
```

The runtime test should build the launcher and assert that a payload `connect()` to an external address is accepted on a local test listener instead.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime/seccompnotify -run 'TestDecodeSockaddrIPv4|TestFDRegistryDupClonesHelperFD|TestResolveLauncherCommandUsesSiblingLauncher|TestSupervisorStartRedirectsTCPConnectRuntime'`

Expected: FAIL because the package does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Copy and adapt the reference files from `~/dev/patchpilot-v2/internal/sandbox/internal/helperruntime/seccompnotify`, but remove the raw-TCP fallback assumptions from the runtime target model. Keep:

- notify FD receive/respond loop
- helper FD injection via `SECCOMP_IOCTL_NOTIF_ADDFD`
- socket registry
- launcher socketpair handshake

Define runtime targets around one transparent TCP ingress plus DNS bridging:

```go
type RuntimeTargets struct {
	TransparentTCPAddr string
	DNSRoundTrip func(context.Context, string, []byte) ([]byte, error)
	RecordOriginalDestination func(localAddr, host string, port int)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime/seccompnotify -run 'TestDecodeSockaddrIPv4|TestFDRegistryDupClonesHelperFD|TestResolveLauncherCommandUsesSiblingLauncher|TestSupervisorStartRedirectsTCPConnectRuntime'`

Expected: PASS on Linux; non-Linux uses the stub build and skips runtime coverage.

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/seccompnotify
git commit -m "feat: add seccomp notify supervisor"
```

### Task 5: Run transparent payload execs through the launcher and supervisor

**Files:**
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/config.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `cmd/bbox-helper/main.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestRunSupervisedExecStartsLauncherInTransparentMode(t *testing.T)
func TestTransparentExecCancelTargetsCurrentRequestID(t *testing.T)
```

Use test doubles for:

- supervisor creation
- supervisor prepare/start hooks
- bridge DNS round trips

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime -run 'TestRunSupervisedExecStartsLauncherInTransparentMode|TestTransparentExecCancelTargetsCurrentRequestID'`

Expected: FAIL because transparent exec still starts payloads directly.

- [ ] **Step 3: Write the minimal implementation**

Update `internal/helperruntime/runtime.go` to:

- create a supervisor only for `TrafficModeTransparent`
- wrap payload `exec.Cmd` through the launcher before `cmd.Start()`
- start the supervisor after the child PID exists
- route exec input by request ID and honor `ExecInput.Cancel`

Trim `internal/helperruntime/config.go` so transparent mode uses one `TransparentTCPAddr` instead of public DNS/HTTP/HTTPS listener config.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime -run 'TestRunSupervisedExecStartsLauncherInTransparentMode|TestTransparentExecCancelTargetsCurrentRequestID'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/runtime.go internal/helperruntime/config.go internal/helperruntime/runtime_test.go cmd/bbox-helper/main.go
git commit -m "feat: supervise transparent payload execs"
```

### Task 6: Replace the old transparent listeners with a single protocol-aware TCP ingress

**Files:**
- Modify: `internal/helperruntime/transparent_mode.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/ingress/transparent.go`
- Create: `internal/helperruntime/ingress/transparent_tcp.go`
- Create: `internal/helperruntime/ingress/transparent_tcp_test.go`
- Modify: `internal/helperruntime/runtime_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestTransparentTCPClassifiesHTTP1Plaintext(t *testing.T)
func TestTransparentTCPClassifiesTLSClientHello(t *testing.T)
func TestTransparentTCPRejectsUnknownProtocol(t *testing.T)
func TestTransparentHTTPUsesOriginalDestinationPortOnNonStandardPort(t *testing.T)
```

Keep tests at the connection boundary with `net.Pipe()` or a single test listener instead of dialing helper-exposed `:80`/`:443`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime ./internal/helperruntime/ingress -run 'TestTransparentTCPClassifiesHTTP1Plaintext|TestTransparentTCPClassifiesTLSClientHello|TestTransparentTCPRejectsUnknownProtocol|TestTransparentHTTPUsesOriginalDestinationPortOnNonStandardPort'`

Expected: FAIL because the transparent runtime still routes by dedicated DNS/HTTP/HTTPS listeners.

- [ ] **Step 3: Write the minimal implementation**

Implement `transparent_tcp.go` with a first-read classifier that:

- dispatches TLS to `serveMITMConn`
- dispatches plaintext HTTP/1.x to `serveHTTPForward`
- closes anything else

Update `transparent_mode.go` to bind only one transparent TCP ingress listener and expose its address to the supervisor runtime targets.

Record original destination host/port in the runtime bridge so request rewriting can preserve non-standard ports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime ./internal/helperruntime/ingress -run 'TestTransparentTCPClassifiesHTTP1Plaintext|TestTransparentTCPClassifiesTLSClientHello|TestTransparentTCPRejectsUnknownProtocol|TestTransparentHTTPUsesOriginalDestinationPortOnNonStandardPort'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/transparent_mode.go internal/helperruntime/runtime.go internal/helperruntime/ingress/transparent.go internal/helperruntime/ingress/transparent_tcp.go internal/helperruntime/ingress/transparent_tcp_test.go internal/helperruntime/runtime_test.go
git commit -m "feat: add single transparent tcp ingress"
```

### Task 7: Add `h2c` and TLS-backed HTTP/2 multi-stream support on the transparent ingress

**Files:**
- Create: `internal/helperruntime/ingress/h2c.go`
- Create: `internal/helperruntime/ingress/h2c_test.go`
- Modify: `internal/helperruntime/ingress/mitm.go`
- Modify: `internal/helperruntime/runtime_test.go`
- Modify: `integration/mitm_h2_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestTransparentTCPClassifiesH2CPriorKnowledge(t *testing.T)
func TestTransparentTCPUpgradesHTTP11ToH2C(t *testing.T)
func TestTransparentTLSHTTP2SupportsMultipleConcurrentStreams(t *testing.T)
```

The HTTP/2 integration test must open one client connection and issue multiple concurrent requests before reading all responses.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime ./internal/helperruntime/ingress ./integration -run 'TestTransparentTCPClassifiesH2CPriorKnowledge|TestTransparentTCPUpgradesHTTP11ToH2C|TestTransparentTLSHTTP2SupportsMultipleConcurrentStreams'`

Expected: FAIL because transparent mode does not yet support cleartext HTTP/2 or explicit multi-stream assertions.

- [ ] **Step 3: Write the minimal implementation**

Implement:

- `h2c` prior-knowledge handling using `http2.Server`
- HTTP/1.1 `Upgrade: h2c` handling that reuses the same connection
- request forwarding that preserves the original destination host/IP and port for each stream
- TLS-backed HTTP/2 multi-stream handling by reusing the existing MITM `http2.ConfigureServer` path

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime ./internal/helperruntime/ingress ./integration -run 'TestTransparentTCPClassifiesH2CPriorKnowledge|TestTransparentTCPUpgradesHTTP11ToH2C|TestTransparentTLSHTTP2SupportsMultipleConcurrentStreams'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/ingress/h2c.go internal/helperruntime/ingress/h2c_test.go internal/helperruntime/ingress/mitm.go internal/helperruntime/runtime_test.go integration/mitm_h2_test.go
git commit -m "feat: support transparent h2c and multi-stream h2"
```

### Task 8: Emulate all supported UDP DNS syscall variants through the bridge

**Files:**
- Modify: `internal/helperruntime/seccompnotify/types.go`
- Modify: `internal/helperruntime/seccompnotify/supervisor_linux.go`
- Modify: `internal/helperruntime/seccompnotify/supervisor_linux_test.go`
- Modify: `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `internal/helperruntime/runtime_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestSupervisorStartRedirectsConnectedUDPDNSRuntime(t *testing.T)
func TestSupervisorStartRedirectsSendToDNSRuntime(t *testing.T)
func TestSupervisorStartRedirectsSendMsgDNSRuntime(t *testing.T)
func TestSupervisorRejectsDNSTCPRuntime(t *testing.T)
```

Cover both connected UDP and unconnected `sendto`/`recvfrom` and `sendmsg`/`recvmsg` pairs.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/helperruntime/seccompnotify ./internal/helperruntime -run 'TestSupervisorStartRedirectsConnectedUDPDNSRuntime|TestSupervisorStartRedirectsSendToDNSRuntime|TestSupervisorStartRedirectsSendMsgDNSRuntime|TestSupervisorRejectsDNSTCPRuntime'`

Expected: FAIL because only TCP connect redirection exists.

- [ ] **Step 3: Write the minimal implementation**

Extend supervisor socket state with DNS fields:

```go
type SocketState struct {
	Kind           SocketKind
	DNSManaged     bool
	ConnectedHost  string
	ConnectedPort  int
	PendingDNSResp [][]byte
	// existing fd metadata...
}
```

Implement:

- UDP socket detection for destination port `53`
- DNS payload capture from `sendto`/`sendmsg`/`sendmmsg`
- bridge DNS round trip via `RuntimeTargets.DNSRoundTrip`
- response replay on `recvfrom`/`recvmsg`/`recvmmsg`
- explicit denial for TCP DNS

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/helperruntime/seccompnotify ./internal/helperruntime -run 'TestSupervisorStartRedirectsConnectedUDPDNSRuntime|TestSupervisorStartRedirectsSendToDNSRuntime|TestSupervisorStartRedirectsSendMsgDNSRuntime|TestSupervisorRejectsDNSTCPRuntime'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperruntime/seccompnotify/types.go internal/helperruntime/seccompnotify/supervisor_linux.go internal/helperruntime/seccompnotify/supervisor_linux_test.go internal/helperruntime/seccompnotify/runtime_integration_linux_test.go internal/helperruntime/runtime.go internal/helperruntime/runtime_test.go
git commit -m "feat: emulate dns udp syscalls through the bridge"
```

### Task 9: Enforce IP-literal policy, DNS correlation, and transparent-mode auditing

**Files:**
- Modify: `manager.go`
- Modify: `policy.go`
- Modify: `policy_test.go`
- Modify: `accesslog.go`
- Modify: `accesslog_test.go`
- Modify: `mitm.go`
- Modify: `mitm_test.go`
- Modify: `integration/network_restriction_test.go`
- Create: `integration/transparent_ip_literal_test.go`

- [ ] **Step 1: Write the failing tests**

Add tests for:

```go
func TestMITMCAIssuesIPLeafCertificate(t *testing.T)
func TestPolicyRejectsHostnameClaimOnUncorrelatedIPConnect(t *testing.T)
func TestTransparentHTTPAllowsDirectIPLiteralWhenCIDRAllowsIt(t *testing.T)
func TestTransparentModeAuditsUnsupportedTCPAsDenied(t *testing.T)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestMITMCAIssuesIPLeafCertificate|TestPolicyRejectsHostnameClaimOnUncorrelatedIPConnect|TestTransparentHTTPAllowsDirectIPLiteralWhenCIDRAllowsIt|TestTransparentModeAuditsUnsupportedTCPAsDenied'`

Expected: FAIL because IP-literal policy enforcement and DNS correlation are incomplete.

- [ ] **Step 3: Write the minimal implementation**

Implement:

- IP SAN leaf issuance in `mitm.go`
- correlation cache updates from successful DNS responses in the manager DNS path
- policy checks that require hostname-to-IP correlation when application authority and original destination differ
- access log event kinds for `dns` and `transparent_tcp_denied`

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestMITMCAIssuesIPLeafCertificate|TestPolicyRejectsHostnameClaimOnUncorrelatedIPConnect|TestTransparentHTTPAllowsDirectIPLiteralWhenCIDRAllowsIt|TestTransparentModeAuditsUnsupportedTCPAsDenied'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manager.go policy.go policy_test.go accesslog.go accesslog_test.go mitm.go mitm_test.go integration/network_restriction_test.go integration/transparent_ip_literal_test.go
git commit -m "feat: enforce ip literal policy in transparent mode"
```

### Task 10: Update end-to-end transparent-mode coverage and documentation

**Files:**
- Modify: `integration/transparent_http_test.go`
- Modify: `integration/transparent_https_test.go`
- Modify: `integration/test_helpers_test.go`
- Modify: `README.md`

- [ ] **Step 1: Write the failing tests**

Add or update end-to-end cases for:

```go
func TestTransparentHTTPWithoutProxyEnvUsesSeccompRedirect(t *testing.T)
func TestTransparentHTTPSOnNonStandardPortUsesSeccompRedirect(t *testing.T)
func TestTransparentUnsupportedTCPFailsClosed(t *testing.T)
```

Also update docs assertions or examples so they describe:

- supported protocols
- supported DNS variants
- non-standard port support
- unsupported raw TCP fallback

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./integration -run 'TestTransparentHTTPWithoutProxyEnvUsesSeccompRedirect|TestTransparentHTTPSOnNonStandardPortUsesSeccompRedirect|TestTransparentUnsupportedTCPFailsClosed'`

Expected: FAIL because the old tests still assume direct transparent listeners rather than supervised socket rewriting.

- [ ] **Step 3: Write the minimal implementation**

Update integration helpers so payload programs are executed inside transparent sandboxes and generate real outbound socket syscalls rather than dialing helper listener addresses directly.

Document in `README.md`:

- transparent mode requires Linux seccomp user notifications
- supported protocols are HTTP/1.1, `h2c`, TLS-backed HTTP/1.1, TLS-backed HTTP/2, and UDP DNS on port `53`
- unsupported traffic fails closed

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./integration -run 'TestTransparentHTTPWithoutProxyEnvUsesSeccompRedirect|TestTransparentHTTPSOnNonStandardPortUsesSeccompRedirect|TestTransparentUnsupportedTCPFailsClosed'`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/transparent_http_test.go integration/transparent_https_test.go integration/test_helpers_test.go README.md
git commit -m "test: cover seccomp transparent mode end to end"
```

### Final Verification

**Files:**
- Modify: `docs/superpowers/plans/2026-03-30-seccomp-unotify-transparent-http-dns.md`

- [ ] **Step 1: Run focused unit and integration suites**

Run:

```bash
go test ./internal/helperproto ./internal/helperruntime/... ./integration/... ./...
```

Expected: PASS on a Linux host with seccomp user notification support and build tools for the launcher.

- [ ] **Step 2: Run the seccomp runtime integration tests explicitly**

Run:

```bash
go test ./internal/helperruntime/seccompnotify -run Runtime -v
```

Expected: PASS on Linux; skip gracefully where prerequisites are absent.

- [ ] **Step 3: Update this plan with any necessary implementation notes**

Record any command adjustments, environment prerequisites, or test skips discovered during implementation.

- [ ] **Step 4: Commit final integration fixes**

```bash
git add .
git commit -m "feat: finish seccomp transparent http dns rewrite"
```
