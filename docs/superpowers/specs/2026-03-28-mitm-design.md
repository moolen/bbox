# Phase 3 TLS MITM Design

**Date:** 2026-03-28

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Extend `github.com/moolen/bbox` with manager-wide TLS MITM so sandboxed clients can send HTTPS traffic through the existing host-side policy engine and have policy enforced on decrypted request metadata and bounded request bodies.

This phase keeps the existing trust model intact:

- the sandbox remains unprivileged and network-isolated
- the helper remains the sandbox-local proxy endpoint
- the host-side `ProxyManager` remains the only component allowed to open outbound network connections
- MITM is explicitly opt-in and shared across all sandboxes created by one `ProxyManager`

## Non-Goals

This phase does not include:

- persistent or user-supplied CA management
- response-body inspection or mutation
- arbitrary request or response rewriting
- silent fallback from MITM to raw tunnel mode on TLS or protocol errors
- WebSocket-specific interception semantics
- cross-process shared proxy daemonization

## High-Level Architecture

The recommended architecture is full MITM in the sandbox-local helper, with the host manager remaining the policy and egress authority.

### Plain HTTP

Normal HTTP methods continue using the existing request/response bridge path.

### CONNECT in Tunnel-Only Mode

When MITM is disabled, `CONNECT` continues using the existing raw tunnel path unchanged.

### CONNECT in MITM Mode

When MITM is enabled:

1. the sandboxed client sends `CONNECT host:port` to the sandbox-local helper proxy
2. the helper asks the host manager to authorize the target host and port
3. if allowed, the helper replies `200 Connection Established`
4. the helper terminates TLS locally using a dynamically minted leaf certificate signed by the manager CA
5. the helper parses decrypted HTTP/1.1 and HTTP/2 requests from the client connection
6. the helper forwards normalized request envelopes over the private bridge
7. the host manager evaluates policy on decrypted request data and performs the real upstream HTTPS request
8. the host manager returns the response to the helper
9. the helper serializes the response back to the client over the intercepted TLS session

This keeps all outbound dialing and final policy decisions on the host while allowing the helper to act as the sandbox-local trust anchor and protocol terminator.

## Public API Direction

MITM is configured once per `ProxyManager`.

```go
type ProxyOptions struct {
	ListenAddr    string
	NetworkPolicy NetworkPolicy
	MITM          MITMOptions
}

type MITMOptions struct {
	Enabled             bool
	MaxRequestBodyBytes int64
}
```

Notes:

- MITM remains disabled by default
- CA generation is ephemeral per `ProxyManager`
- request-body inspection is bounded by `MaxRequestBodyBytes`
- TLS version and HTTP/2 rollout details should default internally in this phase rather than creating a wide configuration surface prematurely

Read-only manager accessor:

```go
func (m *ProxyManager) CACertPEM() []byte
```

This is for debugging trust injection and external inspection only. It does not imply persistent CA lifecycle management.

## Policy Model

`NetworkPolicy` remains the central per-sandbox policy object. Existing host and method checks continue to apply to decrypted HTTPS requests.

Phase 3 extends it with request-oriented HTTPS inspection fields:

```go
type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
	AllowConnectPorts []string

	AllowPathPatterns []string
	DenyPathPatterns  []string

	AllowHeaderPatterns map[string][]string
	DenyHeaderPatterns  map[string][]string

	AllowBodyPatterns []string
	DenyBodyPatterns  []string
}
```

Policy evaluation order for MITM traffic:

1. validate the CONNECT target host and port
2. complete TLS interception
3. parse the decrypted request
4. apply method allowlist
5. apply hostname deny/allow rules
6. apply path deny/allow rules
7. apply header deny/allow rules
8. read and bound the request body
9. apply body deny/allow rules
10. deny by default whenever an allowlist category is configured and nothing matches

Body inspection behavior:

- inspect only the bounded prefix of the request body
- reject requests that exceed `MaxRequestBodyBytes`
- do not stream unbounded request bodies through policy evaluation

Response inspection remains out of scope in this phase.

## CA Lifecycle and Trust Injection

MITM mode requires bbox to generate and inject a CA automatically.

### CA Generation

- generate one ephemeral CA keypair and certificate when `NewProxyManager` is called with `MITM.Enabled=true`
- keep CA private key and cert in memory for the lifetime of the manager
- destroy them when `ProxyManager.Close()` completes

### Leaf Issuance

- mint leaf certificates on demand per hostname
- cache leaf certificates in memory for reuse across requests and sandboxes owned by the same manager
- use the CONNECT target host as the baseline certificate identity
- prefer SNI for validation consistency, but reject mismatches rather than papering over them

### Trust Injection

During sandbox staging, write the generated CA into the staged root so common Linux clients can trust the helper-issued leaf certificates.

First-phase target:

- stage CA material into well-known distro trust locations that are sufficient for the tested clients
- ensure staged tools like `curl` can validate intercepted TLS sessions without custom user configuration

The library does not attempt to mutate host trust stores and does not promise universal trust integration for every distribution in Phase 3. It only guarantees the documented/tested sandbox trust setup.

## Bridge Protocol Changes

The existing bridge protocol is not rich enough for decrypted HTTPS request forwarding. Phase 3 needs a protocol version bump and richer request/response envelopes.

Expected additions:

- MITM request envelope
  - scheme
  - authority / host
  - path and raw query
  - method
  - headers
  - bounded request body
  - protocol version metadata
- MITM response envelope
  - status code
  - headers
  - response body payload for the current non-streaming phase
- MITM error envelope or structured error fields for deterministic proxy failures

Raw tunnel envelopes remain for non-MITM `CONNECT`.

Protocol expectations:

- bump `helperproto.ProtocolVersion`
- reject helper/manager version mismatches explicitly
- keep the wire format self-describing enough to distinguish plain HTTP proxying, MITM request forwarding, and raw tunnel traffic

## Helper Runtime Changes

The helper becomes the local TLS terminator in MITM mode.

Responsibilities:

- authorize `CONNECT` target with the host manager before interception
- write `200 Connection Established`
- complete a TLS server handshake using a manager-signed leaf certificate
- negotiate HTTP/1.1 or HTTP/2 with the client
- parse decrypted requests
- forward normalized requests to the host bridge
- serialize host responses back to the client protocol

### HTTP/1.1

- one request at a time per connection is acceptable initially
- request bodies are buffered only up to `MaxRequestBodyBytes`
- helper returns deterministic HTTP errors for policy or size failures

### HTTP/2

- helper must support multiple concurrent streams on one intercepted TLS connection
- helper must preserve independent stream lifecycle, headers, bodies, and response ordering per stream
- helper must not collapse HTTP/2 testing into a single-stream smoke test

Implementation direction:

- use Go's TLS stack and HTTP/2 server support in the helper
- keep MITM request normalization narrow and request-oriented
- avoid bespoke frame parsing if standard library and well-scoped HTTP/2 support are sufficient

## Host Manager Changes

`ProxyManager` gains HTTPS-aware request handling alongside the existing plain HTTP and raw CONNECT paths.

Responsibilities:

- create and own the ephemeral CA
- enforce per-sandbox policy on decrypted request metadata and bounded bodies
- construct outbound HTTPS requests using host-side transports
- preserve the single host-side egress authority
- return deterministic policy failures and request-size failures to the helper

Outbound behavior:

- upstream HTTPS uses normal host-side TLS validation to origin servers
- request bodies are forwarded only after policy passes
- h2 support upstream should come from Go transport defaults where possible rather than custom frame handling

## Error Handling

Failure modes should be explicit and non-ambiguous.

- CA generation failure: `NewProxyManager` fails fast
- trust injection failure: `NewSandbox` fails and cleans up
- denied CONNECT target: return proxy denial before TLS handshake
- TLS handshake failure: close intercepted connection and record context for logs
- SNI / certificate identity mismatch: fail the intercepted connection, do not downgrade to tunnel mode
- request body larger than `MaxRequestBodyBytes`: return deterministic proxy failure
- HTTP/2 negotiation or stream handling failure: fail the affected request or connection explicitly, do not silently downgrade
- helper/manager protocol version mismatch: fail startup or request processing clearly

Silent fallback from MITM to tunnel mode is forbidden in this phase because it would create policy gaps.

## Security Posture

Phase 3 increases capability and risk relative to tunnel-only CONNECT.

Security properties retained:

- payload processes still cannot open host network sockets directly
- policy is still enforced on the host side
- one manager remains the trust anchor for all sandbox egress decisions
- CA lifecycle remains process-local and ephemeral

New security assumptions:

- sandboxed clients trust the injected bbox CA
- helper compromise would expose decrypted in-sandbox HTTPS traffic for that manager
- policy correctness now depends on request normalization for both HTTP/1.1 and HTTP/2

Guardrails:

- MITM stays opt-in
- no persistent CA in Phase 3
- no downgrade fallback
- bounded body inspection only

## Testing Strategy

Add coverage at four levels.

### Unit Tests

- CA generation and PEM export
- leaf issuance and SAN matching
- policy parsing for path/header/body rules
- bounded body inspection and overflow rejection
- protocol versioning and envelope encode/decode

### Staging Tests

- CA files are written into the staged root in the expected trust locations
- staging remains deterministic across multiple sandboxes under one manager

### Helper/Runtime Tests

- MITM CONNECT handshake succeeds for an allowed target
- HTTP/1.1 decrypted request forwarding works end to end through helper and manager
- HTTP/2 decrypted forwarding works for multiple concurrent streams over one intercepted connection
- stream failures remain isolated and do not corrupt unrelated streams on the same h2 session
- request-body size enforcement returns deterministic failures

### Integration Tests

Add self-contained HTTPS integration tests that avoid relying on the public internet:

- sandboxed `curl` trusts the injected CA and completes an allowed HTTPS request
- denied HTTPS requests by path, header, and body are rejected with explicit proxy failures
- multiple sandboxes share one manager CA successfully
- tunnel-only mode still works unchanged when MITM is disabled

Add a small HTTP/2 concurrency/load test:

- use one intercepted client connection
- open multiple concurrent h2 streams against a local HTTPS origin
- verify per-stream responses are correct and not cross-wired
- send enough concurrent requests to exercise stream multiplexing rather than single-request success only

This test is not intended as a benchmark. Its purpose is to prove correctness under concurrent streams on one h2 session and catch basic head-of-line, stream-mapping, and response-routing bugs.

## Documentation Impact

Update:

- README feature overview
- public GoDoc for MITM options and CA accessors
- examples showing MITM-enabled manager creation

Documentation must clearly state:

- MITM is opt-in
- bbox injects an ephemeral CA into sandboxes
- CONNECT tunnel-only mode remains available
- request inspection is limited to request metadata plus bounded request bodies in this phase

## Rollout Plan

Implement incrementally:

1. define MITM public API and CA lifecycle
2. extend staging for CA trust injection
3. extend helper protocol for intercepted request/response forwarding
4. add helper-side TLS termination and HTTP/1.1 interception
5. add host-side decrypted request policy and outbound HTTPS forwarding
6. add helper-side HTTP/2 interception with multi-stream correctness coverage
7. add integration tests for allowed, denied, and multi-sandbox MITM flows
8. update docs and examples

Do not fold response mutation, persistent CA management, or WebSocket-specific interception into this phase.
