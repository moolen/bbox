# Phase 2 CONNECT Tunnels Design

**Date:** 2026-03-27

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Extend `github.com/moolen/bbox` with hardened HTTP `CONNECT` tunneling so sandboxed payloads can open proxied TCP tunnels through the host-side policy engine.

This phase keeps the existing trust model intact:

- the sandbox remains unprivileged and network-isolated
- the helper remains the sandbox-local proxy endpoint
- the host-side `ProxyManager` remains the only component allowed to open outbound network connections

## Non-Goals

This phase does not include:

- TLS MITM
- HTTP body inspection for tunneled traffic
- WebSocket-specific proxy semantics
- HTTP/2 interception
- generic arbitrary stream forwarding beyond `CONNECT`
- cross-process shared host proxy daemonization

## High-Level Architecture

The current HTTP request/response flow remains unchanged for normal methods like `GET` and `POST`.

`CONNECT` requests add a second data path:

1. payload process opens a `CONNECT host:port` request against the sandbox-local helper proxy
2. helper sends a `ConnectRequest` over the private bridge
3. host `ProxyManager` validates the target against per-sandbox policy
4. if allowed, the host opens a real outbound TCP connection to `host:port`
5. helper replies `200 Connection Established` to the payload process
6. helper and host exchange framed stream chunks over the bridge until either side closes

The helper never receives host network capability. It only relays bytes between the payload-side proxy socket and the host bridge.

## Public API Direction

The public policy surface extends the existing `NetworkPolicy` type:

```go
type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
	AllowConnectPorts []string
}
```

`AllowConnectPorts` accepts:

- exact ports like `443`
- inclusive ranges like `10000-10100`

Policy behavior:

- `AllowConnect=false` denies all `CONNECT`
- `AllowConnect=true` with no `AllowConnectPorts` still denies all `CONNECT`
- `CONNECT` is only allowed when the hostname passes the existing host regex policy and the destination port matches one configured exact port or range

Invalid port specifications fail fast during policy compilation.

Examples:

```go
NetworkPolicy{
	AllowHostPatterns: []string{`(^|[.])github[.]com$`},
	AllowConnect:      true,
	AllowConnectPorts: []string{"443", "8443", "10000-10100"},
}
```

## Internal Policy Model

`compiledPolicy` gains parsed connect-port rules in addition to the existing method and hostname rules.

Expected internal behavior:

- normal HTTP methods continue using the current method + hostname checks
- `CONNECT` evaluates hostname and port together
- deny-by-default remains the posture once connect support is configured

Validation order for `CONNECT`:

1. parse and normalize `host:port`
2. require method `CONNECT`
3. require `AllowConnect=true`
4. require at least one configured port rule to match
5. apply deny hostname regexes
6. apply allow hostname regexes
7. deny by default if allow host rules are configured and none match

## Bridge Protocol Changes

The existing bridge only supports request/response proxying and exec streaming. `CONNECT` needs explicit tunnel messages.

New protocol concepts:

- `ConnectRequest`
  - sandbox ID is still implied by the bridge owner
  - carries target host and port
- `ConnectResponse`
  - allow or deny decision
  - denial text for user-facing proxy errors
- `TunnelFrame`
  - byte payload for one tunnel direction
- `TunnelClose`
  - half-close or terminal close notification

Tunnel messages must be independent from exec stdout/stderr frames so proxy traffic and command execution stay clearly separated.

## Helper Runtime Changes

The helper runtime will implement `CONNECT` inside its proxy handler:

- validate that the inbound request is a legal proxy `CONNECT`
- hijack the client connection after approval
- send `ConnectRequest` to the host bridge
- on approval, write `200 Connection Established`
- relay payload-side bytes to the host over `TunnelFrame`
- relay host-side bytes back to the payload connection
- propagate EOF and close signals cleanly

Hardening requirements:

- reject malformed `CONNECT` targets early
- bound handshake time with deadlines
- ensure one tunnel cleanup path closes all goroutines and file descriptors
- continue to keep payload processes unable to inherit the bridge file descriptor

## Host Manager Changes

`ProxyManager` will gain a tunnel handling path alongside `handleProxyRequest`.

Responsibilities:

- compile and store tunnel-capable policy
- enforce hostname and port policy for each sandbox
- open outbound TCP connections only after approval
- apply dial timeout and idle timeout defaults
- stream bytes between outbound TCP connection and helper bridge
- surface structured denial text for proxy clients

The host manager remains the trust anchor for network egress decisions.

## Error Handling

Denied tunnels should surface as normal proxy failures to clients:

- policy denials should map to HTTP `403`
- malformed `CONNECT` requests should map to HTTP `400`
- host dial failures should map to HTTP `502`
- timeout-driven failures should map to HTTP `504` when possible

User-facing denial bodies should include a short policy reason, similar to the current HTTP request denial path.

## Security Posture

This phase is intentionally narrow:

- no decrypted visibility into tunneled TLS
- no content-based filtering once a tunnel is approved
- no tunnel approval without explicit port allow rules

Security properties retained:

- sandbox payloads still cannot open host network sockets directly
- policy is still enforced on the host side only
- the helper remains a constrained relay, not a dialer

Known limitation preserved:

- approving a tunnel delegates all post-connect application-layer policy to the remote protocol endpoint, because Phase 2 does not inspect encrypted traffic

## Testing Strategy

Add focused coverage at three levels.

### Unit Tests

- parse valid and invalid connect port specs
- verify exact-port and range matching
- verify `AllowConnect=true` plus empty port rules still denies
- verify hostname regex and port rules compose correctly

### Runtime/Protocol Tests

- bridge round-trip for `ConnectRequest` and `ConnectResponse`
- tunnel frame handling and shutdown behavior

### Integration Test

Add a real end-to-end test that:

- starts a local TCP echo server on the host
- creates two sandboxes with different `CONNECT` policies
- uses a sandboxed client through the helper proxy
- verifies one tunnel succeeds and one is denied

The integration test should stay self-contained and avoid relying on the public internet.

## Demo Impact

The existing demo may gain an optional `CONNECT` example after the library path is implemented and verified, but that is secondary to the library and test coverage.

## Rollout Plan

This phase should be implemented incrementally:

1. extend policy parsing and validation for `AllowConnectPorts`
2. extend helper protocol with explicit connect/tunnel messages
3. add helper runtime and host manager tunnel handling
4. add integration coverage for allowed and denied tunnels
5. optionally extend the demo and README

Do not fold MITM, WebSocket support, or advanced HTTP/2 behavior into this phase.
