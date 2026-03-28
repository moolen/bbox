# Transparent Traffic Mode Design

**Date:** 2026-03-28

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Extend `github.com/moolen/bbox` so sandbox users can choose between two supported HTTP(S) ingress models:

- explicit proxy mode using `HTTP_PROXY` / `HTTPS_PROXY`
- transparent mode for ordinary hostname-based HTTP and HTTPS traffic without proxy env vars

This change must preserve the existing trust model:

- the sandbox remains unprivileged and network-isolated
- the sandbox-local helper remains the only in-sandbox traffic ingress point
- the host-side `ProxyManager` remains the only component allowed to make outbound network connections
- host-side policy evaluation remains authoritative

## Non-Goals

This phase does not include:

- arbitrary TCP interception beyond HTTP and HTTPS
- interception of IP-literal destinations
- interception of non-default ports such as `:8080` or `:8443`
- HTTP/3 or QUIC interception
- fallback to privileged packet redirection such as iptables, nftables, or TPROXY
- transparent interception for applications that bypass the sandbox resolver
- silent downgrade from TLS interception failure to tunnel mode

## User-Facing Requirements

The library must support two selectable modes per sandbox:

1. `proxy` mode
2. `transparent` mode

User expectations:

- existing proxy-mode callers keep working unchanged
- users explicitly choose transparent mode through sandbox configuration
- transparent mode requires no proxy env vars inside payload processes
- transparent mode limitations are documented as part of the public behavior

## Public API Direction

Add an explicit traffic mode to `SandboxOptions`:

```go
type TrafficMode string

const (
	TrafficModeProxy       TrafficMode = "proxy"
	TrafficModeTransparent TrafficMode = "transparent"
)

type SandboxOptions struct {
	Name        string
	Binaries    []string
	Mounts      []Mount
	Env         []string
	Policy      NetworkPolicy
	WorkDir     string
	TrafficMode TrafficMode
}
```

Behavior:

- `TrafficModeProxy` is the default when the field is empty
- invalid mode values fail sandbox creation explicitly
- `TrafficModeTransparent` requires manager-wide `MITM.Enabled=true`; sandbox creation fails explicitly otherwise
- `ProxyManager` configuration remains manager-wide
- MITM remains manager-wide and applies according to the selected traffic mode

## High-Level Architecture

The recommended design keeps one host-side policy and egress engine while adding a second sandbox-local ingress model.

### Proxy Mode

Proxy mode remains the current behavior:

1. sandbox runs receive `HTTP_PROXY` and `HTTPS_PROXY`
2. payload sends plain HTTP or proxy `CONNECT` to the helper proxy listener
3. helper forwards normalized requests over the private bridge
4. host `ProxyManager` evaluates policy and performs outbound requests

### Transparent Mode

Transparent mode replaces proxy env configuration with sandbox-local DNS and well-known local listeners:

1. payload resolves `example.com`
2. sandbox-local DNS replies with loopback
3. payload opens `example.com:80` or `example.com:443`
4. connection lands on the helper listener inside the sandbox namespace
5. helper reconstructs the logical destination host from HTTP `Host` or TLS SNI
6. helper forwards normalized request data over the private bridge
7. host `ProxyManager` evaluates policy and performs the real outbound request
8. helper returns the response to the payload process

The helper still never receives direct host network capability. It remains a protocol terminator and bridge client only.

## Runtime Layout

There is still one long-lived helper process per sandbox.

The helper itself owns all mode-specific listeners. Transparent mode does not introduce a second independently supervised DNS daemon.

### Proxy Mode Listeners

- configured explicit proxy listener, today defaulting to `127.0.0.1:31111`

### Transparent Mode Listeners

- DNS listeners on `127.0.0.1:53/udp` and `127.0.0.1:53/tcp`
- HTTP listener on `127.0.0.1:80`
- HTTPS MITM listener on `127.0.0.1:443`

The helper reports readiness only after all listeners required for the selected mode are successfully bound and serving.

### Low-Port Binding Assumption

Transparent mode relies on the helper being able to bind privileged ports inside the sandbox network namespace.

Implementation assumption:

- the helper runs as namespace-root inside the unprivileged user namespace created for the sandbox
- low-port binding is attempted directly by the helper inside that namespace
- bbox does not rely on host-wide packet redirection, host firewall changes, or host-wide sysctl mutations to make this work

If the target environment does not allow binding `:53`, `:80`, or `:443` inside the sandbox namespace, transparent mode must fail sandbox startup explicitly.

## DNS And Sandbox Setup

Transparent mode depends on a sandbox-local DNS service.

Sandbox staging changes:

- write `/etc/resolv.conf` in the staged root to point to `127.0.0.1`
- keep `/etc/hosts` for `localhost` only

The DNS responder lives inside the helper process rather than as a second long-lived daemon.

Transparent DNS behavior:

- serve both UDP and TCP DNS on `127.0.0.1:53`
- for ordinary hostname `A` lookups, reply with `127.0.0.1`
- for ordinary hostname `AAAA` lookups, return `NOERROR` with no answers so clients do not pivot to `::1`
- do not resolve real upstream IPs inside the sandbox
- the host manager resolves upstream destinations later using the logical target hostname
- return `REFUSED` for unsupported query types
- do not advertise recursion or attempt to behave like a recursive resolver
- write `/etc/resolv.conf` without search domains so resolution remains narrow and deterministic

The DNS responder should follow narrow, deterministic rules rather than trying to emulate a full recursive resolver.

## Helper Responsibilities

The helper behavior diverges by traffic mode.

### Proxy Mode

Proxy mode remains unchanged:

- ordinary HTTP requests use the existing request/response bridge path
- HTTPS uses proxy `CONNECT`
- when MITM is enabled, the helper intercepts decrypted traffic after `CONNECT`

### Transparent HTTP On `:80`

The helper accepts ordinary origin-form HTTP requests:

- parse request target and `Host`
- reject requests without a usable destination host
- normalize the request into the same shape used for plain HTTP host-side forwarding
- return the host response over the client connection

Transparent HTTP does not use proxy-form absolute URLs as a requirement. It should handle ordinary client requests aimed at origin servers.

### Transparent HTTPS On `:443`

The helper acts as the TLS terminator directly:

- accept the incoming TCP connection
- extract the destination host from SNI
- mint or retrieve a manager-signed leaf certificate for that host
- complete a TLS server handshake
- parse decrypted HTTP/1.1 and HTTP/2 requests
- normalize them into the existing MITM request path
- return host responses over the intercepted TLS session

There is no internal fake `CONNECT` step in transparent mode. The ingress protocol is direct TLS, not explicit proxy tunneling.

Transparent HTTPS is only available when manager-wide MITM is enabled. The mode does not provide an SNI-based raw tunnel fallback.

## Host Manager And Policy Model

The host-side `ProxyManager` remains responsible for:

- sandbox registration
- policy lookup
- final allow/deny decisions
- upstream DNS resolution
- outbound dialing
- access/audit logging

Policy meaning should remain as consistent as possible across both traffic modes.

### Shared Request Policy

For decrypted request traffic in either mode:

- method allowlists behave the same
- hostname allow/deny behaves the same
- path, header, and body inspection behave the same
- upstream execution and response handling behave the same

### `CONNECT` Policy Scope

`AllowConnect` and `AllowConnectPorts` remain specific to explicit proxy `CONNECT` requests.

That means:

- proxy mode tunnel-only HTTPS still depends on `AllowConnect`
- proxy mode MITM-over-`CONNECT` still depends on `AllowConnect`
- transparent HTTPS on `:443` does not depend on `AllowConnect`, because there is no proxy tunnel request to authorize

Transparent HTTPS instead performs:

1. destination host validation from SNI or equivalent authority data
2. decrypted request policy evaluation on the resulting HTTP request

This keeps transparent mode from inventing fake proxy semantics purely to reuse policy checks.

## CA Lifecycle And Trust

Transparent HTTPS uses the same manager-wide ephemeral CA model as explicit MITM mode:

- when MITM is enabled for a manager, generate one ephemeral CA
- stage trust material into the sandbox root for supported clients
- mint leaf certificates per hostname on demand
- cache leaf certificates in memory per manager

Transparent HTTPS must fail closed when trust setup or leaf issuance is unavailable.

## Error Handling

Transparent mode must fail fast and explicitly.

Sandbox startup failures:

- cannot bind `:53`, `:80`, or `:443`
- cannot stage a usable `resolv.conf`
- MITM is required but trust material cannot be staged
- helper readiness completes with one required listener missing

Request-time failures:

- HTTP request without a usable `Host` -> HTTP `400`
- HTTPS connection without usable SNI / authority -> terminate connection
- TLS handshake failure -> fail the intercepted connection and do not downgrade
- unsupported DNS queries -> deterministic `REFUSED`
- attempts to unsupported ports or IP literals -> documented miss, not partial interception

## Transparent Mode Limitations

Transparent mode is intentionally bounded in this phase. These are productized limitations, not experimental disclaimers.

Supported:

- hostname-based HTTP on port `80`
- hostname-based HTTPS on port `443`
- ordinary HTTP/1.1 client behavior
- HTTPS MITM for HTTP/1.1 and HTTP/2 over TLS where the client trusts the staged CA and supplies usable SNI
- IPv4 loopback interception only

Not supported:

- IP-literal destinations such as `https://1.1.1.1/`
- non-default ports such as `:8080`, `:8443`, or arbitrary custom ports
- IPv6 transparent interception via `::1`
- QUIC / HTTP/3
- arbitrary non-HTTP TCP protocols
- applications that use a DNS path outside the staged sandbox resolver
- clients that omit or obscure host identity such that the helper cannot recover the logical destination safely

These limitations must be documented in public GoDoc and examples so callers choose the correct mode.

## Observability

Existing audit and logging should become mode-aware without creating separate semantics for similar traffic.

Recommended additions:

- include traffic mode in access events
- log transparent HTTP attempts distinctly from proxy HTTP attempts only when the distinction matters operationally
- keep destination host, method, path, allow/deny result, and error semantics consistent across modes

The point of mode awareness is troubleshooting, not a second incompatible event model.

## Testing Strategy

This feature should land with both unit and integration coverage.

### Unit Tests

- `TrafficMode` parsing, validation, and defaulting
- DNS responder rules for `A`, `AAAA`, and unsupported queries over UDP and TCP
- transparent HTTP host extraction
- transparent HTTPS SNI extraction
- helper readiness behavior when one transparent listener fails
- policy behavior differences between proxy and transparent ingress

### Integration Tests

- existing proxy-mode HTTP flow still passes unchanged
- existing proxy-mode HTTPS MITM flow still passes unchanged
- transparent HTTP request to a hostname succeeds without proxy env vars
- transparent HTTPS request to a hostname succeeds without proxy env vars
- transparent HTTP deny-by-host returns deterministic failure
- transparent HTTPS deny-by-path/header/body returns deterministic failure after decryption
- IP-literal requests fail as documented
- non-default port requests fail as documented
- multiple sandboxes can run concurrently with different modes and different policies

## Implementation Notes

The implementation should prefer reuse of existing normalized request paths rather than creating parallel policy engines.

Recommended structure:

- extend sandbox/public types with `TrafficMode`
- extend staging to write transparent-mode DNS config
- add helper config and readiness for mode-specific listeners
- add a small DNS responder component
- add transparent HTTP ingress in the helper
- add transparent HTTPS MITM ingress in the helper
- reuse the current host-side plain HTTP and MITM request handling
- update logging/audit metadata with traffic mode

This feature should be planned and implemented as one coherent traffic-mode slice rather than mixed ad hoc into unrelated networking work.
