# Seccomp-Unotify Transparent HTTP+DNS Design

**Date:** 2026-03-30

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Replace the current listener-bound transparent traffic approach with a seccomp-unotify based transport rewrite that:

- transparently supports HTTP/1.1, cleartext HTTP/2 (`h2c`), and TLS-backed HTTP/1.1 or HTTP/2 on standard and non-standard ports
- transparently supports DNS over UDP port `53`
- forwards HTTP(S) traffic through the existing host-side proxy and MITM pipeline
- forwards DNS queries to the host resolvers configured in the host `/etc/resolv.conf`
- keeps policy enforcement authoritative on the host side
- fails closed for non-HTTP TCP protocols and unsupported DNS variants

## Non-Goals

This phase does not include:

- generic raw TCP tunneling as a transparent fallback
- support for non-HTTP application protocols over TCP
- DNS over TCP
- QUIC or HTTP/3
- privileged packet interception through iptables, nftables, TPROXY, or eBPF redirection
- host-network execution for sandboxed payload processes
- silent downgrade from unsupported traffic to passthrough

## User-Facing Behavior

Transparent mode remains explicitly selected per sandbox through `SandboxOptions.TrafficMode`.

Transparent mode behavior:

- payload processes do not need proxy environment variables
- outbound HTTP on any TCP port is supported when the stream is valid HTTP/1.x or `h2c`
- outbound HTTPS on any TCP port is supported when the stream is valid TLS carrying HTTP/1.1 or HTTP/2
- outbound DNS works for UDP port `53`, including connected and unconnected socket flows
- outbound non-HTTP TCP is denied
- outbound DNS over TCP is denied

Proxy mode remains unchanged.

## High-Level Architecture

The long-lived sandbox helper remains the only in-sandbox traffic ingress point. The host-side `ProxyManager` remains the only component that performs host DNS resolution, upstream dialing, policy evaluation, access logging, and outbound network I/O.

Transparent mode is reworked into four parts:

1. a small C launcher installed inside the sandbox that creates the seccomp unotify listener before `execve()` into the real payload program
2. a helper-side seccomp supervisor that receives and handles seccomp notifications for the launched payload process
3. a single sandbox-local transparent TCP ingress listener that accepts all rewritten outbound TCP streams
4. a helper-to-manager DNS bridge path that forwards raw UDP DNS queries to the host-side DNS service

## Execution Model

There are still two process classes inside a sandbox:

- one long-lived helper process started by bubblewrap
- one or more short-lived payload processes launched by the helper on demand

Only payload processes are supervised by seccomp-unotify transparent networking. The long-lived helper is not placed behind the same stream-rewrite path because it must own the local ingress listeners and bridge.

## C Launcher

The launcher is a small C binary shipped beside the sandbox helper binary.

Responsibilities:

- create a seccomp filter using `SECCOMP_FILTER_FLAG_NEW_LISTENER`
- return the resulting notify FD to the helper over a Unix domain socketpair
- scrub its control environment before `execve()`
- `execve()` into the real target program without spawning an extra long-lived shim process

The launcher design should closely follow the proven implementation in `~/dev/patchpilot-v2/internal/sandbox/cmd/patchpilot-seccomp-launcher/main.c`, adapted to this repository layout and naming.

The helper exec path wraps payload commands through this launcher only when `TrafficModeTransparent` is active.

## Seccomp Supervision

The helper creates a per-exec supervisor for transparent mode. The supervisor owns:

- the seccomp notify FD
- a child-FD to helper-FD registry
- destination metadata for redirected sockets
- DNS socket state needed to emulate connected and unconnected UDP behavior

The supervisor intercepts at least these syscalls:

- `socket`
- `connect`
- `close`
- `dup`
- `dup2`
- `dup3`
- `fcntl`
- `sendto`
- `sendmsg`
- `sendmmsg`
- `recvfrom`
- `recvmsg`
- `recvmmsg`
- `getsockname`
- `getpeername`

The supervisor may additionally intercept `bind` when needed to preserve fail-closed behavior for managed DNS sockets.

The seccomp response policy is:

- managed HTTP/DNS sockets are fully emulated or redirected by the supervisor
- unsupported use of managed sockets returns a deterministic syscall error
- unrelated syscalls continue normally

## Transparent TCP Design

### Single Ingress Listener

All outbound `AF_INET` and `AF_INET6` `SOCK_STREAM` sockets created by the payload are treated as potentially managed sockets.

On intercepted `connect()`:

1. the supervisor captures the original destination IP/port
2. the child socket is backed by a helper-owned socket
3. the helper-owned socket is connected to one sandbox-local transparent TCP ingress listener
4. the original destination metadata is recorded against the resulting local connection identity

There is no special routing by destination port. Port `80` and `443` are no longer privileged routing keys.

### Protocol Classification

The ingress listener peeks the first bytes of each accepted connection and classifies traffic as:

- TLS ClientHello
- HTTP/1.x plaintext
- cleartext HTTP/2 prior knowledge (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
- HTTP/1.1 with `Upgrade: h2c`

Everything else is denied and audited as unsupported transparent TCP.

Classification rules:

- TLS traffic is detected from the TLS record header and parsed far enough to obtain SNI and ALPN when present
- HTTP/1.x plaintext is parsed as an origin-form or absolute-form request and normalized into the existing proxy request path
- `h2c` prior knowledge is handled by speaking HTTP/2 server-side directly on the accepted connection
- `Upgrade: h2c` starts as HTTP/1.1 and switches the same connection into HTTP/2 after a successful upgrade

### HTTP Routing

After classification:

- plaintext HTTP/1.x and `h2c` requests are forwarded to the existing host-side proxy request path
- TLS-backed HTTP/1.1 and HTTP/2 requests are forwarded to the existing host-side MITM request path

Transparent mode does not preserve opaque tunnels. It always terminates supported HTTP protocols in the helper and forwards normalized requests over the bridge for host-side policy evaluation.

### HTTP/2 Requirements

Transparent mode must support HTTP/2 with multiple concurrent streams on a single client connection in both forms:

- cleartext `h2c`
- TLS-backed `h2`

The helper-side transparent ingress implementation must keep per-stream request and response handling isolated while reusing the existing host-side policy engine for each logical request.

## DNS Design

### Staged Resolver Configuration

The staged sandbox `/etc/resolv.conf` mirrors the host nameserver configuration from the host `/etc/resolv.conf`.

The file should be narrowed to deterministic content:

- keep `nameserver` entries from the host configuration
- omit search domains and options not needed for basic resolution

This preserves normal libc resolver behavior while making actual network delivery controllable through seccomp supervision.

### Managed DNS Sockets

Only UDP port `53` is supported.

The supervisor manages both connected and unconnected UDP DNS usage patterns, including:

- `connect()` then `send`/`recv`
- `sendto`/`recvfrom`
- `sendmsg`/`recvmsg`
- `sendmmsg`/`recvmmsg`

When the destination is UDP port `53`, the helper must not let the packet leave the sandbox namespace directly. Instead:

1. the raw DNS payload is captured by the supervisor
2. the payload is sent over the bridge to a host-side manager DNS service
3. the manager DNS service forwards the query over UDP to the host resolvers from the host `/etc/resolv.conf`
4. the raw response payload is returned to the supervised process through the matching emulated receive syscall

Unsupported DNS behavior:

- DNS over TCP is denied
- UDP traffic to non-`53` ports is not treated as DNS

The host-side DNS service should follow the implementation shape already proven in `~/dev/patchpilot-v2/internal/sandbox/manager_dns_service.go`.

## Policy Model

The host-side policy engine remains authoritative. Transparent mode must not invent a second policy language inside the helper.

### HTTP Policy

For each logical HTTP request, policy continues to apply to:

- method
- hostname or IP literal authority
- port
- path
- headers
- request body

The meaning should stay aligned with existing explicit proxy and MITM modes.

### IP Literal Policy

Direct IP literal destinations are supported only when policy can be enforced deterministically.

Requirements:

- the compiled policy model must be extended so it can authorize IP literals and CIDR ranges in addition to hostnames
- access events must record whether the request was authorized by hostname policy, IP policy, or both

For plaintext HTTP to an IP literal, the authority is the original destination IP unless a stricter consistency rule applies.

For TLS to an IP literal:

- the original destination IP is authoritative
- SNI may be empty
- when a certificate is minted for interception, the leaf certificate must support IP SANs

### Hostname-to-IP Consistency

If a connection is made to an IP literal but the application-level authority claims a hostname, the request is allowed only when the hostname can be correlated to that IP from DNS answers previously observed for the same sandbox within a bounded freshness window.

If that correlation is unavailable, the request is denied. This prevents a process from connecting to an arbitrary IP while presenting an unrelated hostname for policy bypass.

## Certificate And Trust Model

Transparent TLS interception continues to use the manager-wide ephemeral CA.

Additional requirements for this rewrite:

- leaf issuance must support both DNS SANs and IP SANs
- transparent TLS must work on non-standard ports
- clients negotiating `h2` over ALPN must continue to function under interception

If trust material or leaf issuance is unavailable, transparent TLS fails closed.

## Bubblewrap And Sandbox Wiring

Transparent mode still uses a network namespace isolated from the host.

Bubblewrap startup remains responsible for:

- staging the helper and launcher binaries into the sandbox root
- wiring the private bridge FD between manager and helper
- wiring any existing sandbox seccomp profile used for helper hardening

The payload-process seccomp-unotify filter is separate from the bubblewrap helper seccomp profile. The two mechanisms must not be conflated.

## Error Handling

Transparent mode must fail fast and fail closed.

Sandbox startup failures:

- helper cannot bind the transparent TCP ingress listener
- helper cannot initialize the host-backed DNS bridge path
- launcher cannot be found or executed
- launcher cannot install the seccomp notify filter
- helper cannot receive or serve the seccomp notify FD

Request-time failures:

- TCP stream is not recognizable as supported HTTP
- TLS handshake lacks the information needed to enforce policy
- DNS syscall pattern is unsupported
- upstream proxy/MITM or DNS round trip fails
- policy denies the destination or request content

For denied traffic:

- close the client connection cleanly when possible
- return deterministic syscall errors for supervised DNS operations
- record the denial in access/audit logs with the original destination metadata

## Auditing

Access logging must preserve the original outbound intent rather than the rewritten local listener addresses.

Audit records should include:

- sandbox ID
- traffic kind (`http_request`, `mitm_request`, `dns_request`, `transparent_tcp_denied`)
- original destination host or IP
- original destination port
- policy decision
- protocol form (`http1`, `h2c`, `tls-http1`, `tls-h2`, `dns-udp`)
- denial reason when applicable

## Testing Strategy

The rewrite is complete only when all of these are covered by automated tests.

### Unit Coverage

- seccomp notification decoding and socket-state tracking
- TCP protocol classification
- DNS syscall emulation for connected and unconnected UDP
- IP-literal policy checks and hostname-to-IP correlation
- IP SAN certificate issuance

### Integration Coverage

- plaintext HTTP/1.1 on standard and non-standard ports
- plaintext HTTP/2 prior knowledge on non-standard ports
- HTTP/1.1 upgrade to `h2c`
- TLS-backed HTTP/1.1 on standard and non-standard ports
- TLS-backed HTTP/2 with multiple concurrent streams on one connection
- DNS via connected UDP
- DNS via `sendto`/`recvfrom`
- DNS via `sendmsg`/`recvmsg`
- direct IP-literal HTTP
- direct IP-literal HTTPS
- denial of unsupported TCP protocols
- denial of DNS over TCP

### Regression Guardrails

Existing proxy-mode tests must continue to pass unchanged. Transparent mode tests from the current listener-based design should be updated or replaced so they validate the seccomp-supervised path rather than direct low-port listeners.

## Implementation Constraints

- reuse the existing host-side proxy, MITM, tunnel, and audit infrastructure where possible
- copy proven seccomp-unotify mechanics from `~/dev/patchpilot-v2/internal/sandbox/internal/helperruntime/seccompnotify` and adapt them to the current repository structure instead of re-inventing them
- keep transparent mode fail-closed
- do not keep the raw TCP fallback from the divergent tree because it conflicts with the requirement that only HTTP+DNS are supported and policed
