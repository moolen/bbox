# Remove Transparent DNS Listener Design

**Date:** 2026-03-30

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Remove the in-sandbox transparent DNS server from `bbox` while preserving transparent HTTP(S) support and keeping DNS available only through the supervised seccomp-mediated path.

## Motivation

Transparent mode currently still starts a helper-owned DNS listener and fails startup if that listener cannot bind low port `53`.

That behavior is no longer aligned with the current transport architecture:

- staged transparent-mode `resolv.conf` now carries host nameserver entries instead of pointing to `127.0.0.1`
- payload DNS is already intercepted through the supervised socket path and forwarded to the host manager with `DNSRoundTrip`
- the remaining DNS listener requirement mainly preserves a legacy startup dependency rather than a necessary runtime path

The result is avoidable startup failure in environments where low-port binding is restricted even though supervised DNS forwarding is otherwise available.

## Non-Goals

This change does not include:

- adding a fallback in-sandbox DNS listener on a different port
- supporting DNS that bypasses the supervised seccomp path
- changing the host-side DNS resolution authority
- changing transparent HTTP or transparent TLS ingress behavior
- widening transparent mode to arbitrary UDP traffic

## User-Facing Behavior

After this change:

- transparent mode no longer binds `127.0.0.1:53`
- transparent sandbox startup no longer fails because a DNS listener cannot bind
- DNS from payload processes works only when it flows through the supervised seccomp DNS path
- payload DNS that bypasses the supervised path fails closed

This is an intentional narrowing of supported behavior. Transparent mode remains defined around the supervised ingress path, not around broad compatibility with all possible resolver behavior.

## Design

### Transparent Runtime Startup

`internal/helperruntime/runTransparentMode` should stop creating `dnsruntime.NewServer(...)` entirely.

Transparent startup should only:

- create the raw TCP ingress listener
- optionally create the IPv6 loopback ingress listener
- initialize the bridge with transparent traffic mode metadata
- serve the raw TCP listeners and bridge read loop

No helper-side DNS serve loop remains.

### Transparent Readiness

Transparent-mode readiness should no longer imply “DNS listener bound”.

The helper may continue to populate the ready envelope DNS field only if downstream code still needs a non-empty marker for “transparent DNS path is available”, but the value must no longer represent a bound listener. The preferred direction is to stop treating `DNSAddr` as a required transparent readiness condition and rely on the presence of the supervised runtime DNS callback instead.

If the existing ready envelope shape makes that awkward, the implementation should minimize changes while keeping the semantics explicit in comments and tests.

### DNS Runtime Path

The only supported transparent DNS path becomes:

1. payload issues DNS socket syscalls
2. seccomp supervisor recognizes managed UDP or TCP DNS traffic on port `53`
3. helper forwards the DNS payload through `DNSRoundTrip`
4. host manager performs upstream DNS round trips using host resolver configuration
5. helper writes the DNS response back into the payload process via syscall emulation

This path already exists and remains authoritative.

### Failure Semantics

Transparent mode must fail closed when supervised DNS support is unavailable.

Specifically:

- if the seccomp-supervised transparent runtime cannot be prepared, payload execution should fail
- if payload DNS attempts use unsupported traffic shapes, those requests should fail rather than escape directly
- no fallback local resolver should be started

### Staging

Transparent-mode staging should continue to write resolver configuration derived from host nameserver entries unless implementation review discovers a stronger reason to narrow it further.

This design intentionally does not reintroduce `nameserver 127.0.0.1`.

## Files Likely Affected

- `internal/helperruntime/transparent_mode.go`
  Remove DNS listener startup and shutdown wiring.
- `internal/helperruntime/config.go`
  Remove or narrow `DefaultTransparentDNSAddr` and any comments that still describe a direct transparent DNS bind as required behavior.
- `internal/helperruntime/runtime.go`
  Adjust transparent runtime target plumbing if `DNSAddr` no longer represents a real listener.
- `internal/helperruntime/runtime_test.go`
  Replace listener-binding startup assertions with tests for startup without a DNS listener and continued supervised DNS operation.
- `internal/helperruntime/dns/server.go`
  Remove if it becomes unused.
- `cmd/bbox-helper/main.go`
  Remove the helper DNS listen flag if no longer needed.
- `doc.go`, `ARTICLE.md`, and design/spec docs referencing helper-owned transparent DNS listeners
  Update documentation to describe supervised DNS instead of a local DNS daemon.

## Testing Strategy

Add or update tests to prove:

1. transparent runtime starts without binding a DNS listener
2. transparent payload DNS queries still succeed through the supervised DNS bridge
3. helper startup no longer fails because port `53` is unavailable
4. unsupported DNS traffic still fails closed
5. no code path still depends on `DNSAddr` meaning “real listener bound”

The tests should prefer narrow unit and integration coverage over broad refactoring.

## Risks

- readiness logic may still assume that transparent mode always reports a DNS listener address
- legacy tests or docs may still encode the old “bind `127.0.0.1:53`” design
- removing `dns/server.go` may expose hidden dependencies outside the obvious startup path

## Recommended Implementation Direction

Take the smallest coherent slice:

1. delete the transparent DNS listener startup path
2. update readiness expectations
3. keep `DNSRoundTrip` as the only DNS implementation path
4. remove dead code and stale docs once tests are green
