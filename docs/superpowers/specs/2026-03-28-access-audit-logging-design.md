# Access Audit And Live Logging Design

**Date:** 2026-03-28

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Extend `github.com/moolen/bbox` so library users can:

- retrieve a per-sandbox audit snapshot of domains accessed during the sandbox session
- see whether each domain attempt was allowed, denied, or failed upstream
- receive live per-request proxy access logs as JSON lines
- override the default stdout logger with an injected logger implementation

This is intentionally an observability feature. It must not alter policy behavior, network routing, or sandbox isolation semantics.

## Non-Goals

This phase does not include:

- persistent audit storage beyond the sandbox lifetime
- log subscriptions or streaming APIs beyond the injected logger hook
- response-body logging
- arbitrary configurable log formats beyond the default JSON-lines output
- cross-process audit aggregation across multiple `ProxyManager` instances

## User-Facing Requirements

The feature is explicitly split into two separate user capabilities:

1. `AccessedDomains()` for per-sandbox audit snapshots
2. live request logging to stdout by default, with an injectable logger interface for library consumers

Audit behavior requirements:

- include every request attempt, not only successful requests
- include allowed requests, policy-denied requests, and upstream failures
- include the accessed domain and the result for that attempt
- for HTTPS MITM traffic, capture both:
  - the CONNECT attempt
  - the decrypted HTTP request attempts inside that tunnel

Logging behavior requirements:

- default output is JSON lines
- emit one log record per request attempt
- allow library consumers to replace the default logger with their own implementation

## High-Level Architecture

The right integration point is the host-side `ProxyManager`, because all plain HTTP, CONNECT, and MITM traffic already converges there before outbound dialing.

Recommended structure:

1. all request paths emit a shared internal access event
2. the manager records that event into per-sandbox audit state
3. the same event is forwarded to the configured logger

This keeps audit state and live logging consistent and avoids separate logic paths drifting over time.

## Public API Direction

### Logger Hook

Add a small logger interface to `ProxyOptions`:

```go
type AccessLogger interface {
	LogAccess(AccessLogEntry)
}

type ProxyOptions struct {
	ListenAddr    string
	NetworkPolicy NetworkPolicy
	MITM          MITMOptions
	AccessLogger  AccessLogger
}
```

Default behavior:

- when `AccessLogger` is nil, bbox uses a default JSON-lines logger writing to stdout
- when `AccessLogger` is set, bbox uses the injected logger instead of stdout

### Logged Entry

The default log payload and injected logger input should use one structured entry type:

```go
type AccessLogEntry struct {
	Time       time.Time
	SandboxID  string
	Kind       string
	Host       string
	Port       int
	Method     string
	Path       string
	Allowed    bool
	StatusCode int
	Result     string
	Error      string
}
```

Field semantics:

- `Kind` is one of `http`, `connect`, or `mitm`
- `Allowed` means policy allowed the attempt to proceed
- `Result` distinguishes outcomes such as `allowed`, `denied`, or `upstream_error`
- `StatusCode` is the proxy-visible or upstream-visible status when applicable
- `Error` carries the denial reason or transport failure text when present

### Sandbox Audit Snapshot

Expose an audit snapshot through the sandbox:

```go
type AccessedDomain struct {
	Host         string
	Attempts     int
	LastResult   string
	LastError    string
	LastSeenAt   time.Time
	LastPort     int
	ConnectSeen  bool
	HTTPSeen     bool
	MITMSeen     bool
}

func (s *Sandbox) AccessedDomains() []AccessedDomain
```

Behavior:

- returns a snapshot for one sandbox only
- aggregates repeated attempts by normalized host
- includes every attempted domain, not only successful ones
- result fields reflect the most recent observed attempt for that host
- returns a copy so callers cannot mutate internal manager state

## Event Model

Internally, bbox should use one unified access event model for both logging and audit aggregation.

Suggested internal event shape:

```go
type accessEvent struct {
	Time       time.Time
	SandboxID  string
	Kind       string
	Host       string
	Port       int
	Method     string
	Path       string
	Allowed    bool
	StatusCode int
	Result     string
	Error      string
}
```

This event stays internal. Public APIs use `AccessLogEntry` and `AccessedDomain`.

## Request Path Semantics

### Plain HTTP

For every proxied plain HTTP request:

- emit one `http` event
- record the normalized host and port
- mark denied requests as `Allowed=false`, `Result="denied"`
- mark transport failures after policy approval as `Allowed=true`, `Result="upstream_error"`
- mark successful upstream requests as `Allowed=true`, `Result="allowed"`

### CONNECT

For every CONNECT attempt:

- always emit one `connect` event
- include the requested target host and port
- record denied CONNECT attempts as `Allowed=false`, `Result="denied"`
- record successful authorization as `Allowed=true`, `Result="allowed"`

This event is independent from any later MITM request events.

### HTTPS MITM

When MITM is enabled and decrypted requests are forwarded:

- emit the CONNECT event as above
- emit one `mitm` event per decrypted HTTP request
- include method and path from the decrypted request
- apply the same allowed / denied / upstream-error result mapping

This preserves both the outer tunnel attempt and the inner request-level audit trail.

## Normalization Rules

Audit and logging should use the same host normalization strategy used by policy evaluation where practical:

- preserve the logical destination host
- separate host and port when known
- normalize `host:port` inputs so audit aggregation keys by host, not raw authority strings

The goal is stable audit output such that repeated attempts to `example.com:443` aggregate under `example.com` with `LastPort=443`.

## Manager State And Lifecycle

The `ProxyManager` should own per-sandbox audit state.

Recommended shape:

- maintain a map keyed by sandbox ID
- each sandbox record stores aggregated `AccessedDomain` state by normalized host
- protect audit state with the existing manager mutex

Lifecycle behavior:

- initialize empty audit state when sandbox registration succeeds
- update audit state whenever an access event is emitted
- remove audit state when the sandbox is closed and unregistered

`Sandbox.AccessedDomains()` should delegate to the manager and return an immutable snapshot.

## Logging Behavior

Default logging:

- JSON lines
- one line per emitted access event
- write to stdout

Injected logging:

- if the user supplies `ProxyOptions.AccessLogger`, bbox routes all access events to that logger
- bbox should not additionally emit the default stdout logs in that case

Operational constraints:

- logging should be best-effort
- logger failures must not break request handling
- bbox should avoid logging request bodies by default

## Error And Result Mapping

The audit and log result model must be explicit and consistent:

- policy denial:
  - `Allowed=false`
  - `Result="denied"`
  - `Error` contains the policy reason
- policy allowed, upstream transport failed:
  - `Allowed=true`
  - `Result="upstream_error"`
  - `Error` contains the transport failure
- policy allowed, upstream response completed:
  - `Allowed=true`
  - `Result="allowed"`
  - `StatusCode` contains the response status where relevant

For CONNECT in MITM mode:

- a successful CONNECT authorization logs as allowed even if later decrypted requests are denied
- later MITM request denials are separate events and must not overwrite the fact that the CONNECT itself was allowed

## Concurrency And Safety

The manager serves multiple sandboxes concurrently, so audit updates must be thread-safe.

Requirements:

- no data races between concurrent requests in one sandbox
- no data races between different sandboxes
- snapshots returned by `AccessedDomains()` must be copies
- slow or misbehaving logger implementations should not be able to corrupt manager state

This phase does not introduce asynchronous buffering or a background log worker unless required for correctness. Start simple.

## Testing Strategy

Unit coverage:

- access event to audit aggregation mapping
- repeated attempts update `Attempts` and last-result fields correctly
- policy-denied, upstream-error, and success events map to the expected audit/log fields
- default logger selection and injected logger override behavior

Integration coverage:

- allowed and denied plain HTTP requests appear in `AccessedDomains()`
- CONNECT attempts are recorded
- MITM request attempts are recorded separately from CONNECT
- injected logger receives structured entries during real sandbox traffic

## Security And Privacy Notes

This feature increases observability, not sandbox privilege.

Guardrails:

- do not log request bodies by default
- do not persist audit state beyond the sandbox lifecycle in this phase
- keep audit/logging entirely host-side
- continue treating the host manager as the single policy authority

The feature is intended for operational auditing, so visibility of domains, methods, paths, statuses, and policy outcomes is acceptable. Sensitive payload content remains out of scope.
