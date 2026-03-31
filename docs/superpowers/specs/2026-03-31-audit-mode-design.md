# Audit Mode And Policy Reporting Design

**Date:** 2026-03-31

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Extend `github.com/moolen/bbox` so both library users and `bbox` CLI users can:

- run sandboxes in an explicit `audit` policy mode that evaluates policy but does not block mediated traffic
- keep the existing `enforce` behavior while optionally surfacing policy violations during and after execution
- retrieve richer per-sandbox summaries than the current host-only `AccessedDomains()` snapshot
- receive deterministic end-of-session summaries in the CLI

This feature is about observability and policy development. It must reuse bbox's existing mediation boundaries rather than claim visibility into unsupported traffic classes.

## Non-Goals

This phase does not include:

- payload capture or request-body persistence
- redaction of arbitrary request payloads
- persistence of audit data beyond the sandbox lifetime
- packet-level visibility outside bbox's existing HTTP, HTTPS MITM, CONNECT, DNS, and transparent mediation paths
- changing sandbox network isolation semantics
- changing the default `enforce` behavior for existing callers

## User-Facing Requirements

The feature must work for both:

1. library callers using `ProxyManager` and `Sandbox`
2. CLI callers using `bbox`

Required user outcomes:

- users can choose between `enforce` and `audit`
- `audit` mode bypasses policy denials for traffic bbox already mediates
- bbox still records whether a request would have violated policy in `audit`
- `enforce` mode can report policy violations during and after execution
- users can retrieve an aggregated host-level summary
- users can retrieve a grouped request-level summary by host, port, method, path, and request kind where applicable
- CLI users can see a readable summary after the sandboxed command exits

## Current State

bbox already has a shared host-side access-event pipeline:

- per-request `AccessLogEntry`
- injected `AccessLogger`
- default JSON-lines logging
- per-sandbox `AccessedDomains()` aggregation keyed by normalized host

That provides a strong base, but it is missing:

- an explicit policy execution mode
- explicit policy-violation reporting separate from access outcomes
- request-level aggregation APIs
- a CLI end-of-run summary

## High-Level Architecture

The right design keeps one host-side request evaluation pipeline and separates two concerns that are currently coupled:

1. **policy evaluation**
2. **policy enforcement**

Every mediated request should:

1. be normalized into the existing host-side request model
2. be evaluated against the compiled policy
3. emit an access event containing the actual outcome
4. optionally emit or attach policy-violation diagnostics
5. be either blocked or allowed depending on the selected policy mode

This avoids a parallel "audit implementation" and ensures `enforce` and `audit` observe the same request normalization.

## Public API Direction

### Policy Mode

Add an explicit shared mode:

```go
type PolicyMode string

const (
    PolicyModeEnforce PolicyMode = "enforce"
    PolicyModeAudit   PolicyMode = "audit"
)
```

Behavior:

- `enforce` is the default when unset
- invalid values fail manager or sandbox construction explicitly
- sandbox-level mode overrides manager default for that sandbox

### Reporting Options

Add reporting controls that do not affect allow/deny semantics:

```go
type ReportingOptions struct {
    PolicyViolations bool
    AccessSummary    bool
    RequestSummary   bool
}
```

Suggested placement:

```go
type ProxyOptions struct {
    // existing fields...
    PolicyMode PolicyMode
    Reporting  ReportingOptions
}

type SandboxOptions struct {
    // existing fields...
    PolicyMode PolicyMode
    Reporting  ReportingOptions
}
```

Semantics:

- manager values are defaults inherited by new sandboxes
- sandbox values override manager defaults when explicitly set
- reporting toggles control emitted diagnostics and summaries, not policy decisions

### Access Log Entry Expansion

Extend the public access log entry so callers can distinguish real outcome from policy evaluation:

```go
type AccessLogEntry struct {
    Time             time.Time
    SandboxID        string
    TrafficMode      TrafficMode
    Kind             string
    Host             string
    Port             int
    Method           string
    Path             string
    Allowed          bool
    StatusCode       int
    Result           string
    Error            string
    PolicyMode       PolicyMode
    PolicyAllowed    bool
    PolicyViolations []string
}
```

Field semantics:

- `Allowed` remains the actual runtime outcome
- `PolicyAllowed` records whether the compiled policy would allow the request
- `PolicyViolations` contains one or more human-readable policy reasons when evaluation fails
- in `enforce`, `Allowed` and `PolicyAllowed` usually match
- in `audit`, `Allowed` may be `true` while `PolicyAllowed` is `false`

### Richer Summary API

Keep `Sandbox.AccessedDomains()` for compatibility and add a richer summary surface:

```go
type AccessSummary struct {
    Hosts    []AccessedHostSummary
    Requests []RequestAggregate
}

type AccessedHostSummary struct {
    Host               string
    TrafficMode        TrafficMode
    Attempts           int
    LastResult         string
    LastError          string
    LastSeenAt         time.Time
    LastPort           int
    ConnectSeen        bool
    HTTPSeen           bool
    MITMSeen           bool
    DNSSeen            bool
    PolicyViolations   int
    PolicyAllowedCount int
    PolicyDeniedCount  int
}

type RequestAggregate struct {
    Kind               string
    Host               string
    Port               int
    Method             string
    Path               string
    Attempts           int
    AllowedCount       int
    DeniedCount        int
    PolicyAllowedCount int
    PolicyDeniedCount  int
    LastSeenAt         time.Time
    LastStatusCode     int
    LastError          string
}

func (s *Sandbox) AccessSummary() AccessSummary
```

Grouping rules:

- host summaries aggregate by normalized host
- request summaries aggregate by `kind + host + port + method + path`
- request summaries should omit meaningless fields where the protocol does not provide them
- DNS groups by `kind=dns`, `host`, and `port=53`
- CONNECT groups by `kind=connect` or `transparent_connect`, `host`, and `port`

## Internal Evaluation Model

Introduce an internal policy-evaluation result that is shared by all request paths:

```go
type policyEvaluation struct {
    Allowed bool
    Reasons []string
}
```

Every current policy check should move from a pure `error` return shape toward one of these two patterns:

1. internal helpers return `policyEvaluation`
2. enforcement adapters convert a denied evaluation back into today's error messages when needed

This preserves current response behavior while making "would have been denied" observable in `audit`.

## Policy Mode Semantics

### Enforce

`enforce` preserves today's behavior:

- denied evaluation blocks the request
- bbox records an access event with `Allowed=false`
- if policy-violation reporting is enabled, the violation is emitted live and included in summaries

### Audit

`audit` changes only the enforcement decision:

- bbox still evaluates policy normally
- denied evaluation is recorded as a policy violation
- bbox does not block the mediated request because of policy
- access events reflect the actual runtime outcome of the request

Examples:

- policy would deny `POST /upload`, upstream succeeds:
  - `Allowed=true`
  - `Result="allowed"`
  - `PolicyAllowed=false`
  - `PolicyViolations=["method POST is not allowed", ...]`
- policy would deny a DNS lookup, upstream DNS resolution succeeds:
  - request continues in `audit`
  - violation is recorded even though runtime outcome is successful

## Request Path Coverage

The first version must cover every existing mediated path consistently:

- proxy HTTP
- CONNECT
- HTTPS MITM
- DNS
- transparent HTTP
- transparent HTTPS
- transparent raw TCP authorization paths that currently surface as `transparent_connect`

The design must not claim to observe unsupported traffic that bypasses bbox mediation.

## Logging And Reporting

### Live Logging

Keep the existing access logger model and extend it with policy fields.

Default behavior:

- keep JSON-lines access logging unless explicitly disabled by CLI settings
- one line per access attempt
- include policy metadata when present

Library behavior:

- injected `AccessLogger` still receives one entry per access attempt
- bbox should not call a second logger implicitly when a custom logger is supplied

### Policy-Violation Reporting

Policy-violation reporting is a second presentation layer, not a second event source.

Recommended behavior:

- violations are derived from the same access event plus policy evaluation
- CLI may present them as concise stderr lines
- library users can derive them from `AccessLogEntry` or consume them from summaries

### End-of-Session CLI Summary

When enabled, bbox prints a human-readable summary after the payload exits.

Recommended sections:

1. host summary
2. grouped request summary
3. policy violations summary

Example shape:

```text
Access summary
  example.com: attempts=5 last_result=allowed last_port=443 violations=2
  api.example.com: attempts=3 last_result=upstream_error last_port=443 violations=0

Request summary
  mitm GET example.com:443 /v1/data attempts=3 allowed=3 policy_denied=1
  http POST example.com:80 /upload attempts=2 allowed=2 policy_denied=2
  dns example.com:53 attempts=1 allowed=1 policy_denied=0
```

Formatting does not need to match this exactly, but it must be deterministic and stable enough for human inspection.

## CLI Direction

Add explicit flags:

- `--policy-mode enforce|audit`
- `--report-policy-violations`
- `--report-access-summary`
- `--report-request-summary`
- `--access-log json|off`

Add a convenience flag:

- `--audit`

Shorthand semantics:

- `--audit` expands to:
  - `--policy-mode audit`
  - `--report-policy-violations`
  - `--report-access-summary`
  - `--report-request-summary`

Default CLI behavior:

- no behavior changes for existing callers
- if none of the new report flags are set, bbox behaves as today aside from enriched JSON log fields

## Compatibility

Compatibility requirements:

- existing code using `Sandbox.AccessedDomains()` keeps working
- existing custom `AccessLogger` implementations continue to compile if added fields are purely additive to `AccessLogEntry`
- existing sandboxes default to `PolicyModeEnforce`
- current response status codes and denial messages remain unchanged in `enforce`

## Security And Privacy

Do not log full payloads in this phase.

Rationale:

- request bodies may contain credentials, tokens, cookies, API keys, prompts, PII, or source code
- once bbox records payloads, it implicitly owns redaction guarantees
- ad hoc redaction is too weak for a first version

Allowed v1 metadata:

- body presence
- bounded body size
- existing allow/deny evaluation results

Deferred future work:

- opt-in payload capture
- sink-specific redaction rules
- structured redaction tests

## Implementation Notes

Recommended implementation steps:

1. add `PolicyMode` and reporting configuration types
2. thread effective mode/reporting from manager defaults to sandbox instances
3. refactor policy checks to expose reusable evaluation results
4. extend access events and `AccessLogEntry`
5. extend audit aggregation to track policy counters and request aggregates
6. add `Sandbox.AccessSummary()`
7. add CLI flags and summary rendering
8. update docs and examples

## Testing Strategy

Add coverage for:

- default `enforce` behavior remaining unchanged
- `audit` allowing traffic that policy would deny while recording violations
- `enforce` reporting violations without changing allow/deny semantics
- aggregation by host and by request key
- CLI summary output for representative HTTP, MITM, CONNECT, and DNS cases
- additive `AccessLogEntry` contents delivered to custom `AccessLogger`
- snapshot-copy behavior for `AccessSummary()` and `AccessedDomains()`

Representative integration scenarios:

- method denied by policy but allowed in `audit`
- path denied by policy but allowed in `audit`
- DNS host denied by policy but allowed in `audit`
- CONNECT denied by policy but allowed in `audit`
- `enforce` run with policy-violation reporting enabled

## Open Follow-Ups

These are explicitly deferred:

- payload capture and redaction
- machine-readable summary export format
- persistent audit history across sandbox lifetime boundaries
- separate event subscription APIs beyond the existing logger hook
