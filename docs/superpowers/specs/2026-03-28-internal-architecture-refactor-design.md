# Internal Sandbox Architecture Refactor Design

## Goal

Restructure the sandbox internals so the helper runtime, manager-side proxy orchestration, and helper client transport each have clear package boundaries and narrower responsibilities. The refactor should preserve current behavior, keep the existing security hardening intact, and make the next CLI cleanup phase smaller and safer.

## Scope

This phase covers internal architecture only:

- split `internal/helperruntime/runtime.go` into focused internal packages and smaller entrypoint files
- reduce responsibility spread in `manager.go`
- reduce responsibility spread in `helper_client.go`
- align small public API seams where the current internal split is blocked by duplicated or misplaced configuration
- keep tests green and preserve current proxy, transparent, MITM, tunnel, DNS, and exec behavior

## Non-Goals

This phase does not:

- redesign sandbox features or network policy semantics
- change default security posture beyond preserving the already-landed hardening
- perform the main `cmd/bbox` architecture cleanup
- introduce streaming request or response bodies across the bridge
- redesign the wire protocol in `internal/helperproto`

## Current Problems

### Helper Runtime Monolith

`internal/helperruntime/runtime.go` is 1632 lines and currently mixes:

- startup and mode selection
- transparent DNS serving
- proxy and transparent HTTP ingress
- transparent HTTPS interception and MITM flow
- tunnel lifecycle and bridge message routing
- command execution and PTY handling
- low-level helpers such as bounded reads and listener shims

That makes tests coarse, encourages hidden coupling through the `bridge` type, and makes even small behavior changes high-risk.

### Manager Responsibility Sprawl

`manager.go` is 865 lines and currently acts as:

- sandbox registry
- helper binary locator and helper bootstrap dependency owner
- proxy request adapter
- CONNECT authorization and dialing policy engine
- MITM request evaluator and upstream transport owner
- certificate authority facade
- access audit sink

Those concerns move at different speeds and should not require the same file context to change safely.

### Helper Client Responsibility Sprawl

`helper_client.go` is 792 lines and currently mixes:

- helper process lifecycle and readiness
- bridge read loop and envelope dispatch
- run-session state management
- tunnel registration and bidirectional relay
- exec stream delivery

This makes the client difficult to reason about because process lifecycle, bridge protocol handling, and tunnel I/O all mutate shared state from one type.

## Target Architecture

### Helper Runtime Package Layout

Keep `internal/helperruntime` as the public internal entrypoint package, but split implementation into subpackages:

- `internal/helperruntime/runtime`
  - startup configuration validation
  - proxy-mode and transparent-mode boot wiring
  - top-level `Run` orchestration helpers
- `internal/helperruntime/bridge`
  - bridge type
  - envelope send/read loop
  - request correlation
  - tunnel registration and tunnel frame delivery
  - shared bounded body helpers used by ingress paths
- `internal/helperruntime/ingress`
  - proxy HTTP handler
  - transparent HTTP handler
  - CONNECT handling
  - transparent HTTPS interception
  - MITM HTTP serving
- `internal/helperruntime/dns`
  - transparent DNS server and DNS query helpers
- `internal/helperruntime/exec`
  - exec session setup
  - PTY and stdio wiring
  - exec input and output streaming

`internal/helperruntime/runtime.go` should shrink to a small entrypoint layer or disappear in favor of a few focused files under the root package plus the new subpackages.

### Manager-Side Package Layout

Keep the public `bbox` API surface stable where practical, but extract internal collaborators so `ProxyManager` becomes a coordinator instead of the implementation site for every concern.

Recommended internal units:

- `internal/manager/registry`
  - sandbox registration
  - sandbox attachment and lookup
  - sandbox naming
  - accessed-domain snapshots
- `internal/manager/proxy`
  - proxy request handling
  - MITM request handling
  - upstream transport ownership
  - authority validation and response-size enforcement
- `internal/manager/connect`
  - CONNECT authorization
  - tunnel dialing helpers
- `internal/manager/audit`
  - access event recording and sink fanout
- `internal/manager/helperbin`
  - helper binary resolution and package-root lookup

`ProxyManager` should keep only:

- construction and dependency wiring
- lifecycle ownership for shared collaborators
- methods needed by existing callers

### Helper Client Package Layout

Extract helper-client internals behind smaller files or subpackages:

- `internal/hostbridge/client`
  - helper process lifecycle
  - read loop
  - envelope dispatch
  - ready-state transitions
- `internal/hostbridge/run`
  - run-session state
  - exec result completion
  - stdin and resize pumps
- `internal/hostbridge/tunnel`
  - host tunnel registration
  - outbound relay
  - close semantics

If package extraction causes circular dependencies, file-level extraction inside the existing package is acceptable for the first cut, but responsibilities should still match these boundaries.

## Dependency Rules

To keep the cleanup from regressing into another monolith, enforce these directional rules:

- helper-runtime ingress code may depend on bridge, exec, and dns packages through explicit interfaces or focused types
- bridge code must not depend on ingress handlers or exec command construction
- exec code must not import ingress or DNS code
- manager proxy code may depend on registry lookups and audit recording through interfaces, but registry code must not depend on proxy logic
- helper client tunnel code must not own process-lifecycle decisions

The point is not maximal abstraction. The point is one-way dependencies that match runtime ownership.

## Public API Cleanups Allowed In This Phase

Small breaking changes are acceptable where they remove ambiguity or duplicate configuration:

- consolidate body-size limits so public configuration clearly lives in one place
- remove or rename internal-facing helpers that leaked into broader files only because code lived together
- tighten constructor signatures so extracted collaborators receive only the dependencies they actually use

This phase should avoid broad API redesign. If a cleanup does not directly unblock the package split or reduce architectural ambiguity, defer it.

## Migration Strategy

Use a staged refactor rather than a rewrite:

1. Extract tests around current behavior before moving code.
2. Move low-risk leaf concerns first:
   - DNS server
   - bounded body helpers
   - authority validation helpers
3. Extract bridge and tunnel coordination behind focused files or packages.
4. Extract exec session handling.
5. Extract manager collaborators and reduce `ProxyManager` to orchestration.
6. Extract helper client collaborators and reduce shared mutable state.

Each stage should leave the repository building and tests passing. No flag day rewrite.

## Testing Strategy

Preserve and expand behavior coverage around the seams being introduced:

- helper runtime tests should target DNS behavior, request rewriting, bounded body reads, CONNECT handling, MITM authority validation, and exec session behavior with focused unit tests where possible
- manager tests should cover proxy request policy evaluation, CONNECT authorization, MITM upstream authority handling, response-size limits, and audit recording
- helper client tests should cover ready-state handling, run-session completion, tunnel activation and shutdown, and stream forwarding

The goal is to replace broad monolithic tests with smaller seam-oriented tests while keeping end-to-end coverage for critical traffic paths.

## Success Criteria

This phase is complete when:

- `internal/helperruntime/runtime.go`, `manager.go`, and `helper_client.go` are materially smaller and no longer each own multiple unrelated domains
- extracted packages or files have clear single-purpose responsibilities
- current sandbox networking and exec behavior remain intact
- existing hardening stays enforced
- `go test ./...` passes
- the resulting structure makes the later `cmd/bbox` cleanup mostly translation and wiring work instead of dependency untangling

## Follow-Up Work

After this internal phase lands, the next refactor should target `cmd/bbox/main.go` by separating:

- Cobra command construction
- option parsing and validation
- config translation into `bbox` types
- terminal and process execution helpers
