# Phase 1 Sandbox Library Design

**Date:** 2026-03-27

**Status:** Draft approved in conversation, awaiting written-spec review

## Goal

Build a reusable Go library plus small demo CLI that:

- starts one shared host-side proxy/egress-policy service
- creates multiple persistent unprivileged `bwrap` sandboxes concurrently
- applies per-sandbox network policy through the shared proxy
- stages requested binaries plus their runtime `.so` dependencies automatically
- supports explicit read-only and read-write host mounts
- runs arbitrary commands inside already-running sandboxes

Phase 1 is the foundation for a production-quality wrapper around unprivileged filesystem, PID, and network isolation. It intentionally excludes advanced interception features such as MITM, WebSocket-aware proxying, and full HTTP/2 proxy behavior.

## Non-Goals

Phase 1 does not include:

- TLS MITM
- content/body filtering beyond basic host and method policy
- WebSocket proxy semantics
- HTTP/2 tunnel or interception support
- distributed proxy deployment
- container image support
- Windows or macOS support

## High-Level Architecture

The system has three runtime roles:

1. **Host proxy manager**
   A long-lived host-side object that owns outbound network access, per-sandbox policy enforcement, sandbox registration, logging hooks, and lifecycle coordination.

2. **Sandbox helper**
   A long-lived process running inside each `bwrap` sandbox. It exposes a private control channel back to the host, launches user commands inside the sandbox, and provides the sandbox-local loopback proxy endpoint that payload processes use.

3. **Sandbox payload processes**
   Untrusted user processes such as `curl`, `wget`, `go`, or arbitrary commands. These inherit the sandbox filesystem and namespace restrictions, but do not inherit the host bridge capability.

The host proxy manager is the trust anchor for network policy. Sandboxes are isolated from the host network namespace and rely on their helper to relay outbound requests over a private host bridge. The helper is more trusted than payload processes, but less trusted than the host.

## Phase 1 Component Model

### `ProxyManager`

Responsibilities:

- own one shared host-side proxy service
- register and deregister sandbox sessions
- hold per-sandbox network policies
- execute outbound HTTP requests on behalf of sandboxes
- expose structured logs and basic metrics hooks
- manage graceful shutdown

Properties:

- single process-local instance can serve many sandboxes
- policies are keyed by sandbox/session ID
- host-side transport pool is shared but policy decisions are sandbox-specific

### `Sandbox`

Responsibilities:

- represent one persistent `bwrap` instance
- own sandbox staging directory and mount plan
- launch and monitor the in-sandbox helper
- expose an API for running commands in the already-running sandbox
- clean up bridge resources and temporary roots on close

Properties:

- sandbox lifetime is independent of any one payload process
- multiple `Run` calls can be issued sequentially; concurrency may be limited in Phase 1 if needed for simpler helper state

### Sandbox Helper

Responsibilities:

- start inside the sandbox as PID 1-ish long-lived control process
- bind the sandbox-local proxy address reachable by payload processes
- speak a private RPC/bridge protocol to the host proxy manager
- launch payload commands on request
- stream stdout, stderr, and exit status back to the host caller
- ensure payload processes do not inherit the host bridge capability

### Demo CLI

Responsibilities:

- demonstrate creation of one shared proxy manager
- demonstrate creation of one or more sandboxes
- demonstrate binary staging, mount setup, and per-sandbox policy
- run a sample process and print logs/results

The CLI is only a thin integration layer around the library API. It should not own core business logic.

## Public API Direction

The Phase 1 API should stay compact and stable enough for extension:

```go
type ProxyManager struct { ... }
type Sandbox struct { ... }

type ProxyOptions struct {
    AllowConnect    bool
    Logger          Logger
}

type NetworkPolicy struct {
    AllowHostRegex   []*regexp.Regexp
    DenyHostRegex    []*regexp.Regexp
    AllowHTTPMethods []string
}

type Mount struct {
    Source   string
    Target   string
    ReadOnly bool
}

type SandboxOptions struct {
    Name           string
    Binaries       []string
    ReadOnlyMounts []Mount
    ReadWriteMounts []Mount
    Env            []string
    Policy         NetworkPolicy
    WorkDir        string
}

type RunOptions struct {
    Env    []string
    WorkDir string
}

type RunResult struct {
    ExitCode int
    Stdout   []byte
    Stderr   []byte
}

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error)
func (p *ProxyManager) NewSandbox(ctx context.Context, opts SandboxOptions) (*Sandbox, error)
func (s *Sandbox) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error)
func (s *Sandbox) Close() error
func (p *ProxyManager) Close() error
```

Notes:

- `AllowConnect` is included in Phase 1 as a policy knob, but only for coarse allow/deny behavior. Advanced tunnel inspection is out of scope.
- API names may change during implementation, but the shape should stay close to this.
- `Binaries` may accept either absolute paths or executable names resolved through the host `PATH`.

## Filesystem and Binary Staging

Each sandbox gets its own staged root directory. The library will:

1. resolve requested binaries on the host
2. inspect runtime dependencies using `ldd`
3. collect the ELF loader, direct shared-library closure, and any required NSS/runtime files
4. copy them into the staged root at their expected sandbox paths
5. add helper binary/artifacts needed for the in-sandbox control process

Phase 1 staging rules:

- copied binaries are read-only inside the sandbox
- staged root is per-sandbox for correctness and isolation
- staging logic deduplicates file copies within a sandbox build
- missing binaries or dependency resolution failures are surfaced before the sandbox starts

Future optimization:

- shared staging cache across sandboxes can be added later, but should not complicate Phase 1 correctness

## Mount Model

Mounts are explicit and user-provided.

Supported mount types in Phase 1:

- read-only bind mounts
- read-write bind mounts
- fresh `/proc`, `/dev`, `/tmp`

Mount validation requirements:

- source paths must exist on the host
- target paths must be absolute sandbox paths
- overlapping/conflicting mount definitions must be rejected deterministically
- read-write mounts should be minimized and obvious in logs

Default filesystem posture:

- minimal staged root
- no implicit broad host binds
- temporary writable space only under explicit RW mounts plus sandbox `/tmp`

## Namespace and Sandbox Setup

Each sandbox should use `bwrap` with:

- user namespace
- PID namespace
- network namespace
- isolated mount namespace
- `--die-with-parent`
- `--new-session`
- clean environment

The helper runs inside the sandbox and remains alive until sandbox teardown.

The design does **not** rely on the host later joining the child network namespace. That approach failed for the PoC and is not part of the library architecture.

## Network Model

Each sandbox sees only its own loopback proxy endpoint inside its private network namespace.

Data flow:

1. payload process makes HTTP request through sandbox-local proxy
2. in-sandbox helper accepts the request
3. helper serializes request metadata/body onto a private host bridge tagged with sandbox identity
4. host proxy manager loads the sandbox policy
5. host proxy manager allows or denies the request
6. if allowed, host transport performs outbound request
7. response flows back through the helper to the payload process

Per-sandbox policy is mandatory even though the host proxy instance is shared.

## Policy Model

Phase 1 policy must be evaluated on the host side only.

Supported controls:

- allow host regexes
- deny host regexes
- allowlisted HTTP methods
- coarse `CONNECT` allow/deny

Evaluation order:

1. validate request shape
2. parse effective target host/method
3. apply explicit deny rules
4. apply allow rules
5. deny by default when policy is configured and no allow rule matches

Phase 1 should keep policy enforcement intentionally narrow and auditable. It should not attempt deep payload inspection.

## Command Execution Model

`Sandbox.Run` executes commands inside an existing sandbox helper.

Execution flow:

1. host sends exec RPC with argv/env/workdir
2. helper validates request and spawns payload process
3. helper streams stdout/stderr over control channel
4. helper returns exit status
5. host surfaces a `RunResult`

Security requirements:

- helper must not leak the host bridge connection or raw inherited fds to the payload process
- payload env must be curated, not inherited wholesale from helper runtime
- helper must set CLOEXEC on any control/bridge descriptors before spawning payloads

## Concurrency Model

Phase 1 must support:

- one proxy manager serving multiple sandboxes concurrently
- multiple persistent sandboxes existing concurrently
- concurrent outbound requests from different sandboxes

Phase 1 may choose one of two execution constraints for `Sandbox.Run`:

- allow one active command per sandbox for simpler helper design, or
- support multiple active commands with per-command stream multiplexing

The recommended first implementation is **one active command per sandbox**, with the internal protocol designed so multi-command support can be added later.

## Logging and Observability

Production readiness requires structured visibility even in Phase 1.

Minimum observability:

- sandbox creation/teardown events
- staged binary list and mount summary
- policy allow/deny decisions with sandbox ID, host, and method
- helper lifecycle events
- payload exit codes
- bridge/proxy transport failures

Sensitive data such as request bodies should not be logged by default.

## Error Handling

The library should fail fast and explicitly for:

- missing binaries
- unresolved shared-library dependencies
- invalid mount definitions
- invalid regex or policy configuration
- helper startup failure
- proxy registration failure
- bridge protocol mismatch
- payload launch failure

Runtime network denials should be surfaced as ordinary proxy denials, not as process crashes.

Cleanup rules:

- partial sandbox startup failures must tear down temp roots and child processes
- `Close` should be idempotent
- `ProxyManager.Close` should reject or drain active sandboxes predictably

## Security Properties and Limits

Phase 1 security properties:

- unprivileged namespace-based isolation
- no direct child access to host network namespace
- network access mediated by host policy
- no bridge capability inheritance to payload processes
- explicit filesystem exposure only through staged artifacts and requested mounts

Phase 1 limits:

- this is not VM-grade isolation
- helper compromise still gives an attacker the helper’s allowed bridge behaviors
- host proxy manager is part of the trusted computing base
- host-policy bugs can weaken network isolation

## Demo CLI Scope

The CLI should demonstrate:

- creating one proxy manager
- creating at least two sandboxes with different per-sandbox policies
- specifying binaries and mounts
- running commands such as `curl`, `wget`, or `go version`
- showing one allowed network action and one denied action

The CLI is not a full product interface and should not outrun the library API.

## Implementation Shape

Expected package layout for Phase 1:

- `pkg/proxy` or equivalent for host proxy manager and policy
- `pkg/sandbox` or equivalent for staging and lifecycle
- `pkg/helperproto` for bridge/control protocol types
- `cmd/demo` for the CLI/demo

Exact naming can change, but host proxy, sandbox lifecycle, staging, and helper protocol should be separated into focused packages.

## Testing Strategy

Phase 1 testing should include:

- unit tests for binary/dependency resolution
- unit tests for mount validation
- unit tests for policy evaluation
- unit tests for bridge protocol encoding/decoding
- integration tests creating multiple sandboxes concurrently
- end-to-end tests showing allowed and denied outbound requests

Given the security-sensitive nature of the helper boundary, integration coverage matters more than cosmetic CLI coverage.

## Open Decisions Intentionally Deferred

These are deferred to implementation planning or later phases:

- exact RPC framing and streaming protocol
- whether to use one bridge per sandbox or one multiplexed proxy transport
- whether `Run` allows multiple concurrent commands per sandbox in Phase 1
- cache layout for staged binary reuse
- exact public package names

## Recommended Next Step

After written-spec review, create an implementation plan for Phase 1 only:

- library packages
- helper/control protocol
- sandbox lifecycle
- per-sandbox proxy policy
- demo CLI

Do not fold MITM, WebSocket support, or advanced HTTP/2 handling into the Phase 1 plan.
