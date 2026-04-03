# Docker Socket Policy Design

## Goal

Allow a sandboxed process to use a Docker-compatible socket without exposing the real host daemon socket directly.

The solution must let `bbox` mediate Docker Engine API access with a policy system that can:

- default to deny
- allow or deny high-level Docker operations such as `image_pull`, `build`, `container_create`, and `exec_start`
- support raw HTTP method/path matching as an escape hatch
- inspect selected request payload fields for sensitive operations
- prevent obvious sandbox escape and exfiltration paths such as `exec`, `push`, archive copy, attach, and privileged container creation
- fit the existing `bbox` manager-owned policy and audit model

## Scope

This design covers:

- a host-side Docker socket proxy owned by `bbox`
- per-sandbox Docker socket policy
- library and CLI config shape for Docker socket mediation
- request normalization from Engine API paths to higher-level operations
- payload-aware policy for `build`, `container_create`, and `exec_create`
- audit logging for Docker socket decisions

This design does not cover:

- Kubernetes API mediation
- full Docker API parity in phase 1
- daemon-side hardening outside `bbox`
- implementing a separate build backend in this phase

## Threat Model

The sandbox should never receive the real `/var/run/docker.sock`. Access to the Docker daemon is a high-trust control plane, so the proxy must treat the daemon as a protected host resource.

Primary abuse paths to block:

- `docker exec` or attach-style access into already-running containers
- `docker run` or `docker create` with privileged mode, host namespaces, device passthrough, or host bind mounts
- `docker push` as a clean exfiltration channel
- archive and export endpoints that can move data in or out of containers or images
- daemon-management endpoints unrelated to the requested workflows

Important limitation:

- allowing `docker build` does not preserve the sandbox's network isolation on its own
- build steps run on the Docker daemon / BuildKit side rather than inside `bbox`
- Buildx drivers such as `docker-container` can create builder containers through Docker itself

That means a Docker socket proxy can control who may ask for a build and with what parameters, but it cannot by itself guarantee that build-time execution cannot exfiltrate over the builder's own network path. If build-time exfiltration is in scope, this design should be paired with a dedicated constrained builder or other daemon-side controls.

## Decision

Use a `bbox`-owned Unix domain socket proxy as the primary enforcement point.

Do not rely on a Docker authorization plugin as the primary barrier. It may be useful later as defense-in-depth, but the main guarantee should be that the sandbox never talks to the real daemon socket.

The Docker socket policy must be a first-class configuration surface, separate from `NetworkPolicy`, because the decision key is Docker operation and payload semantics rather than remote hostname matching.

## Architecture

### Components

Add a dedicated Docker mediation path owned by `ProxyManager`:

- `dockerSocketManager`
  - creates and tears down per-sandbox proxy sockets
  - owns compiled Docker socket policy for each sandbox
  - records audit events
- `dockerSocketProxy`
  - accepts HTTP over a sandbox-visible Unix socket
  - normalizes requests into Docker operations
  - evaluates policy
  - forwards approved requests to the real daemon socket
- `compiledDockerSocketPolicy`
  - high-level operation rules
  - raw HTTP escape-hatch rules
  - payload matchers for build, image refs, container config, and exec config

### Trust Boundary

The host-side proxy socket is the only Docker endpoint mounted into the sandbox. The real daemon socket remains outside the sandbox and is reachable only by the proxy process.

The proxy should be sandbox-specific, not manager-global, so policy, audit, and future request state can remain scoped to a single sandbox.

### Data Flow

1. `bbox` creates a sandbox and, when Docker socket mediation is enabled, starts a per-sandbox Unix socket listener on the host.
2. `bbox` mounts that proxy socket into the sandbox at the configured path, typically `/var/run/docker.sock`.
3. The sandboxed Docker client sends Engine API requests to the proxy socket.
4. The proxy strips any version prefix such as `/v1.52`, maps the request to a normalized operation, and parses any relevant query/body fields.
5. The compiled Docker socket policy returns allow or deny, plus reasons for audit reporting.
6. Approved requests are forwarded to the real host Docker socket. Denied requests fail closed with a deterministic HTTP error.

## Policy Model

### High-Level Shape

Expose both a public library API and a CLI config block.

Proposed library shape:

```go
type DockerSocketOptions struct {
	Enabled          bool
	MountPath        string
	TargetSocketPath string
	Policy           DockerSocketPolicy
}

type DockerSocketPolicy struct {
	DefaultAction RuleAction
	Rules         []DockerSocketRule
}

type DockerSocketRule struct {
	Name       string
	Action     RuleAction
	Operations []DockerOperation
	HTTP       *DockerHTTPMatch
	ImageRefs  *DockerImageRefMatch
	Build      *DockerBuildMatch
	Container  *DockerContainerMatch
	Exec       *DockerExecMatch
}
```

Proposed CLI shape:

```yaml
docker_socket:
  enabled: true
  mount_path: /var/run/docker.sock
  target_socket_path: /var/run/docker.sock
  default_action: deny
  rules:
    - name: allow-pull
      action: allow
      operations: [image_pull]
      image_refs:
        allow:
          - "^docker[.]io/library/.*$"
          - "^ghcr[.]io/acme/.*$"

    - name: allow-image-inspect
      action: allow
      operations: [image_inspect]

    - name: allow-build
      action: allow
      operations: [build]
      build:
        context:
          type: local_only
        dockerfile_paths:
          - "^Dockerfile$"
          - "^docker/.*$"

    - name: deny-exec
      action: deny
      operations: [exec_create, exec_start]

    - name: deny-push
      action: deny
      operations: [image_push]

    - name: raw-deny-archive
      action: deny
      http:
        methods: [GET, PUT]
        path_patterns:
          - "^/containers/[^/]+/archive$"
```

### Rule Semantics

- rules are evaluated in order
- the first matching rule wins
- omitted match dimensions are wildcards
- `default_action` applies when no rule matches
- `operations` is the normal interface
- `http` is an escape hatch for unsupported or not-yet-normalized endpoints

This differs intentionally from `NetworkPolicy`, which is a pure allow-rule system. Docker socket policy needs ordered allow and deny rules because the surface is broader and more stateful.

## Operation Mapping

The proxy should normalize Engine API requests into versionless operations before policy evaluation.

Initial operation set:

- `image_pull`
- `image_inspect`
- `image_push`
- `build`
- `container_create`
- `container_start`
- `exec_create`
- `exec_start`
- `attach`
- `archive_read`
- `archive_write`
- `image_export`
- `daemon_admin`
- `unknown`

Initial endpoint mapping:

- `POST /images/create` -> `image_pull`
- read-only image metadata paths such as `/images/{name}/json` -> `image_inspect`
- `POST /images/{name}/push` -> `image_push`
- `POST /build` -> `build`
- `POST /containers/create` -> `container_create`
- `POST /containers/{id}/start` -> `container_start`
- `POST /containers/{id}/exec` -> `exec_create`
- `POST /exec/{id}/start` -> `exec_start`
- attach-style endpoints -> `attach`
- `/containers/{id}/archive` `GET` -> `archive_read`
- `/containers/{id}/archive` `PUT` -> `archive_write`

Any unmapped endpoint should evaluate as `unknown` and be denied by default.

## Phase 1 Policy Posture

Recommended phase 1 policy for the stated use case:

- allow `image_pull`
- allow `image_inspect`
- allow `build`
- deny `image_push`
- deny `container_create`
- deny `container_start`
- deny `exec_create`
- deny `exec_start`
- deny attach, archive, export, and daemon-admin endpoints unless explicitly opened later

This satisfies the immediate requirement to support pull and build while blocking the most direct escape and exfiltration paths.

## Payload-Aware Enforcement

### Image Pull

`image_pull` rules may match normalized image references and registry/repository patterns.

Examples:

- allow pulls from `docker.io/library/*`
- allow pulls from `ghcr.io/acme/*`
- deny everything else by default

### Build

`build` requires dedicated handling. The proxy must not treat `POST /build` as a generic allow.

Phase 1 build checks:

- reject requests that declare remote contexts
- reject push/export options that send output to a registry
- allow only local-context builds from the Docker client's tar-stream upload path
- allow only approved Dockerfile paths within the uploaded context

Important enforcement limit:

- the Engine API does not preserve the original host path that the Docker client tarred before upload
- therefore the proxy can reliably enforce "local tar-stream context only" and Dockerfile path constraints inside that context
- it cannot reliably prove which sandbox filesystem path the tar stream originated from without adding a higher-level wrapper protocol

This means the policy field should use `local_only` to mean "no remote URL or stdin-based remote context semantics," not "cryptographically prove the archive came from `/workspace`."

### Container Create

Phase 1 denies `container_create`, so no container payload enforcement is required to meet the initial use case.

For the first phase that allows container creation, add a dedicated nested matcher:

```yaml
container:
  allow_privileged: false
  allow_host_network: false
  allow_host_pid: false
  allow_host_ipc: false
  allow_devices: false
  allow_bind_mounts: false
  allowed_cap_add: []
  denied_security_opts:
    - "seccomp=unconfined"
    - "apparmor=unconfined"
```

The proxy should reject requests that set:

- `HostConfig.Privileged=true`
- host namespace modes
- device passthrough
- bind mounts outside an allowlist
- dangerous `SecurityOpt` values
- capability additions outside an allowlist

If `container_create` is ever allowed, `container_start` should only be allowed for container IDs created through this proxy under an approved policy decision.

### Exec

Phase 1 denies both `exec_create` and `exec_start`.

If exec support is ever introduced, it should remain payload-aware because exec create requests also carry a privileged mode and command details.

## Buildx And Builder Driver Behavior

Docker build flows need explicit guardrails:

- `docker buildx create` with the `docker-container` driver creates a BuildKit daemon in a container
- that flow depends on container create/start permissions through the Docker API
- because phase 1 denies `container_create` and `container_start`, container-backed builder creation is implicitly denied

This is desirable for the current use case. Phase 1 should support only build flows that operate through the daemon's built-in builder path and do not require creating helper containers through the socket policy.

## Streaming And Hijack Semantics

Attach-like endpoints and other connection-hijacking flows should be denied in phase 1.

This is both a security decision and an implementation simplification:

- no upgraded or hijacked connection forwarding path is needed in the first phase
- the proxy can remain request/response oriented
- long-lived streaming channels that complicate audit and policy are excluded by default

## Audit And Reporting

Docker socket mediation should reuse the existing policy-mode and reporting model where practical.

Each decision should emit an access record containing at least:

- sandbox ID
- kind=`docker_socket`
- normalized operation
- HTTP method
- normalized path
- selected image reference or object ID when available
- allow or deny result
- status code
- policy mode
- policy violations or first deny reason

Suggested summary dimensions:

- operation
- image reference
- result
- sandbox

## Error Handling

Fail closed in all ambiguous cases.

Examples:

- unknown endpoint mapping -> deny
- malformed JSON body for a payload-aware operation -> deny
- body too large to inspect for a payload-aware operation -> deny
- unsupported transfer encoding on a payload-aware operation -> deny
- upstream daemon error after an allowed request -> return upstream error and audit it as an allowed request with upstream failure

For denied requests, return deterministic HTTP errors such as `403 Forbidden` with a short plaintext reason, consistent with the existing proxy service style.

## Testing Strategy

Add unit and integration coverage for:

- version-prefix stripping and endpoint-to-operation mapping
- default deny for unknown endpoints
- allow and deny rule ordering
- raw HTTP escape-hatch matching
- image reference allowlist matching
- `build` denial for remote contexts
- `build` denial for push/export outputs
- `build` allowance for local tar-stream contexts with approved Dockerfile paths
- denial of `exec_create` and `exec_start`
- denial of attach and archive endpoints
- per-sandbox audit logging
- mount/config wiring for the sandbox-visible proxy socket

When container creation is later introduced, add tests for privileged and host-mode container denial, plus start-only-for-approved-container-ID behavior.

## Implementation Notes

Recommended file layout, following the existing manager/service split:

- `docker_socket.go`
  - public API types
- `docker_socket_policy.go`
  - policy compilation and matching
- `docker_socket_proxy.go`
  - Unix socket listener and request forwarding
- `docker_socket_mapping.go`
  - endpoint normalization and operation mapping
- `docker_socket_build.go`
  - build-specific query/body parsing
- CLI config wiring in `cmd/bbox/config.go`

This should stay separate from the generic network proxy path. Reuse the existing policy compilation, audit, and manager lifecycle patterns, but keep Docker socket semantics isolated in their own module.

## Rollout

Phase 1:

- add config and public API surface
- stand up per-sandbox Docker socket proxy
- implement operation mapping and ordered policy evaluation
- support `image_pull`, `image_inspect`, and `build`
- deny `push`, `create`, `start`, `exec`, attach, archive, export, and daemon-admin paths
- add audit logging and tests

Phase 2:

- add payload-aware `container_create` policy
- track approved container IDs for gated `container_start`
- add more complete endpoint coverage where needed

Phase 3:

- decide whether a constrained dedicated build backend is required for stronger exfiltration guarantees during build execution

## Decision Summary

Proceed with a `bbox`-owned Docker socket proxy and a dedicated ordered Docker socket policy language that supports both high-level operations and raw HTTP escape hatches.

For the current use case, phase 1 should allow only `image_pull`, `image_inspect`, and `build`, deny `push`, `create`, `start`, and `exec`, and document clearly that build-time execution occurs on the daemon side and therefore requires additional controls if build-time network exfiltration must also be prevented.
