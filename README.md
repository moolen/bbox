# bbox 📦

A sandbox to enforce network access policies.

> ⚠️ **Work in progress:** bbox is a experiment and not for production use


### Why does `bbox` exist? 

I want restrict egress traffic of an untrusted process. When running AI agents autonomously (in CI, with a controller pattern) the network paths are predictable. The existing options to lock down egress traffic have shortcomings and trade-offs i didn't want to accept.

- `HTTP_PROXY` semantics rely on 1) clients behaving correctly and 2) having a second network boundary outside the realm of the client. This makes deployment more complex, and especially when intercepting TLS the management and orchestration of TLS CA certificaes, private keys and injecting trust is a process burden.
- CNI such as cilium or calico which implement host-based rules are great, but requires you to have and maintain a Kubernetes cluster. That's a lot of overhead if you don't have one at hand.
- Landlock provides mechanisms to lock down TCP `connect()` calls help, but support for Landlock is not that wide spread.

## Overview

How it works:
1. On Linux, use bubblewrap to create a sandbox for pid/mount/network etc. This sandbox has no network connectivity to the host. CA trust is injected into the sandbox, so we can terminate TLS and inspect traffic.
2. On Linux, stage a single `bbox` binary into the isolated sandbox. it re-enters hidden internal helper mode to provide a way out for DNS, HTTP and HTTPS. no ICMP, raw TCP or UDP can leave.
3. On Linux transparent mode, use `seccomp unotify` to intercept tcp/udp syscalls and point them at the `bridge`.
4. On macOS, launch the payload under `sandbox-exec` with a generated Seatbelt profile and route proxy-mode traffic through a host-side helper proxy bound to loopback.
5. Enforce network policies on the host side for HTTP, HTTPS and DNS traffic.

## Packaging

`bbox` ships as a single binary on Linux and macOS.

On Linux, the transparent seccomp launcher is embedded into `bbox` and executed from an anonymous `memfd`, so release archives and the sandbox filesystem only need `/app/bbox`.

On macOS, `bbox` supports the same `bbox.yaml` shape, but the first backend is intentionally narrower:

- supported: `traffic_mode: proxy`, `policy.rules`, `workdir`, `env`, `clear_env`, access logging, audit mode
- rejected explicitly on Darwin: `traffic_mode: transparent`, `mount_ro`, `mount_rw`, seccomp options

`bin` remains part of the config on macOS, but it is interpreted as an executable allowlist for the Seatbelt profile instead of Linux staging metadata.

## CLI Configuration (`bbox.yaml`)

`bbox` loads CLI configuration from a `bbox.yaml` file discovered from your current working directory.

Discovery order:
1. `./bbox.yaml` (current working directory)
2. first parent directory containing `bbox.yaml`
3. continue upward until filesystem root
4. if none is found, run with built-in defaults

If `bbox.yaml` is found in a parent directory, relative paths in `workdir`, `mount_ro`, and `mount_rw` are resolved relative to the directory containing that `bbox.yaml`.

`docker_socket.target_socket_path` is a host path and must be absolute. `docker_socket.mount_path` is the in-sandbox socket location and must also be absolute.

The CLI resolves the payload command and any explicit `bin` entries against the effective sandbox `PATH`. By default that comes from the inherited host environment. You can override it with `env: ["PATH=..."]` in `bbox.yaml` or `--env PATH=...` on the CLI. If you also set `clear_env: true`, set `PATH` explicitly if you still want command-name lookup inside the sandbox.

On Linux, bbox also adds read-only mounts for the effective `PATH` roots so those command lookups can keep working at runtime. For entries under `/usr`, this collapses to a single `/usr` mount. For non-root `.../bin` and `.../sbin` entries, bbox mounts the parent directory instead.

On macOS, bbox does not mirror the Linux PATH mount behavior. Instead, the resolved payload command plus any explicit `bin` entries are used to build the generated Seatbelt executable allowlist.

Example:

```yaml
name: demo-sandbox
workdir: ./workspace
bin:
  - curl
mount_ro:
  - ./certs:/etc/ssl/certs
mount_rw:
  - ../shared:/workspace/shared
env:
  - API_TOKEN=redacted
clear_env: false
traffic_mode: proxy # or transparent
max_request_body_bytes: 65536
access_log: json # json or off
report_policy_violations: true
report_access_summary: true
report_request_summary: true
policy:
  rules:
    - host_patterns:
        - "^api[.]example[.]com$"
      http_methods:
        - POST
    - host_patterns:
        - "^api[.]example[.]com$"
      connect_ports:
        - "443"
docker_socket:
  enabled: true
  mount_path: /var/run/docker.sock
  target_socket_path: /var/run/docker.sock
  default_action: deny
  rules:
    - action: allow
      operations:
        - image_pull
    - action: allow
      operations:
        - image_inspect
    - action: allow
      operations:
        - build
      build:
        context: local_only
        dockerfile_paths:
          - "^Dockerfile$"
          - "^docker/.*$"
    - action: deny
      operations:
        - image_push
        - exec_create
        - exec_start
```

On macOS, omit `mount_ro`, `mount_rw`, and `traffic_mode: transparent`. Those settings are Linux-only today and fail with explicit runtime errors on Darwin.

## Docker Socket Mediation

When `docker_socket.enabled: true` is set, `bbox` does not mount the real host Docker socket into the sandbox. It creates a sandbox-specific Unix socket proxy on the host, mounts that proxy socket into the sandbox, normalizes Docker Engine API requests, evaluates them against the configured Docker socket policy, and only then forwards allowed requests to the real daemon socket.

Phase 1 supports these normalized operations:

- `image_pull`
- `image_inspect`
- `build`

Phase 1 denies other Docker endpoints by default. In particular, the intended default posture is to deny:

- `image_push`
- `container_create`
- `container_start`
- `exec_create`
- `exec_start`
- attach, archive, export, daemon-admin, and unknown endpoints

The Docker socket policy is separate from `policy:` because Docker authorization decisions are based on Docker operations and selected request payload semantics rather than remote hostnames.

Current build enforcement is intentionally narrow:

- local tar-stream build contexts can be allowed
- remote build contexts are denied
- push and export semantics on `POST /build` are denied
- Dockerfile paths can be allowlisted with regexes

Important limitation: allowing `docker build` does not preserve `bbox` network isolation by itself. Build steps execute on the Docker daemon or BuildKit side, not inside the `bbox` sandbox, so build-time network exfiltration still depends on daemon-side controls outside this proxy.

## Rootless `docker build` Inside `bbox`

On Linux, `bbox` can also stage a rootless BuildKit toolchain into the sandbox and expose a narrow `docker build` compatibility shim. This keeps the build itself inside the existing `bbox` proxy-mode egress boundary instead of sending the build to a host Docker daemon.

Current scope and trade-offs:

- supported today: `docker build`
- supported flags: `-f`, `-t`, `--build-arg`, `--target`
- network mode: proxy mode only
- proxy handling: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase variants are forwarded into the build as build args
- output: OCI archive written to `.bbox-docker-build.oci.tar` in the sandbox working directory

Required host prerequisites:

- `bwrap`
- `podman`
- `buildkitd`
- `buildctl`
- `runc`
- `newuidmap`
- `newgidmap`
- subordinate ID mappings for the current user in `/etc/subuid` and `/etc/subgid`

Current limitation: this path relies on proxy-aware build steps. `bbox` remains the network policy engine, but the in-sandbox builder currently runs in proxy mode rather than transparent mode. Workloads that ignore proxy environment variables are not yet supported by this builder path under strict policy.

The integration suite now includes a live default-path verification that clones `github.com/moolen/spectre` and builds its provided `Dockerfile` inside `bbox` using the `builder` target. The test fails hard when the Linux/rootless builder prerequisites above are missing.

Merge precedence is:
1. CLI defaults
2. `bbox.yaml` (if present)
3. supported runtime flags that are explicitly set on the CLI override file values (for example `--name`, `--workdir`, `--bin`, `--mount-ro`, `--mount-rw`, `--env`, `--clear-env`, `--max-request-body-bytes`, `--traffic-mode`, reporting flags, and `--access-log`)
4. `--audit` (forces audit reporting on)

If no `bbox.yaml` is present, bbox still defaults to audit-first behavior:
- policy mode is `audit`
- `report_policy_violations`, `report_access_summary`, and `report_request_summary` are enabled
- `traffic_mode` defaults to `proxy`
- `access_log` defaults to `json`
- HTTPS `CONNECT` is allowed on port `443`

Use `--print-policy` to print the final merged manager+sandbox configuration before execution.

Example:

```bash
bbox --print-policy --report-access-summary=false -- curl -sS https://example.com
```

The printed JSON includes merged file settings plus final flag state.

## Library Reporting

Existing code can keep using `Sandbox.AccessedDomains()`. It returns the compatibility host-level snapshot: normalized host, attempts, last result, last error, last port, and high-level protocol flags such as `HTTPSeen` or `ConnectSeen`.

`Sandbox.AccessSummary()` is the richer reporting API. It returns:

- `Hosts`: host-level aggregates plus policy counters and `DNSSeen`
- `Requests`: grouped request rows keyed by request kind, host, port, method, and path where those fields exist

Typical usage:

```go
summary := sandbox.AccessSummary()
for _, req := range summary.Requests {
	log.Printf("%s %s:%d %s %s attempts=%d", req.Kind, req.Host, req.Port, req.Method, req.Path, req.Attempts)
}
```

If you need per-attempt reporting instead of aggregates, inject an `AccessLogger` through `ProxyOptions`.

## CLI Flags

Current policy-shaping CLI flags were intentionally removed in favor of config-file policy definition:

- removed: `--policy-mode`
- removed: `--allowed-domain`
- removed: `--allowed-domains-file`
- removed: `--deny-domain`
- removed: `--allow-connect`
- removed: `--allow-connect-port`
- removed: `--allow-http-method`
- removed: `--allow-path`
- removed: `--deny-path`
- removed: `--mitm`

Use `bbox.yaml` `policy:` to define allow/deny behavior, and keep runtime flags for execution/reporting behavior.

The `--audit` flag remains available and forces reporting summaries on for that run.
