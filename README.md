# bbox 📦

A linux sandbox to enforce network access policies.

> ⚠️ **Work in progress:** bbox is a experiment and not for production use


### Why does `bbox` exist? 

I want restrict egress traffic of an untrusted process. When running AI agents autonomously (in CI, with a controller pattern) the network paths are predictable. The existing options to lock down egress traffic have shortcomings and trade-offs i didn't want to accept.

- `HTTP_PROXY` semantics rely on 1) clients behaving correctly and 2) having a second network boundary outside the realm of the client. This makes deployment more complex, and especially when intercepting TLS the management and orchestration of TLS CA certificaes, private keys and injecting trust is a process burden.
- CNI such as cilium or calico which implement host-based rules are great, but requires you to have and maintain a Kubernetes cluster. That's a lot of overhead if you don't have one at hand.
- Landlock provides mechanisms to lock down TCP `connect()` calls help, but support for Landlock is not that wide spread.

## Overview

How it works:
1. use bubblewrap to create a sandbox for pid/mount/network etc. This sandbox has not network connectivity to the host. CA trust is injected into the sandbox, so we are able to terminate TLS and inspect traffic.
2. stage a single `bbox` binary into the isolated sandbox. it re-enters hidden internal helper mode to provide a way out for DNS, HTTP and HTTPS. no ICMP, raw TCP or UDP can leave
3. use `seccomp unotify` to intercept tcp/udp syscalls and point them at the `bridge`.
4. enforce network policies on the host side for HTTP, HTTPS and DNS traffic. 

## Packaging

`bbox` ships as a single linux binary. the transparent seccomp launcher is embedded into `bbox` and executed from an anonymous `memfd`, so release archives and the sandbox filesystem only need `/app/bbox`.

## CLI Configuration (`bbox.yaml`)

`bbox` loads CLI configuration from a `bbox.yaml` file discovered from your current working directory.

Discovery order:
1. `./bbox.yaml` (current working directory)
2. first parent directory containing `bbox.yaml`
3. continue upward until filesystem root
4. if none is found, run with built-in defaults

If `bbox.yaml` is found in a parent directory, relative paths in `workdir`, `mount_ro`, and `mount_rw` are resolved relative to the directory containing that `bbox.yaml`.

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
  allow_host_patterns:
    - "^api[.]example[.]com$"
  allow_http_methods:
    - POST
  allow_connect: true
```

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
- removed: `--deny-domain`
- removed: `--allow-http-method`
- removed: `--mitm`

Use `bbox.yaml` `policy:` to define allow/deny behavior, and keep runtime flags for execution/reporting behavior.

The `--audit` flag remains available and forces reporting summaries on for that run.
