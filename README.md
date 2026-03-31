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

## Policy Modes

`bbox` evaluates mediated traffic against `NetworkPolicy` in one of two modes:

- `enforce` is the default. A policy violation blocks the mediated request.
- `audit` evaluates the same policy but does not block mediated HTTP, CONNECT, MITM, DNS, or transparent traffic because of policy alone.

In both modes bbox still records what happened. Access log entries expose:

- `Allowed`: the real runtime outcome
- `PolicyAllowed`: whether the compiled policy would have allowed the request
- `PolicyViolations`: human-readable denial reasons when policy evaluation failed

That means an `audit` run can report `Allowed=true` and `PolicyAllowed=false` for the same request, while `enforce` can still log the violation that produced an HTTP `403` or other denial.

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

## CLI Reporting

The CLI defaults to `--policy-mode enforce`.

Use `--audit` when you want policy evaluation without policy enforcement. That flag is shorthand for:

- `--policy-mode audit`
- `--report-policy-violations`
- `--report-access-summary`
- `--report-request-summary`

You can also enable the reporting outputs independently in `enforce` mode:

- `--report-policy-violations` prints the grouped policy-denial reasons seen during the run
- `--report-access-summary` prints the host-level aggregate summary
- `--report-request-summary` prints the grouped request summary

Example:

```bash
bbox --audit --allowed-domain example.com -- curl -sS https://example.com
```
