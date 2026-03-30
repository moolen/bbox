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
2. deploy a `bridge` helper into the isolated sandbox which provides a way out for DNS, HTTP and HTTPS. no ICMP, raw TCP or UDP can leave
3. use `seccomp unotify` to intercept tcp/udp syscalls and point them at the `bridge`.
4. enforce network policies on the host side for HTTP, HTTPS and DNS traffic. 


