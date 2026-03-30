# The Hard Part of an Unprivileged Sandbox Is Not `bwrap`

An unprivileged sandbox sounds clean in conversation. You create a few namespaces, stage a root filesystem, and call it isolation. Then you try to run something useful inside it.

That is where the tidy version ends.

The interesting problem is not starting a process in `bubblewrap`. The interesting problem is deciding which capabilities cross the boundary, in what form, and under whose control. Filesystem access is one part of that story. Network access is where the story becomes less polite.

This repository takes a fairly strict position: the sandbox should stay unprivileged, the payload should stay untrusted, and outbound network access should remain a host-side decision. That sounds obvious. It is also where most “simple” designs begin to accumulate exceptions.

## Namespaces Are the Easy Part

At first glance, the model is straightforward.

Each sandbox gets its own user, PID, mount, and network namespaces. A staged root filesystem provides the binaries you asked for, plus the shared libraries and runtime files they actually need. `bwrap` binds that staged tree read-only, mounts fresh `/proc`, `/dev`, and `/tmp`, and then starts a long-lived helper inside the sandbox.

So far, so normal.

What should happen next is also obvious. Payload processes inside the sandbox should run with a restricted view of the world, and any network access should be filtered according to policy.

What actually happens is that “network access” is not a single thing. It is DNS resolution, TCP dialing, TLS trust, proxy semantics, HTTP version negotiation, and the steady stream of edge cases that arrive when software meets other software.

The namespace only gives you a place to stand. It does not tell you how to move traffic safely.

## The Boundary That Matters

The key design choice here is not the sandbox itself. It is the helper.

Each sandbox has one long-lived helper process running inside `bwrap`. That helper is the only component inside the namespace allowed to talk over the private bridge back to the host. Payload processes do not inherit that bridge file descriptor when commands are executed.

This matters more than it first appears.

If every payload process could directly reach the host-side control channel, the policy layer would quickly turn into an argument about message validation. By narrowing the bridge to a single in-sandbox component, the system keeps one capability crossing one boundary in one form. That is not glamorous. It is merely survivable.

The host-side `ProxyManager` is the trust anchor. It owns policy, outbound transports, audit state, certificate issuance for MITM mode, and sandbox registration. The helper is trusted to normalize traffic and launch commands. The payload is trusted to do none of those things.

That hierarchy is deliberate.

## Why the Policy Lives Outside

A common instinct is to enforce policy inside the sandbox. After all, that is where the process runs.

This is backwards.

If the sandbox can make its own outbound network decisions, the host has already given away the interesting capability. The clean version of “local enforcement” becomes a more complicated version of “please behave.” That may be acceptable for instrumentation. It is a weak place to anchor control.

This design keeps the authoritative decision on the host. The helper turns HTTP requests, `CONNECT` tunnels, and intercepted HTTPS traffic into structured messages on the bridge. The host manager looks up the per-sandbox policy, decides whether the request is allowed, and only then performs the real outbound request.

In other words, the sandbox does not get networking. It gets a request path.

That distinction is the whole point.

## The Awkward Reality of “Transparent” Networking

Explicit proxy mode is the easy story. Inject `HTTP_PROXY` and `HTTPS_PROXY`, bind a loopback proxy inside the sandbox, and let the helper forward requests to the host manager. It is not elegant, but it is honest.

Transparent mode looks better on a slide. No proxy environment variables. Just run the program and let it behave normally.

Naturally, it is less simple.

Because the sandbox is in its own network namespace, transparent mode still makes the helper impersonate the TCP entry points ordinary clients expect. The helper binds `127.0.0.1:80` for HTTP and `127.0.0.1:443` for HTTPS, while DNS no longer runs through a helper-owned daemon.

Instead, staging derives `resolv.conf` from the host nameserver configuration and seccomp-notify supervision forwards DNS socket activity through the managed path. DNS behavior remains policy-visible without introducing a separate in-sandbox DNS server lifecycle.

What should happen is simple: the client resolves `example.com`, connects to it, and the system applies policy.

What actually happens is narrower. This only works for hostname-based HTTP on `:80` and HTTPS on `:443`, with SNI available for TLS. IP literals are out. Non-default ports are out. QUIC is out. Arbitrary TCP is out. Applications that bypass the sandbox resolver are, predictably, out.

This is not a bug in the implementation. It is the cost of refusing privileged packet redirection tricks and still wanting something that feels transparent to ordinary clients.

The result is useful, but it is not magic. One should be careful with that word.

## MITM Is Not a Feature Add-On

For HTTPS, transparent mode forces an uncomfortable but important conclusion: once you stop relying on explicit proxy semantics, you do not get meaningful request policy from the tunnel alone.

You need the request.

That means terminating TLS in the helper, extracting the logical destination from SNI, minting a leaf certificate from a manager-owned ephemeral CA, and sending decrypted request metadata to the host for policy evaluation. The host then decides on method, host, path, headers, and a bounded request body before making the upstream request itself.

What should happen is that HTTPS remains opaque and policy remains simple.

What actually happens is that opaque HTTPS is only simple if you are willing to authorize tunnels at a much coarser level. This repository is not willing to do that for transparent mode. It requires MITM support and fails closed if trust injection or certificate issuance is unavailable.

That is a reasonable trade.

It is also a reminder that “transparent HTTPS policy” is usually shorthand for “we are doing TLS interception, but politely.”

## Staging Is Part of the Security Model

Sandbox write-ups often treat filesystem staging as setup work. Here it is part of the design.

The system does not bind broad slices of the host filesystem into the sandbox and call that practical. It resolves the requested binaries, walks their shared-library dependencies with `ldd`, copies the needed files into a per-sandbox root, and adds a small amount of runtime configuration such as `nsswitch.conf`, `hosts`, `resolv.conf` for transparent mode, and CA bundles when MITM is enabled.

That sounds operational. It is also about control.

A narrow staged root avoids the usual “temporary” bind mount that becomes permanent because somebody’s toolchain was inconvenient. Explicit read-only and read-write mounts are still supported, but they are treated as user decisions rather than ambient entitlement.

This is a better default. It is also more work.

## Why Not Just Join the Namespace From the Host?

There is a familiar temptation here too. Start the sandbox, join its network namespace from the host, and wire traffic from there.

The repository explicitly avoids that approach. For good reason.

Namespace joining sounds simpler because it preserves a single host-side control plane. In practice, it tends to create lifecycle and ownership problems in exactly the area where you want clarity. Which process owns the listeners. Which context defines readiness. Which side is allowed to fail independently. Which file descriptors cross where. These are not decorative questions.

Putting the ingress point inside the sandbox keeps the topology honest. Traffic enters where the sandbox can see it. Policy is evaluated where the host can enforce it. The bridge between them is narrow and explicit.

That is easier to reason about than a host process that keeps leaning into the child namespace to do one more thing.

## The Operational Payoff

The value of this model is not that it produces a perfect sandbox. It does not.

The value is that it gives you a legible capability graph. One helper per sandbox. One host manager for egress. One policy lookup per request. One place where audit state accumulates. One place where outbound requests actually happen.

That structure buys useful properties.

Multiple sandboxes can share the same host-side manager without sharing policy. Access attempts are logged per sandbox. HTTPS request policy can inspect real paths and headers rather than guessing from destination host alone. The payload process can be killed, restarted, or replaced without rebuilding the control plane around it.

These are boring advantages. They are usually the ones that survive contact with production.

## The Limits Are Not Embarrassing

Every sandbox design accumulates a list of things it does not handle. The interesting question is whether those limits are accidental or chosen.

The limits here are mostly chosen.

Transparent mode does not pretend to support arbitrary TCP. It does not pretend to understand HTTP/3. It does not quietly downgrade when TLS interception is required but unavailable. Request-body inspection is bounded rather than infinite. Privileged host networking tricks are left out on purpose.

That restraint is healthy.

An unprivileged sandbox is part of a larger system: process execution, dependency staging, DNS behavior, certificate trust, policy semantics, logging, and teardown. Once you see the problem at that level, the fashionable one-line answers begin to look underspecified.

## A More Useful Mental Model

The wrong mental model is “run a process in `bwrap` and then bolt policy onto it.”

The better model is “build a narrow transport and capability boundary around an isolated process, then decide which requests the host will honor.” The namespaces matter. The staged root matters. But the architecture lives in the boundary between the helper and the manager.

That is where the real sandbox is.

## Conclusion

An unprivileged sandbox is appealing because it appears to avoid the usual privilege-heavy machinery. Sometimes it does.

But removing privilege does not remove design pressure. It moves that pressure into naming, bridging, staging, DNS, TLS, and policy placement. The clean idea remains clean only if you ignore the part where real programs need to run.

This approach makes a sensible trade. Keep the sandbox small, keep the payload untrusted, keep egress authority on the host, and accept that transparent behavior will be narrower than the word suggests. That is not a universal answer.

It is, however, a serious one.
