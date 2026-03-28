# Network Restriction Suite Design

## Goal

Add an extensive default-on integration test suite that proves sandbox payloads have heavily restricted outbound networking beyond bbox's intended egress path. The suite must be hermetic, run entirely against local fixtures, and cover both `proxy` and `transparent` traffic modes.

## Non-Goals

- adding new network restrictions in production code unless the tests prove a real gap
- relying on real internet access or public infrastructure
- replacing existing positive-path HTTP/HTTPS integration tests
- introducing custom probe binaries when stable host tools can exercise the same behaviors

## Current Context

bbox sandboxes already run in a private network namespace via bubblewrap `--unshare-net`. Existing integration coverage proves allowed and denied HTTP/HTTPS behavior through bbox-managed egress paths, but it does not yet systematically prove that other outbound networking primitives are blocked by default.

That missing coverage matters most after adding transparent mode, because the helper now owns low-port DNS/HTTP/HTTPS listeners inside the sandbox namespace. We need regression coverage that demonstrates those listeners do not accidentally widen general network reachability.

## Requirements

### Functional

The suite must verify that a sandbox payload cannot use the private network namespace for arbitrary outbound networking attempts, including:

- DNS lookups outside bbox's intended behavior
- ICMP echo traffic
- raw TCP connects that do not go through bbox-managed HTTP/HTTPS behavior
- raw UDP sends
- directed broadcast or other broadcast-style sends

The suite must exercise both:

- `TrafficModeProxy`
- `TrafficModeTransparent`

For proxy mode, the suite should prove blocked non-HTTP networking from the same sandbox. Existing allowed-path HTTP/HTTPS tests already cover the positive proxy flow and do not need to be duplicated here.

For transparent mode, the suite should prove:

- only the documented transparent HTTP/HTTPS behavior remains usable
- unrelated outbound networking primitives still fail

### Test Behavior

- hermetic only: no real remote endpoints
- default-on in `go test ./...`
- missing required host tools fail the test suite rather than skip
- blocked cases assert non-zero exit from the sandboxed command
- exact stderr strings are not the contract unless a tool-specific assertion is unusually stable and valuable

## Proposed Approach

Use a single matrix-driven integration suite plus a small shared helper layer.

### Why this approach

- keeps all "blocked outbound networking" assertions in one place
- avoids duplicating sandbox setup between protocol families
- makes adding future blocked vectors straightforward
- stays aligned with the existing integration-test style

## Test Architecture

### New Integration File

Add one primary file:

- `integration/network_restriction_test.go`

This file will define a table of protocol probes and expected blocked behavior, then run that matrix for both traffic modes where applicable.

### Shared Helper Additions

Extend:

- `integration/test_helpers_test.go`

with helpers for:

- resolving required host tools up front
- building sandbox option presets for `proxy` vs `transparent`
- asserting blocked command outcomes consistently
- provisioning hermetic local listeners for TCP/UDP/broadcast-style targets

## Coverage Matrix

The suite should cover at least these probe families.

### 1. DNS

Intent: prove payloads cannot use arbitrary DNS as a general egress channel.

Probe form:

- use a host DNS client tool such as `dig` or `nslookup`
- target a non-loopback resolver address in the sandbox, for example `8.8.8.8`
- also include a TCP DNS attempt if the tool supports it

Expected result:

- non-zero exit

Mode notes:

- proxy mode: should fail because no direct DNS egress exists
- transparent mode: should also fail for arbitrary external resolver access; only bbox's local DNS listener is intended

### 2. ICMP

Intent: prove the payload cannot emit ordinary ping traffic.

Probe form:

- `ping -c 1 -W 1 127.0.0.2` or another hermetic local-only target outside the helper listeners

Expected result:

- non-zero exit

Rationale:

- this checks raw non-TCP/UDP networking rather than bbox-managed HTTP behavior

### 3. Raw TCP

Intent: prove payloads cannot open arbitrary TCP sockets to local listeners unless the traffic is going through bbox's supported ingress.

Probe forms:

- `nc -zv 127.0.0.1 <ephemeral-port>`
- `nc -zv 127.0.0.2 <ephemeral-port>` when useful for namespace isolation

Fixture:

- hermetic host-side TCP listener started by the test

Expected result:

- non-zero exit

Mode notes:

- proxy mode: raw TCP must fail
- transparent mode: raw TCP to arbitrary ports must fail; transparent mode only supports hostname-based HTTP `:80` and HTTPS `:443`

### 4. Raw UDP

Intent: prove payloads cannot send arbitrary UDP datagrams.

Probe form:

- `nc -u -w 1 127.0.0.1 <ephemeral-port>` or `socat - UDP:<addr>:<port>` depending on available tool contract

Fixture:

- hermetic host-side UDP listener started by the test

Expected result:

- non-zero exit

### 5. Broadcast / Directed Broadcast

Intent: prove payloads cannot use broadcast-style traffic as an escape hatch.

Probe form:

- UDP send to `255.255.255.255:<port>` or another stable broadcast-style destination supported by the chosen tool

Expected result:

- non-zero exit

Notes:

- the assertion is the command failing, not packet capture
- if one host tool has unstable behavior for broadcast sends, prefer the tool with the cleanest deterministic failure in CI and local Linux environments

## Tooling Contract

The suite will depend on host tools and fail if they are missing. That is intentional.

Required tools should be resolved at test startup with clear errors. Likely initial set:

- `curl`
- `ping`
- `dig` or `nslookup`
- `nc`

The exact final list should prefer the smallest set that covers the protocol matrix cleanly.

If a tool is unavailable:

- fail the relevant test immediately with a clear message
- do not silently skip

## Mode Strategy

### Proxy Mode

Use a sandbox configured with:

- default `TrafficModeProxy`
- strict allow policy only for bbox-supported HTTP methods/hosts where needed by setup

The restriction suite should not re-prove generic allowed HTTP flow; instead it should prove that direct DNS, ICMP, raw TCP, raw UDP, and broadcast attempts still fail from the payload.

### Transparent Mode

Use a sandbox configured with:

- `TrafficModeTransparent`
- manager-wide MITM enabled

Transparent-specific restriction checks should ensure:

- allowed transparent HTTP/HTTPS behavior is not widened into arbitrary TCP/UDP access
- IP literals and non-default ports remain unusable
- raw protocol attempts remain blocked

## Assertions

### Primary Assertion

For blocked probes, assert:

- sandbox run itself completes
- command exit code is non-zero

This keeps the suite robust across small stderr wording differences between distributions and tool versions.

### Secondary Assertion

Where a tool produces a stable and meaningful signal without making the test brittle, allow a light stderr/stdout sanity check such as "some output was produced" or "connection failed". These checks are optional and should never be the core contract.

## Hermetic Fixtures

All fixtures stay local to the test process:

- host-side TCP listener on ephemeral port
- host-side UDP listener on ephemeral port
- existing transparent-mode low-port listeners where required

No test may depend on:

- public DNS
- public IP connectivity
- third-party services
- route availability outside the local machine

## Failure Model

If the suite fails, the failure should answer one of these questions clearly:

- a payload gained direct network reachability it should not have
- transparent-mode ingress accidentally permits unsupported traffic
- a required host-tool contract changed or is missing

This suite is intentionally conservative. False positives from brittle stderr assertions are worse than broad non-zero exit assertions, because they reduce trust in the security signal.

## Implementation Notes

- prefer table-driven tests with `mode`, `probe name`, `argv`, and `setup`
- keep per-probe setup isolated so one failure does not contaminate later probes
- reuse existing sandbox/test helper patterns rather than building a second integration harness
- when transparent-mode tests require low ports, continue to fail explicitly if the environment cannot provide them
- if the suite discovers a real production gap, fix the product code in a separate task inside the same plan rather than weakening the test

## Testing Strategy

### Targeted Commands

At minimum, implementation should support focused verification with:

```bash
go test ./integration -run 'TestNetworkRestrictionsProxyMode|TestNetworkRestrictionsTransparentMode' -v
```

### Full Verification

The suite must pass in:

```bash
go test ./...
```

## File Plan

- Create: `integration/network_restriction_test.go`
- Modify: `integration/test_helpers_test.go`
- Possibly modify: existing integration helper files only if a small refactor is needed to share mode-aware sandbox setup cleanly

## Open Questions Resolved

- hermetic vs external: hermetic
- host tools vs custom clients: host tools
- blocked assertion strictness: non-zero exit is the contract
- missing tools: fail, do not skip
- default-on vs opt-in: default-on
- proxy-mode positive HTTP rechecks: unnecessary here; focus on blocked direct network attempts
