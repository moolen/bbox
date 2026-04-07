# Docker Build Proxy-Mode Design

## Goal

Make `bbox` rootless `docker build` work reliably when the sandbox itself runs in `traffic_mode: proxy`.

Success means:

- proxy-aware tools used inside Dockerfile `RUN` steps work under the bbox proxy boundary
- non-proxy-aware network clients fail closed in proxy mode
- multi-stage builds remain supported
- the default integration coverage is synthetic, deterministic, and exercises the supported runtime and tool matrix directly

This design does not try to make arbitrary direct TCP/UDP networking work in proxy mode. That remains the job of `traffic_mode: transparent`.

## Problem

The current rootless BuildKit path can build successfully in transparent mode because bbox intercepts traffic below the application layer and the docker-build shim injects trust for MITM TLS handling.

Proxy mode has a different requirement: build steps only work if the actual network clients inside `RUN` honor `HTTP_PROXY` / `HTTPS_PROXY` and trust the bbox MITM CA. The current implementation forwards proxy variables as build args, but proxy-mode support is not treated as a first-class, verified contract. Coverage is also anchored to a live upstream repository (`github.com/moolen/spectre`), which is slower and less deterministic than a purpose-built fixture.

## Requirements

### Functional

- `traffic_mode: proxy` must support rootless `docker build`
- supported Dockerfile `RUN` networking in proxy mode includes at least:
  - `curl`
  - `wget`
  - `npm`
  - `pip`
  - `go`
- supported builds must include multi-stage Dockerfiles
- the final stage must be able to consume artifacts copied from earlier stages
- the builder must continue to respect the sandbox network policy
- non-proxy-aware clients must fail closed in proxy mode

### Verification

- the default integration test path must hard-fail when prerequisites are missing
- the existing Spectre integration test must be replaced with a synthetic multi-stage integration
- proxy-mode integration must prove real network access through bbox, not just local mocks
- transparent-mode coverage must keep working

### Non-goals

- making arbitrary non-proxy-aware clients work in proxy mode
- preserving the real Spectre repository clone as the default builder verification path
- expanding supported Docker CLI surface beyond the current `docker build` shim

## Recommended Approach

Keep the existing rootless BuildKit architecture and make proxy-mode behavior explicit and deterministic.

The key design choice is to support two builder networking models that match the enclosing bbox sandbox mode:

- `traffic_mode: transparent`
  - no proxy env should be required inside build steps
  - network enforcement stays below the application layer
- `traffic_mode: proxy`
  - proxy env must be present and trusted inside build steps
  - only proxy-aware clients are supported
  - no alternate fallback path should exist for direct egress

This preserves one builder implementation while keeping the trust boundary simple: bbox remains the only network policy engine, and the sandbox mode determines whether applications must be proxy-aware.

## Architecture

### 1. Builder runtime env must be mode-aware

The docker-build shim already runs `buildkitd` and `buildctl` inside the sandbox. In proxy mode, their runtime env must remain compatible with the proxied sandbox model:

- keep proxy vars available where the builder runtime and executor path need them
- do not strip proxy vars in proxy mode
- keep the current transparent behavior where direct proxy env is unnecessary

The dormant `BBOX_DOCKER_BUILD_PROXY_ARGS_ONLY` behavior should not define the supported product shape anymore. If retained for narrow internal use, it must not be active for the normal proxy-mode builder path.

### 2. Build-step env must remain proxy-aware

For proxy mode, bbox should continue to forward:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `NO_PROXY`
- lowercase variants

into BuildKit as build args.

That matches Docker and BuildKit expectations for proxy-aware `RUN` steps and keeps user intent aligned with the existing sandbox env model.

### 3. TLS trust must be injected automatically

The current Dockerfile rewrite path should remain the basis for trust injection:

- copy the staged trust bundle into common Linux trust locations
- set `SSL_CERT_FILE`
- set `NODE_EXTRA_CA_CERTS`
- set `NPM_CONFIG_CAFILE`

This is sufficient for the currently known tool matrix to trust bbox MITM TLS without requiring upstream Dockerfile edits.

If later ecosystems need extra env or filesystem trust locations, that should extend this same rewrite path rather than introducing per-tool ad hoc handling elsewhere.

### 4. Fail-closed behavior is a feature

Proxy mode must not attempt transparent rescue behavior for clients that ignore proxy env.

If a client does not honor proxy settings, the build should fail because:

- bbox only exposes proxied HTTP(S) egress in proxy mode
- DNS and direct socket behavior remain constrained by the sandbox model

This makes the support contract crisp:

- proxy-aware clients succeed
- non-proxy-aware clients fail closed

## Synthetic Integration Fixture

Replace the live Spectre clone integration with a synthetic multi-stage Dockerfile generated inside the test.

### Fixture shape

The generated build context should include:

- a `curl` stage
  - performs an HTTPS fetch with `curl`
- a `wget` stage
  - performs an HTTPS fetch with `wget`
- a `node` stage
  - performs an `npm` networked operation such as `npm view` or `npm install`
- a `python` stage
  - performs a `pip` networked operation
- a `golang` stage
  - performs `go mod download`
- a final stage
  - copies artifacts from the earlier stages
  - verifies that the overall multi-stage solve succeeds

The fixture should prefer small real operations over large dependency trees so the test remains stable and reasonably fast.

### Positive integration

The proxy-mode success test should:

- create a bbox manager without transparent mode
- create a sandbox with `traffic_mode: proxy`
- enable `docker_build`
- run `docker build .`
- assert exit code zero
- assert the OCI output tar exists

The allowlist should only contain the hosts required by the synthetic fixture, for example package registries and any file download origins actually used by the selected commands.

### Negative integration

A separate proxy-mode integration should intentionally use a non-proxy-aware network client or direct-socket pattern in a Dockerfile `RUN` step and assert failure.

This test exists to prove fail-closed semantics, not just success semantics.

The test should assert:

- non-zero build exit code
- stderr contains a networking failure or policy-relevant failure mode
- no alternate successful egress path exists

## Migrating the Existing Spectre Integration

`integration/docker_build_spectre_test.go` should stop cloning `github.com/moolen/spectre` and instead become the default synthetic multi-stage docker-build integration.

Reasons:

- it removes external repo shape drift from the default test path
- it makes supported ecosystems explicit
- it gives better failure localization
- it covers more of the intended support matrix than Spectre alone

If real-world regression coverage is still useful later, it should be reintroduced as a separate opt-in integration test, not the default hard-failing path.

## Error Handling

The docker-build path should preserve enough BuildKit stderr to distinguish these classes of failure:

- proxy env not propagated
- trust bundle not applied
- policy deny on an unexpected host
- supported tool ignored proxy unexpectedly
- expected fail-closed negative case

The builder implementation should avoid silent fallback behavior. If proxy mode is selected, observed success should always be attributable to normal proxy-aware behavior, not to accidental direct egress.

## Trade-offs

### Benefits

- keeps one rootless builder architecture
- aligns behavior with bbox sandbox mode semantics
- gives deterministic default coverage across multiple ecosystems
- makes the support contract explicit

### Costs

- some ecosystem-specific trust handling may continue to accumulate in the Dockerfile rewrite path
- proxy-mode support remains intentionally limited to clients that honor proxy env
- synthetic fixture maintenance becomes part of the test surface

## Testing Strategy

Fresh verification for this work should include:

- docker-build unit tests around proxy-env planning and trust injection
- focused CLI/config tests if mode-sensitive config behavior changes
- proxy-mode positive integration for the synthetic multi-stage Dockerfile
- proxy-mode negative integration for fail-closed unsupported clients
- existing transparent-mode docker-build coverage

## Acceptance Criteria

The work is complete when all of the following are true:

- proxy-mode `docker build` succeeds for the synthetic multi-stage fixture
- the fixture exercises `curl`, `wget`, `npm`, `pip`, and `go`
- the final stage consumes outputs from earlier stages
- a separate proxy-mode negative test proves non-proxy-aware clients fail closed
- transparent-mode builder integration still passes
- the README and example guidance describe proxy-mode and transparent-mode expectations accurately
