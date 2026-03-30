# Single-Binary `bbox` Design

**Date:** 2026-03-30

## Goal

Ship `bbox` as a single user-facing binary while keeping exactly one on-disk executable inside the sandbox. The helper role should become an internal execution mode of `bbox`, and the seccomp launcher should execute from an anonymous `memfd` rather than a staged file.

## Non-Goals

- Rewriting the seccomp launcher logic from C into Go.
- Supporting non-Linux hosts.
- Preserving separate `bbox-helper` or `bbox-seccomp-launcher` release artifacts.
- Eliminating the launcher process entirely.

## Current State

Today the host resolves or builds two sibling binaries:

- `bbox-helper`
- `bbox-seccomp-launcher`

Sandbox staging copies both into the root filesystem:

- `/app/bbox-helper`
- `/app/bbox-seccomp-launcher`

At runtime the helper later resolves the launcher as a sibling executable beside itself. This works, but it means release bundles and local development flows still depend on multiple executables.

## Requirements

- End users should ship only `bbox`.
- The sandbox filesystem should contain only one executable on disk: `/app/bbox`.
- Transparent mode must continue to use the existing small C launcher design for seccomp unotify setup before `execve()`.
- Proxy mode and transparent mode must keep the same externally visible behavior.
- Local development and release builds must stay deterministic.

## Options Considered

### Option 1: Full self-reexec in Go

Use `bbox` for the CLI, helper, and launcher roles, with hidden internal modes for the latter two.

Pros:

- Pure single-executable architecture.
- Simplest runtime packaging model.

Cons:

- Requires rewriting the launcher logic in Go.
- Highest regression risk around seccomp notify setup and fd passing.

### Option 2: Helper in `bbox`, launcher from `memfd`

Use `bbox` for the CLI and helper roles. Embed the existing static C launcher payload in `bbox` and execute it from an anonymous `memfd`.

Pros:

- Only one shipped binary.
- Only one on-disk executable inside the sandbox.
- Preserves the proven launcher implementation.
- Minimizes changes to the seccomp notify handshake.

Cons:

- Requires a launcher materialization layer around `memfd_create` and fd-based exec.
- Adds Linux runtime assumptions for fd-exec support.

### Option 3: Full fd-only fanout

Run helper and launcher entirely from anonymous fds.

Pros:

- Maximum packaging purity.

Cons:

- Unnecessary complexity.
- Worse debuggability and operability.

## Chosen Approach

Choose **Option 2**.

`bbox` becomes a multi-role executable:

- normal CLI mode
- hidden `internal-helper` mode

The seccomp launcher remains a small C program, but it is no longer staged as `/app/bbox-seccomp-launcher`. Instead, `bbox` embeds per-architecture launcher bytes and the helper executes those bytes from an anonymous `memfd`.

This keeps the runtime model simple without rewriting the highest-risk part of the system.

## Architecture

### 1. Host entrypoint

The existing `cmd/bbox` binary becomes the only public executable. It continues to parse CLI flags and create sandboxes exactly as it does today.

### 2. Internal helper mode

The code currently in `cmd/bbox-helper/main.go` moves behind an internal entrypoint callable from `bbox`.

Instead of launching `/app/bbox-helper`, `bwrap` launches:

`/app/bbox internal-helper ...`

This keeps the helper role explicit while removing the separate helper binary entirely.

### 3. Embedded launcher assets

Build-time steps produce static `bbox-seccomp-launcher` payloads for supported architectures. Those payloads are embedded into the `bbox` binary.

At minimum:

- `linux/amd64`
- `linux/arm64`

The embedded bytes are selected at runtime using the current architecture of the helper process.

### 4. Memfd launcher execution

When transparent mode prepares a payload exec:

1. create an anonymous `memfd`
2. write the embedded launcher bytes to that fd
3. make the fd executable as required by the kernel path used
4. execute the launcher from the fd

The launcher then performs the existing socketpair handshake, installs the seccomp notify filter, passes the notify fd back to the helper, and `execve()`s the real payload.

### 5. Staging model

Sandbox staging copies only:

- `/app/bbox`

No `/app/bbox-helper` is staged.
No `/app/bbox-seccomp-launcher` is staged.

All helper startup and payload supervision flows must be updated to assume `/app/bbox` is the only runtime executable.

## Data Flow

### Sandbox startup

1. Host resolves the current `bbox` executable.
2. Staging copies that executable into the sandbox root as `/app/bbox`.
3. `bwrap` starts `/app/bbox internal-helper ...`.
4. Internal helper mode starts the bridge, ingress, DNS, and request handling logic.

### Transparent payload execution

1. Helper receives an exec request.
2. Seccomp supervisor prepares a launcher socketpair.
3. Supervisor materializes the embedded launcher into an anonymous `memfd`.
4. Supervisor executes the launcher from the fd.
5. Launcher installs seccomp notify and returns the notify fd.
6. Helper serves notifications while the payload runs.

## Error Handling

The system must fail closed with clear errors for:

- unsupported architecture for embedded launcher selection
- inability to create or write the launcher `memfd`
- inability to execute the launcher from the fd
- mismatch between expected and actual helper mode invocation
- missing embedded launcher asset for a release build

Transparent mode should continue to refuse to run when the launcher path cannot be initialized.

## Testing Strategy

### Unit tests

- `bbox` dispatches into internal helper mode correctly.
- helper resolver prefers the current executable rather than sibling helper binaries.
- staging copies only `/app/bbox`.
- launcher asset lookup selects the correct embedded payload.
- runtime tests verify the supervisor no longer depends on a sibling launcher path.

### Integration tests

- proxy mode still runs payloads successfully with only `/app/bbox` staged.
- transparent mode still passes the current seccomp notify integration suite.
- release archive verification confirms each bundle contains only `bbox`.

### Build verification

- release builds must embed the correct launcher payloads per architecture.
- local and CI smoke flows must verify the embedded-launcher path, not an accidental fallback to sibling binaries.

## Release Impact

Release archives should stop shipping:

- `bbox-helper`
- `bbox-seccomp-launcher`

They should ship only:

- `bbox`

The runtime must not rely on a local Go toolchain for helper or launcher reconstruction in release use.

## Migration Plan

1. Introduce internal helper mode in `bbox`.
2. Change staging and sandbox startup to use `/app/bbox`.
3. Add embedded launcher asset generation and selection.
4. Replace sibling launcher lookup with `memfd` execution.
5. Remove separate helper/launcher release packaging and verification expectations.
6. Delete obsolete sibling-binary fallback logic once tests prove the new path.

## Risks

- `memfd` execution semantics can be subtle across kernels and libc assumptions.
- If the embedded launcher build pipeline is not deterministic, releases may drift by architecture.
- Some tests currently assume the launcher exists as a file path and will need careful refactoring.

## Recommendation

Proceed with the helper-in-`bbox`, launcher-from-`memfd` architecture. It is the smallest change that fully satisfies the single-binary and single-on-disk-executable requirements without reimplementing the seccomp launcher in Go.
