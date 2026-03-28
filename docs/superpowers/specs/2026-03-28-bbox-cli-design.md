# Bbox CLI Design

**Date:** 2026-03-28

**Status:** Draft approved in conversation, implementation in progress

## Goal

Add a real end-user `bbox` CLI that lets users run arbitrary commands inside a `bubblewrap` sandbox backed by the existing `bbox` host-side policy engine.

Primary use case:

- run interactive commands, shells, and AI agents inside the sandbox
- keep stdin/stdout/stderr wired through naturally
- make network policy setup easy, especially hostname allowlists loaded from a file

Example target UX:

```bash
bbox --allowed-domains-file allowed.txt -- opencode run 'network test: try to reach example.com and github.com'
```

## Non-Goals

This change does not include:

- non-Linux support
- a multi-subcommand orchestration CLI beyond the initial run-focused command
- policy persistence or profile management
- response-body inspection configuration beyond the existing library MITM knob
- arbitrary TCP interception beyond the library's existing transparent-mode scope

## User-Facing Behavior

`bbox` is a Cobra-based CLI rooted at `cmd/bbox`.

Behavior:

- flags configure one sandbox instance and one payload execution
- payload argv starts after `--`
- the command exits with the payload exit code when execution starts successfully
- stdin, stdout, and stderr are passed through live so interactive tools remain usable
- when the caller has a TTY, the sandboxed payload should observe a functional terminal session rather than a pipe-only environment

Defaults:

- traffic mode defaults to `proxy`
- filesystem mode defaults to convenience
- the current working directory is bind-mounted read-write at the same absolute path
- the sandbox workdir defaults to the caller's current working directory
- proxy-mode runs inject `HTTP_PROXY` / `HTTPS_PROXY`
- transparent mode remains opt-in

## Domain File Format

`--allowed-domains-file` accepts a text file with:

- one host or wildcard entry per line
- blank lines ignored
- lines beginning with `#` ignored

Examples:

- `example.com`
- `api.github.com`
- `*.github.com`

These entries are converted into anchored regex patterns for `NetworkPolicy.AllowHostPatterns`.

Rules:

- literal hosts match exactly one hostname
- `*.example.com` matches subdomains under `example.com`, but not the bare apex
- malformed entries fail CLI validation explicitly

## CLI Surface

The initial CLI surface should cover the common cases without exposing every internal library knob.

Core execution and sandbox flags:

- `--name`
- `--workdir`
- `--bin` repeatable
- `--mount-ro src:dst` repeatable
- `--mount-rw src:dst` repeatable
- `--env KEY=VALUE` repeatable
- `--clear-env`
- `--traffic-mode proxy|transparent`
- `--mitm`
- `--max-request-body-bytes`
- `--print-policy`

Network policy flags:

- `--allowed-domain` repeatable
- `--allowed-domains-file`
- `--deny-domain` repeatable
- `--allow-http-method` repeatable
- `--allow-connect`
- `--allow-connect-port` repeatable
- `--allow-path` repeatable
- `--deny-path` repeatable

High-level policy semantics:

- allow-domain flags and file entries populate `AllowHostPatterns`
- deny-domain flags populate `DenyHostPatterns`
- `--allow-connect` and `--allow-connect-port` control CONNECT explicitly
- path flags are passed through as regex patterns for MITM/decrypted request policy
- `--mitm` enables manager-wide MITM for proxy mode and is required for transparent mode

## Interactive Execution Design

The existing library already supports sandbox lifecycle and stream-frame delivery from the helper, but the public run API only exposes buffered output. The CLI needs an interactive execution path.

Recommended library change:

- add a public interactive execution method on `Sandbox`
- extend run options so callers can provide stdin/stdout/stderr handles and indicate whether the session should behave like a terminal

Required behavior:

- forward host stdin to the helper child process
- forward helper stdout and stderr frames to the requested writers immediately
- continue supporting buffered execution for existing callers
- serialize executions per sandbox as today

TTY handling:

- detect whether the caller's stdio is attached to a terminal
- when interactive mode is used with a terminal, the payload should inherit a functional controlling terminal/session behavior rather than a fully detached batch execution path
- a minimal first version can use direct stdio inheritance in the helper child process if that works within the bridge protocol; a PTY-backed approach is acceptable if required by runtime behavior

## Architecture

The implementation should preserve the current layering:

1. Cobra CLI parses flags and payload argv
2. CLI builds `ProxyOptions` and `SandboxOptions`
3. CLI creates one `ProxyManager`
4. CLI creates one sandbox
5. CLI invokes the new interactive execution method
6. helper runtime starts the payload and streams stdin/stdout/stderr over the existing bridge
7. host-side policy evaluation remains fully inside `ProxyManager`

No CLI-specific bypass of the library should be introduced.

## Error Handling

User-facing failures should be explicit:

- missing payload after `--`
- malformed `src:dst` mount spec
- malformed `KEY=VALUE` env spec
- malformed or unreadable allowed-domain file
- invalid wildcard domain syntax
- transparent mode without MITM
- invalid workdir or mount configuration rejected by the library

Execution-time failures:

- transport/setup failures return a CLI error message
- successful execution with non-zero payload exit should terminate the CLI with the same exit code

## Testing Strategy

Use TDD across both library and CLI behavior.

Coverage should include:

- pure helper tests for domain-file parsing and wildcard-to-regex conversion
- pure helper tests for mount/env spec parsing
- helper-client and helper-runtime tests for interactive stream behavior
- sandbox-level tests for the new public interactive run API rejecting invalid input
- CLI command tests for `--` payload parsing and effective policy construction
- at least one integration-oriented CLI execution test if the existing test harness can support it without brittle terminal requirements

The tests should prove:

- existing buffered `Sandbox.Run` behavior remains intact
- interactive exec forwards stdin and streams stdout/stderr live
- allowed-domain file entries become the intended host regexes
- the default cwd convenience mount and workdir are applied
- proxy mode remains the default
- transparent mode requires MITM
