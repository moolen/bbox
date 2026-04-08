# Structured Mounts Design

## Goal

Replace the current `mount_ro` / `mount_rw` CLI and config surface with a single structured `mounts` model that also supports sandbox-scoped ephemeral directories backed by host disk storage.

## Context

The current model has two limitations:

1. It only supports bind mounts expressed as `src:dst` strings.
2. It cannot express sandbox-owned writable storage that should be cleaned up automatically after the sandbox exits.

This becomes a practical problem for large build workloads. Some tools need tens of gigabytes of writable scratch space, which should not be stored in a `tmpfs`, but also should not persist beyond the sandbox lifetime.

## Existing Behavior

On Linux, bind mounts are currently implemented with bubblewrap `--bind` and `--ro-bind`.

Operationally, bind mounts should be treated as recursive. Mounting `/sys` should expose existing submounts such as `/sys/fs/bpf` and `/sys/kernel/debug`.

The current public API is:

- `bbox.Mount{Source, Target, ReadOnly}`
- `bbox.SandboxOptions.Mounts []Mount`
- CLI flags `--mount-ro` and `--mount-rw`
- YAML keys `mount_ro` and `mount_rw`

## Non-Goals

- Exposing raw bubblewrap mount primitives directly in the public API
- Supporting multiple recursive modes
- Adding `tmpfs`-backed scratch storage as part of this change
- Preserving backward compatibility for `mount_ro` or `mount_rw`

## Proposed Public API

Retain `SandboxOptions.Mounts []Mount`, but redefine `Mount` as a typed mount specification.

```go
type MountType string

const (
	MountTypeBind     MountType = "bind"
	MountTypeEmptyDir MountType = "empty_dir"
)

type Mount struct {
	Type     MountType
	Source   string
	Target   string
	ReadOnly bool
	Mode     uint32
}
```

Semantics:

- `Type: bind`
  - requires `Source`
  - requires `Target`
  - honors `ReadOnly`
  - is recursive by definition
- `Type: empty_dir`
  - requires `Target`
  - ignores `ReadOnly`
  - must not set `Source`
  - may set `Mode`

`Mode` applies only to `empty_dir`. The zero value means "use the default directory mode", which should be `0755`.

## CLI and Config Surface

Remove:

- `--mount-ro`
- `--mount-rw`
- `mount_ro:`
- `mount_rw:`

Add:

- a repeatable `--mount` flag using a structured mount spec format
- a `mounts:` YAML array with structured entries

YAML shape:

```yaml
mounts:
  - type: bind
    source: /sys
    target: /sys
    read_only: true

  - type: empty_dir
    target: /var/lib/buildkit
    mode: 0755
```

CLI shape:

```text
--mount type=bind,source=/sys,target=/sys,read-only
--mount type=empty_dir,target=/var/lib/buildkit,mode=0755
```

The exact CLI grammar should be a key/value form rather than overloading `src:dst` strings. This keeps the CLI aligned with the typed config model and avoids another short-lived syntax.

## Runtime Behavior

### Bind Mounts

For Linux sandboxes:

- `bind` mounts remain backed by bubblewrap bind mounts
- read-only binds emit the read-only bubblewrap form
- read-write binds emit the read-write bubblewrap form
- all bind mounts are treated as recursive

### Empty Directories

`empty_dir` is implemented as:

1. Create a sandbox-owned host directory before sandbox launch
2. Apply the requested mode if provided, otherwise `0755`
3. Bind-mount that directory into the sandbox at `Target`
4. Remove the host directory during sandbox teardown

These directories must be backed by normal host disk storage, not `tmpfs`, so large build caches and builder state can spill to disk.

The host paths for these directories should live under sandbox-owned runtime state, tied to the same lifecycle as the staged root filesystem.

## Validation Rules

Validation must reject:

- unknown mount `type`
- missing `target`
- non-absolute `target`
- `bind` mounts without `source`
- non-absolute `source`
- nonexistent bind `source`
- `empty_dir` mounts that set `source`
- `bind` mounts that set `mode`
- overlapping mount targets
- targets overlapping reserved sandbox paths

The existing reserved-path protections remain in force for all mount types.

## Platform Behavior

Linux:

- full support for `bind` and `empty_dir`

Darwin:

- continue rejecting non-empty `Mounts` at runtime
- update the user-facing error text from `mount_ro` / `mount_rw` wording to the new structured `mounts` model

The config schema should stop accepting `mount_ro` and `mount_rw`. Existing config files that still use them should fail fast with an unknown-field error.

## Implementation Notes

The change will likely require:

- redefining `bbox.Mount` in the library
- extending mount validation to branch on `Type`
- converting `empty_dir` mounts into runtime-managed bind mounts before bubblewrap argument generation
- tracking sandbox-owned ephemeral mount directories in the sandbox lifecycle and removing them on close
- replacing CLI/config parsing for `mount_ro` / `mount_rw` with structured `mounts`
- updating docs and examples to use the new shape

## Testing Strategy

Add or update tests for:

- library mount validation for both mount types
- bubblewrap argument generation for bind mounts
- runtime conversion of `empty_dir` into bind-backed host directories
- teardown cleanup of ephemeral directories
- YAML decoding for structured `mounts`
- CLI `--mount` parsing
- rejection of removed `mount_ro` / `mount_rw` keys
- Darwin runtime rejection for structured mounts

## Migration

This is an intentional breaking change.

Users must convert:

- `mount_ro: ["SRC:DST"]` to `mounts: [{type: bind, source: SRC, target: DST, read_only: true}]`
- `mount_rw: ["SRC:DST"]` to `mounts: [{type: bind, source: SRC, target: DST}]`

No compatibility shim will be provided.
