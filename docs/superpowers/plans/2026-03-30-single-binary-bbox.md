# Single-Binary `bbox` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `bbox` into the only shipped and staged executable by moving the helper role into hidden `bbox` modes and executing the seccomp launcher from embedded bytes via `memfd`, while preserving the current proxy and transparent behavior.

**Architecture:** Extract the current helper `main` logic into an internal entrypoint that both `cmd/bbox` and the legacy helper wrapper can call during the migration. Replace sibling helper resolution with a self-binary resolver, keep transparent mode working during the transition, then switch seccomp launcher startup from a staged file path to an embedded launcher asset executed from an anonymous `memfd`.

**Tech Stack:** Go 1.25, Cobra CLI, Bubblewrap, libseccomp CGO bindings, Linux `memfd_create`/`execveat`, generated Go source for embedded launcher payloads, GoReleaser.

---

## File Structure

- `cmd/bbox/main.go`
  Public CLI entrypoint plus hidden internal helper dispatch.
- `cmd/bbox/main_test.go`
  CLI dispatch tests and hidden helper bypass tests.
- `cmd/bbox-helper/main.go`
  Temporary thin wrapper around the extracted helper entrypoint during migration, deleted in the final cleanup task.
- `internal/helperentrypoint/entrypoint.go`
  New shared helper-mode parser and runner extracted from `cmd/bbox-helper`.
- `internal/helperentrypoint/entrypoint_test.go`
  Tests for helper flag parsing and runtime config handoff.
- `runtime_binary.go`
  New self-binary resolver that replaces `helper_binary.go`.
- `runtime_binary_test.go`
  Resolver tests for packaged `bbox` and source-checkout fallback builds.
- `staging.go`
  Sandbox root staging logic; transition from `/app/bbox-helper` to `/app/bbox`.
- `staging_test.go`
  Staging assertions for one on-disk executable and transparent-mode assets.
- `mounts.go`
  `bwrap` argv builder; update helper invocation to `/app/bbox internal-helper ...`.
- `sandbox.go`
  Sandbox startup wiring for the new runtime binary path.
- `internal/embeddedlauncher/assets_linux.go`
  Runtime API to select embedded launcher bytes for the current architecture.
- `internal/embeddedlauncher/generated_linux_amd64.go`
  Generated launcher bytes for `linux/amd64`.
- `internal/embeddedlauncher/generated_linux_arm64.go`
  Generated launcher bytes for `linux/arm64`.
- `internal/embeddedlauncher/memfd_linux.go`
  Create/write/exec the launcher from an anonymous `memfd`.
- `internal/embeddedlauncher/assets_test.go`
  Coverage for asset lookup and missing-architecture errors.
- `internal/embeddedlauncher/memfd_linux_test.go`
  Focused tests for `memfd` creation and execution argument construction.
- `internal/helperruntime/seccompnotify/supervisor_runtime_linux.go`
  Replace sibling launcher lookup with embedded-launcher `memfd` execution.
- `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go`
  End-to-end regression tests for transparent exec through the embedded launcher path.
- `scripts/generate-embedded-launchers.sh`
  Deterministic generator for the committed arch-specific launcher source files.
- `Makefile`
  Generation target and removal of separate helper/launcher release assumptions.
- `.goreleaser.yaml`
  Local amd64 snapshot bundle contents.
- `.goreleaser.arm64.yaml`
  Local arm64 snapshot bundle contents.
- `.goreleaser.release.yaml`
  Multi-arch release bundle contents; remove separate helper archive members and launcher build hooks.
- `scripts/verify-release-archives.sh`
  Release archive member and architecture verification for the single-binary bundle.
- `.github/workflows/ci.yml`
  Keep local/release smoke coverage aligned with the new archive contents.
- `.github/workflows/release.yml`
  Tagged release workflow after helper/launcher packaging removal.
- `README.md`
  Update release and runtime documentation to describe the single-binary model.

### Task 1: Extract Hidden Helper Mode Into `bbox`

**Files:**
- Create: `internal/helperentrypoint/entrypoint.go`
- Create: `internal/helperentrypoint/entrypoint_test.go`
- Modify: `cmd/bbox/main.go`
- Modify: `cmd/bbox/main_test.go`
- Modify: `cmd/bbox-helper/main.go`

- [ ] **Step 1: Write the failing helper-entrypoint tests**

Add `internal/helperentrypoint/entrypoint_test.go` with focused tests for the current helper flags and runtime config handoff:

```go
func TestRunParsesHelperFlagsAndCallsRuntime(t *testing.T) {
    called := false
    runHelperRuntime = func(ctx context.Context, cfg helperruntime.Config) error {
        called = true
        if cfg.TrafficMode != helperruntime.TrafficModeTransparent {
            t.Fatalf("traffic mode = %q", cfg.TrafficMode)
        }
        if cfg.ProxyAddr != "127.0.0.1:31111" {
            t.Fatalf("proxy addr = %q", cfg.ProxyAddr)
        }
        return nil
    }
    t.Cleanup(func() { runHelperRuntime = helperruntime.Run })

    if err := Run([]string{
        "--bridge-fd", "7",
        "--proxy-addr", "127.0.0.1:31111",
        "--traffic-mode", "transparent",
        "--mitm-enabled=true",
        "child-proxy",
    }); err != nil {
        t.Fatal(err)
    }
    if !called {
        t.Fatal("expected helper runtime to be invoked")
    }
}
```

Add a dispatch test to `cmd/bbox/main_test.go`:

```go
func TestDispatchRunsInternalHelperWithoutCobra(t *testing.T) {
    helperCalled := false
    err := dispatch([]string{"internal-helper", "--bridge-fd", "3"}, commandDeps{}, func(args []string) error {
        helperCalled = true
        if len(args) == 0 || args[0] != "--bridge-fd" {
            t.Fatalf("args = %v", args)
        }
        return nil
    })
    if err != nil {
        t.Fatal(err)
    }
    if !helperCalled {
        t.Fatal("expected internal helper dispatch")
    }
}
```

- [ ] **Step 2: Run the new focused tests to verify they fail**

Run: `go test ./cmd/bbox ./internal/helperentrypoint -run 'TestDispatchRunsInternalHelperWithoutCobra|TestRunParsesHelperFlagsAndCallsRuntime' -count=1`

Expected: FAIL because `dispatch` and `internal/helperentrypoint.Run` do not exist yet.

- [ ] **Step 3: Implement the shared helper entrypoint and hidden dispatch**

Move the helper parsing logic out of `cmd/bbox-helper/main.go` into `internal/helperentrypoint/entrypoint.go`:

```go
package helperentrypoint

func Run(args []string) error {
    parsed, err := parseFlags(args)
    if err != nil {
        return err
    }
    bridge, err := helperruntime.OpenBridgeFromFD(parsed.bridgeFD)
    if err != nil {
        return err
    }
    defer bridge.Close()

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    logger := log.New(os.Stderr, "bbox-helper: ", log.LstdFlags)
    return helperruntime.Run(ctx, helperruntime.Config{...})
}
```

Update `cmd/bbox/main.go` to short-circuit before Cobra:

```go
func dispatch(args []string, deps commandDeps, runHelper func([]string) error) error {
    if len(args) > 0 && args[0] == "internal-helper" {
        return runHelper(args[1:])
    }
    cmd := newRootCommand(deps)
    cmd.SetArgs(args)
    return cmd.Execute()
}
```

Keep `cmd/bbox-helper/main.go` as a temporary wrapper:

```go
func main() {
    if err := helperentrypoint.Run(os.Args[1:]); err != nil {
        log.Fatal(err)
    }
}
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./cmd/bbox ./internal/helperentrypoint -run 'TestDispatchRunsInternalHelperWithoutCobra|TestRunParsesHelperFlagsAndCallsRuntime' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/bbox/main.go cmd/bbox/main_test.go cmd/bbox-helper/main.go internal/helperentrypoint/entrypoint.go internal/helperentrypoint/entrypoint_test.go
git commit -m "refactor: extract bbox internal helper entrypoint"
```

### Task 2: Stage And Launch `/app/bbox` Instead Of `/app/bbox-helper`

**Files:**
- Create: `runtime_binary.go`
- Create: `runtime_binary_test.go`
- Modify: `manager.go`
- Modify: `sandbox.go`
- Modify: `mounts.go`
- Modify: `staging.go`
- Modify: `staging_test.go`
- Delete: `helper_binary.go`
- Delete: `helper_binary_test.go`

- [ ] **Step 1: Write the failing self-binary and staging tests**

Create `runtime_binary_test.go` with a packaged-binary preference test:

```go
func TestRuntimeBinaryResolverPrefersPackagedBBox(t *testing.T) {
    exeDir := t.TempDir()
    exePath := filepath.Join(exeDir, "bbox")
    if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
        t.Fatal(err)
    }

    resolver := newRuntimeBinaryResolver()
    resolver.executablePath = func() (string, error) { return exePath, nil }

    got, err := resolver.RuntimeBinary()
    if err != nil {
        t.Fatal(err)
    }
    if got != exePath {
        t.Fatalf("got %q want %q", got, exePath)
    }
}
```

Update `staging_test.go` to require `/app/bbox`:

```go
func TestStageSandboxRootCopiesBBoxEntrypoint(t *testing.T) {
    bboxPath := filepath.Join(t.TempDir(), "bbox")
    if err := os.WriteFile(bboxPath, []byte("bbox"), 0o755); err != nil {
        t.Fatal(err)
    }

    root, err := stageSandboxRoot(SandboxOptions{}, bboxPath, nil, TrafficModeProxy)
    if err != nil {
        t.Fatal(err)
    }

    if _, err := os.Stat(filepath.Join(root, "app", "bbox")); err != nil {
        t.Fatalf("expected /app/bbox: %v", err)
    }
}
```

Update the `buildBwrapArgs` expectation tests to require:

```go
wantTail := []string{
    "/app/bbox",
    "internal-helper",
    "--bridge-fd", "3",
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test . -run 'TestRuntimeBinaryResolverPrefersPackagedBBox|TestStageSandboxRootCopiesBBoxEntrypoint|TestBuildBwrapArgs' -count=1`

Expected: FAIL because the resolver API and `/app/bbox internal-helper` path do not exist yet.

- [ ] **Step 3: Implement the self-binary resolver and new helper staging**

Replace `helperBinaryResolver` with `runtimeBinaryResolver` in `runtime_binary.go`:

```go
type runtimeBinaryResolver struct {
    once sync.Once
    executablePath func() (string, error)
    packageRoot    func() (string, error)
    makeTempDir    func(string, string) (string, error)
    buildBBox      func(string, string) error
    removeAll      func(string) error
    path string
    dir  string
    err  error
}

func (r *runtimeBinaryResolver) RuntimeBinary() (string, error) {
    r.once.Do(func() {
        if path, ok := r.packagedBBox(); ok {
            r.path = path
            return
        }
        // source-checkout fallback: build ./cmd/bbox into a temp dir
    })
    return r.path, r.err
}
```

Update `mounts.go`:

```go
args = append(args,
    "--",
    cfg.helperPath,
    "internal-helper",
    "--bridge-fd", strconv.Itoa(cfg.bridgeFD),
    "--proxy-addr", cfg.proxyListenAddr,
    ...
)
```

Update `staging.go` to copy only the chosen `bbox` host binary to `/app/bbox` for the helper entrypoint path, but keep the launcher staging in place for now so transparent mode still works before Task 4.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test . -run 'TestRuntimeBinaryResolverPrefersPackagedBBox|TestStageSandboxRootCopiesBBoxEntrypoint|TestBuildBwrapArgs' -count=1`

Expected: PASS

- [ ] **Step 5: Run the broader sandbox regression tests**

Run: `go test . -run 'TestNewSandbox|TestStageSandboxRoot|TestBuildBwrapArgs' -count=1`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add runtime_binary.go runtime_binary_test.go manager.go sandbox.go mounts.go staging.go staging_test.go
git rm helper_binary.go helper_binary_test.go
git commit -m "refactor: stage bbox as the sandbox entrypoint"
```

### Task 3: Embed Launcher Payloads As Generated Go Source

**Files:**
- Create: `internal/embeddedlauncher/assets_linux.go`
- Create: `internal/embeddedlauncher/assets_test.go`
- Create: `internal/embeddedlauncher/generated_linux_amd64.go`
- Create: `internal/embeddedlauncher/generated_linux_arm64.go`
- Create: `scripts/generate-embedded-launchers.sh`
- Modify: `Makefile`
- Modify: `launcher_build_test.go`

- [ ] **Step 1: Write the failing embedded-launcher tests**

Create `internal/embeddedlauncher/assets_test.go`:

```go
func TestForRuntimeArchReturnsLauncherBytes(t *testing.T) {
    payload, err := ForRuntimeArch()
    if err != nil {
        t.Fatal(err)
    }
    if len(payload) == 0 {
        t.Fatal("expected embedded launcher bytes")
    }
}
```

Add a generation verification test or script check:

```sh
./scripts/generate-embedded-launchers.sh --verify
```

- [ ] **Step 2: Run the new focused tests to verify they fail**

Run: `go test ./internal/embeddedlauncher -run TestForRuntimeArchReturnsLauncherBytes -count=1`

Expected: FAIL because the package and generated launcher payloads do not exist yet.

- [ ] **Step 3: Implement the generator and committed generated files**

Create `scripts/generate-embedded-launchers.sh` that:

```sh
#!/bin/sh
set -eu

build_launcher() {
  goos="$1"
  goarch="$2"
  cc="$3"
  out="$(mktemp)"
  "$cc" -O2 -o "$out" ./cmd/bbox-seccomp-launcher/main.c
  # emit Go source containing []byte literal or base64 payload
}
```

Add `internal/embeddedlauncher/assets_linux.go`:

```go
package embeddedlauncher

func ForArch(goarch string) ([]byte, error) {
    switch goarch {
    case "amd64":
        return launcherLinuxAMD64, nil
    case "arm64":
        return launcherLinuxARM64, nil
    default:
        return nil, fmt.Errorf("unsupported launcher arch %q", goarch)
    }
}

func ForRuntimeArch() ([]byte, error) {
    return ForArch(runtime.GOARCH)
}
```

Generate and commit:

- `internal/embeddedlauncher/generated_linux_amd64.go`
- `internal/embeddedlauncher/generated_linux_arm64.go`

Add a Make target:

```make
generate-embedded-launchers:
	./scripts/generate-embedded-launchers.sh
```

- [ ] **Step 4: Run the focused tests and generator verification**

Run: `go test ./internal/embeddedlauncher -run TestForRuntimeArchReturnsLauncherBytes -count=1`

Expected: PASS

Run: `./scripts/generate-embedded-launchers.sh --verify`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/embeddedlauncher/assets_linux.go internal/embeddedlauncher/assets_test.go internal/embeddedlauncher/generated_linux_amd64.go internal/embeddedlauncher/generated_linux_arm64.go scripts/generate-embedded-launchers.sh Makefile launcher_build_test.go
git commit -m "build: embed seccomp launcher payloads"
```

### Task 4: Execute The Embedded Launcher From `memfd`

**Files:**
- Create: `internal/embeddedlauncher/memfd_linux.go`
- Create: `internal/embeddedlauncher/memfd_linux_test.go`
- Modify: `internal/helperruntime/seccompnotify/supervisor_runtime_linux.go`
- Modify: `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go`

- [ ] **Step 1: Write the failing memfd-launch tests**

Add a focused test in `internal/helperruntime/seccompnotify/runtime_integration_linux_test.go` that stops depending on a sibling launcher path:

```go
func TestPrepareUsesEmbeddedLauncherFactory(t *testing.T) {
    called := false
    prev := launcherFactory
    launcherFactory = func() (launcherExecTarget, error) {
        called = true
        return launcherExecTarget{
            Path: "/proc/self/fd/42",
            Args: []string{"--from-memfd"},
            Close: func() error { return nil },
        }, nil
    }
    t.Cleanup(func() { launcherFactory = prev })

    supervisor := NewSupervisor(RuntimeTargets{})
    cmd := exec.Command("/bin/true")
    if err := supervisor.Prepare(context.Background(), cmd); err != nil {
        t.Fatal(err)
    }
    if !called {
        t.Fatal("expected embedded launcher factory")
    }
}
```

Create `internal/embeddedlauncher/memfd_linux_test.go` to cover write/seal helpers with stubbed syscalls.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./internal/helperruntime/seccompnotify ./internal/embeddedlauncher -run 'TestPrepareUsesEmbeddedLauncherFactory|TestOpenExecMemfd' -count=1`

Expected: FAIL because there is no embedded launcher execution path yet.

- [ ] **Step 3: Implement the `memfd` launcher API and wire the supervisor to it**

Create `internal/embeddedlauncher/memfd_linux.go`:

```go
type ExecTarget struct {
    Path  string
    Args  []string
    Close func() error
}

func OpenExecTarget() (ExecTarget, error) {
    payload, err := ForRuntimeArch()
    if err != nil {
        return ExecTarget{}, err
    }
    fd, err := unix.MemfdCreate("bbox-seccomp-launcher", unix.MFD_CLOEXEC)
    if err != nil {
        return ExecTarget{}, fmt.Errorf("memfd_create launcher: %w", err)
    }
    // write payload, chmod as needed, return /proc/self/fd/<n>
}
```

Refactor `supervisor_runtime_linux.go` away from `resolveLauncherCommand()`:

```go
var launcherFactory = func() (embeddedlauncher.ExecTarget, error) {
    return embeddedlauncher.OpenExecTarget()
}

target, err := launcherFactory()
if err != nil {
    return err
}
cmd.Path = target.Path
cmd.Args = append([]string{target.Path}, append(target.Args, targetPath, "--")...)
```

Ensure the supervisor owns and closes the target handle after `cmd.Start()` / `cmd.Wait()` lifecycle setup.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./internal/helperruntime/seccompnotify ./internal/embeddedlauncher -run 'TestPrepareUsesEmbeddedLauncherFactory|TestOpenExecMemfd' -count=1`

Expected: PASS

- [ ] **Step 5: Run the transparent exec integration suite**

Run: `go test ./internal/helperruntime/seccompnotify -count=1`

Expected: PASS, including the existing transparent-mode runtime integration coverage on Linux.

- [ ] **Step 6: Commit**

```bash
git add internal/embeddedlauncher/memfd_linux.go internal/embeddedlauncher/memfd_linux_test.go internal/helperruntime/seccompnotify/supervisor_runtime_linux.go internal/helperruntime/seccompnotify/runtime_integration_linux_test.go
git commit -m "feat: launch transparent payloads from embedded memfd launcher"
```

### Task 5: Remove Separate Helper/Launcher Packaging And Finalize Single-Binary Releases

**Files:**
- Modify: `staging.go`
- Modify: `staging_test.go`
- Modify: `.goreleaser.yaml`
- Modify: `.goreleaser.arm64.yaml`
- Modify: `.goreleaser.release.yaml`
- Modify: `scripts/verify-release-archives.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `Dockerfile`
- Modify: `README.md`
- Delete: `cmd/bbox-helper/main.go`

- [ ] **Step 1: Write the failing single-bundle tests**

Update `staging_test.go` to assert no launcher file is staged:

```go
if _, err := os.Stat(filepath.Join(root, "app", "bbox-seccomp-launcher")); !errors.Is(err, os.ErrNotExist) {
    t.Fatalf("expected no on-disk launcher, got %v", err)
}
```

Update `scripts/verify-release-archives.sh` expectations:

```sh
expected="$(printf '%s\n' bbox)"
```

Add or update a release bundle test to assert `bbox-helper` is absent from archive contents.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test . -run TestStageSandboxRootCopiesBBoxEntrypoint -count=1`

Expected: FAIL because staging still writes the on-disk launcher.

Run: `./scripts/verify-release-archives.sh --run-native amd64 linux_amd64`

Expected: FAIL against current bundle contents.

- [ ] **Step 3: Remove the staged launcher and separate release artifacts**

Update `staging.go` to stop copying `/app/bbox-seccomp-launcher`.

Delete the separate helper wrapper:

```bash
git rm cmd/bbox-helper/main.go
```

Update release configs so archives include only `bbox` and no launcher file members. Remove the dedicated helper builds and launcher before-hooks from the Goreleaser configs once `bbox` contains the embedded payloads.

Update Docker and docs to stop advertising `bbox-helper` and `bbox-seccomp-launcher` as shipped binaries.

- [ ] **Step 4: Run the full release verification path**

Run: `go test ./... -count=1 -timeout=20m`

Expected: PASS

Run: `make release-snapshot`

Expected: PASS

Run: `./scripts/verify-release-archives.sh --run-native amd64 linux_amd64`

Expected: PASS

Run: `./scripts/release-multiarch-snapshot.sh`

Expected: PASS

Run: `./scripts/verify-release-archives.sh --run-native amd64 linux_amd64 linux_arm64`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staging.go staging_test.go .goreleaser.yaml .goreleaser.arm64.yaml .goreleaser.release.yaml scripts/verify-release-archives.sh .github/workflows/ci.yml .github/workflows/release.yml Dockerfile README.md
git rm cmd/bbox-helper/main.go
git commit -m "feat: ship bbox as the only runtime binary"
```

## Final Verification

- [ ] Run: `go test ./... -count=1 -timeout=20m`
- [ ] Run: `make release-snapshot`
- [ ] Run: `./scripts/release-multiarch-snapshot.sh`
- [ ] Run: `./scripts/verify-release-archives.sh --run-native amd64 linux_amd64 linux_arm64`
- [ ] Confirm release archives contain only `bbox`
- [ ] Confirm transparent-mode integration coverage still passes on Linux

## Notes For The Implementer

- Keep the helper wrapper only until the hidden `bbox internal-helper` path is proven. Delete it in the final task, not earlier.
- Do not silently fall back to an on-disk launcher once the `memfd` path exists. Missing embedded assets must fail closed.
- Preserve the existing seccomp notify handshake semantics; only the launcher transport changes.
- `cmd/bbox` should not expose `internal-helper` in `--help` output.
- The current plan-review subagent loop is intentionally skipped here because delegated subagents were not explicitly requested in this session. Self-review the plan before execution.
