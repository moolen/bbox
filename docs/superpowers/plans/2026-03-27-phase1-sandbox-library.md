# Phase 1 Sandbox Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 1 of `github.com/moolen/bbox`: an importable Go library plus small demo CLI that manages one shared host proxy and multiple persistent unprivileged `bwrap` sandboxes with per-sandbox policy, binary staging, and explicit mounts.

**Architecture:** The module root becomes package `bbox`, which exposes `ProxyManager` and `Sandbox` APIs. A separate `cmd/bbox-helper` binary runs inside each sandbox and bridges proxy/exec traffic back to the host manager over a private control channel, while `cmd/demo` exercises the public library API end-to-end.

**Tech Stack:** Go, `bubblewrap`, `net/http`, `os/exec`, `golang.org/x/sys/unix`, regex-based policy evaluation, gob or small typed RPC framing for helper control

---

## File Structure

The implementation should converge on this structure:

- `api.go`
  Public constructors and exported types for package `bbox`
- `manager.go`
  `ProxyManager` lifecycle, sandbox registration, shared transport ownership
- `policy.go`
  Per-sandbox host/method policy evaluation
- `sandbox.go`
  Public `Sandbox` lifecycle and `Run` API
- `staging.go`
  Binary resolution, `ldd` parsing, runtime dependency staging, helper staging
- `mounts.go`
  Mount validation and `bwrap` argument assembly
- `helper_client.go`
  Host-side helper RPC/bridge client
- `types.go`
  Shared exported option/result types
- `internal/helperproto/messages.go`
  Helper protocol request/response message types
- `internal/helperruntime/runtime.go`
  In-sandbox helper server logic used by `cmd/bbox-helper`
- `cmd/bbox-helper/main.go`
  Helper binary entrypoint
- `cmd/demo/main.go`
  Demo CLI showing shared proxy + multiple sandboxes
- `integration/multi_sandbox_test.go`
  End-to-end integration coverage

PoC files at the module root (`main.go`, `proxy.go`, `main_test.go`, `netns_linux.go`) should be removed or absorbed once equivalent library/demo code exists.

### Task 1: Convert the module root into importable package `bbox`

**Files:**
- Create: `api.go`
- Create: `types.go`
- Create: `api_test.go`
- Modify: `go.mod`
- Delete: `main.go`
- Delete: `main_test.go`

- [ ] **Step 1: Write the failing test**

```go
package bbox

import "testing"

func TestNewProxyManagerRejectsInvalidRegex(t *testing.T) {
	_, err := NewProxyManager(ProxyOptions{})
	if err != nil {
		t.Fatalf("unexpected manager construction error: %v", err)
	}

	_, err = compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{"["},
	})
	if err == nil {
		t.Fatal("expected invalid regex compilation to fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestNewProxyManagerRejectsInvalidRegex`
Expected: FAIL with undefined `NewProxyManager`, `ProxyOptions`, `NetworkPolicy`, or `compilePolicy`

- [ ] **Step 3: Write minimal implementation**

Create the public root package and its initial exported types:

```go
package bbox

type ProxyOptions struct{}

type NetworkPolicy struct {
	AllowHostPatterns []string
	DenyHostPatterns  []string
	AllowHTTPMethods  []string
	AllowConnect      bool
}

type ProxyManager struct{}

func NewProxyManager(opts ProxyOptions) (*ProxyManager, error) {
	return &ProxyManager{}, nil
}
```

Also move all executable concerns out of the module root by deleting the old PoC `main.go` once replacement entrypoints exist under `cmd/`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestNewProxyManagerRejectsInvalidRegex`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api.go types.go api_test.go go.mod
git rm -f main.go main_test.go
git commit -m "refactor: turn module root into bbox library package"
```

### Task 2: Implement the host-side policy engine and shared proxy manager

**Files:**
- Create: `manager.go`
- Create: `policy.go`
- Create: `policy_test.go`
- Modify: `api.go`
- Modify: `types.go`

- [ ] **Step 1: Write the failing test**

```go
package bbox

import "testing"

func TestCompiledPolicyHonorsDenyBeforeAllow(t *testing.T) {
	policy, err := compilePolicy(NetworkPolicy{
		AllowHostPatterns: []string{`(^|[.])github[.]com$`},
		DenyHostPatterns:  []string{`^gist[.]github[.]com$`},
		AllowHTTPMethods:  []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.Check("GET", "api.github.com", false); err != nil {
		t.Fatalf("expected api.github.com to be allowed: %v", err)
	}
	if err := policy.Check("GET", "gist.github.com", false); err == nil {
		t.Fatal("expected gist.github.com to be denied")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestCompiledPolicyHonorsDenyBeforeAllow`
Expected: FAIL with undefined `policy.Check` behavior or incorrect evaluation order

- [ ] **Step 3: Write minimal implementation**

Implement:

```go
type compiledPolicy struct {
	allowMethods map[string]struct{}
	allowHosts   []*regexp.Regexp
	denyHosts    []*regexp.Regexp
	allowConnect bool
}

func (p compiledPolicy) Check(method, hostname string, connect bool) error {
	// 1. validate request shape
	// 2. enforce CONNECT knob
	// 3. enforce method allowlist
	// 4. deny regexes
	// 5. allow regexes
	// 6. deny by default when allowlist is configured
	return nil
}
```

Also add `ProxyManager` internals for:

- sandbox registration keyed by sandbox ID
- per-sandbox compiled policy lookup
- a shared `http.Transport` clone for outbound requests

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestCompiledPolicyHonorsDenyBeforeAllow`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manager.go policy.go policy_test.go api.go types.go
git commit -m "feat: add shared proxy manager and policy engine"
```

### Task 3: Implement binary staging, dependency discovery, and mount validation

**Files:**
- Create: `staging.go`
- Create: `mounts.go`
- Create: `staging_test.go`
- Create: `mounts_test.go`
- Modify: `types.go`
- Modify: `sandbox.go`

- [ ] **Step 1: Write the failing tests**

```go
package bbox

import "testing"

func TestParseLddOutputFindsAbsolutePaths(t *testing.T) {
	input := "\tlibcurl.so.4 => /usr/lib/libcurl.so.4 (0x0)\n\t/lib64/ld-linux-x86-64.so.2 (0x0)\n"
	got := parseLddOutput(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(got))
	}
}

func TestValidateMountsRejectsOverlappingTargets(t *testing.T) {
	err := validateMounts([]Mount{
		{Source: "/tmp/one", Target: "/workspace", ReadOnly: true},
		{Source: "/tmp/two", Target: "/workspace", ReadOnly: false},
	})
	if err == nil {
		t.Fatal("expected overlapping mount targets to fail")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestParseLddOutputFindsAbsolutePaths|TestValidateMountsRejectsOverlappingTargets'`
Expected: FAIL with undefined staging or mount validation helpers

- [ ] **Step 3: Write minimal implementation**

Implement:

- `resolveBinary(nameOrPath string) (string, error)`
- `runtimeFilesForBinary(binaryPath string) ([]string, error)`
- `stageSandboxRoot(opts SandboxOptions, helperBinary string) (string, error)`
- `validateMounts([]Mount) error`
- `buildBwrapArgs(root string, helperPath string, mounts []Mount) []string`

Example mount validation core:

```go
func validateMounts(mounts []Mount) error {
	seen := map[string]Mount{}
	for _, m := range mounts {
		if !filepath.IsAbs(m.Target) {
			return fmt.Errorf("mount target %q must be absolute", m.Target)
		}
		if prev, ok := seen[m.Target]; ok {
			return fmt.Errorf("mount target %q conflicts with %q", m.Target, prev.Source)
		}
		seen[m.Target] = m
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestParseLddOutputFindsAbsolutePaths|TestValidateMountsRejectsOverlappingTargets'`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add staging.go mounts.go staging_test.go mounts_test.go types.go sandbox.go
git commit -m "feat: add sandbox staging and mount validation"
```

### Task 4: Define the helper protocol and helper binary

**Files:**
- Create: `internal/helperproto/messages.go`
- Create: `internal/helperproto/messages_test.go`
- Create: `internal/helperruntime/runtime.go`
- Create: `cmd/bbox-helper/main.go`
- Delete: `proxy.go`
- Delete: `netns_linux.go`

- [ ] **Step 1: Write the failing test**

```go
package helperproto

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func TestExecRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := ExecRequest{
		Argv: []string{"/usr/bin/curl", "-v", "http://example.com"},
		Env:  []string{"HTTP_PROXY=http://127.0.0.1:31111"},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got ExecRequest
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Argv) != 3 {
		t.Fatalf("unexpected argv: %#v", got.Argv)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/helperproto -run TestExecRequestRoundTrip`
Expected: FAIL with undefined `ExecRequest`

- [ ] **Step 3: Write minimal implementation**

Create message types for:

- helper handshake/ready
- outbound proxy request/response
- exec request
- stdout/stderr stream frames
- exit status response

Example protocol core:

```go
type ExecRequest struct {
	Argv    []string
	Env     []string
	WorkDir string
}

type ExecResult struct {
	ExitCode int
	Stderr   []byte
}
```

Also create `cmd/bbox-helper/main.go` that enters the helper runtime package and serves:

- sandbox-local proxy listener
- exec RPC handler
- bridge connection to host

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/helperproto -run TestExecRequestRoundTrip`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperproto/messages.go internal/helperproto/messages_test.go internal/helperruntime/runtime.go cmd/bbox-helper/main.go
git rm -f proxy.go netns_linux.go
git commit -m "feat: add helper protocol and helper binary"
```

### Task 5: Implement persistent sandbox lifecycle and `Run` API

**Files:**
- Create: `sandbox.go`
- Create: `helper_client.go`
- Create: `sandbox_test.go`
- Modify: `manager.go`
- Modify: `types.go`

- [ ] **Step 1: Write the failing test**

```go
package bbox

import "testing"

func TestSandboxRunRejectsEmptyArgv(t *testing.T) {
	s := &Sandbox{}
	_, err := s.Run(nil, nil, RunOptions{})
	if err == nil {
		t.Fatal("expected empty argv to fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestSandboxRunRejectsEmptyArgv`
Expected: FAIL with undefined `Sandbox.Run` or incorrect nil handling

- [ ] **Step 3: Write minimal implementation**

Implement:

- `ProxyManager.NewSandbox(ctx, opts)` to:
  - validate options
  - stage the root
  - create the private bridge/socketpair
  - start `bwrap` with `cmd/bbox-helper`
  - wait for helper readiness
  - register compiled policy under a sandbox ID
- `Sandbox.Run(ctx, argv, opts)` to:
  - reject empty argv
  - send `ExecRequest`
  - collect stdout/stderr and exit status
- `Sandbox.Close()` to:
  - stop helper process
  - close bridge
  - unregister policy
  - remove staged root

Example validation core:

```go
func (s *Sandbox) Run(ctx context.Context, argv []string, opts RunOptions) (*RunResult, error) {
	if len(argv) == 0 {
		return nil, errors.New("argv must not be empty")
	}
	return s.client.Run(ctx, argv, opts)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestSandboxRunRejectsEmptyArgv`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add sandbox.go helper_client.go sandbox_test.go manager.go types.go
git commit -m "feat: add persistent sandbox lifecycle and run api"
```

### Task 6: Add integration coverage for multiple sandboxes and per-sandbox policy

**Files:**
- Create: `integration/multi_sandbox_test.go`
- Modify: `manager.go`
- Modify: `sandbox.go`
- Modify: `internal/helperruntime/runtime.go`

- [ ] **Step 1: Write the failing integration test**

```go
package integration

import (
	"context"
	"regexp"
	"testing"

	"github.com/moolen/bbox"
)

func TestTwoSandboxesUseDifferentPolicies(t *testing.T) {
	ctx := context.Background()
	manager, err := bbox.NewProxyManager(bbox.ProxyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	allowed, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "allowed",
		Binaries: []string{"curl"},
		Policy: bbox.NetworkPolicy{
			AllowHostRegex: []*regexp.Regexp{regexp.MustCompile(`^example[.]com$`)},
			AllowHTTPMethods: []string{"GET"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()

	denied, err := manager.NewSandbox(ctx, bbox.SandboxOptions{
		Name:     "denied",
		Binaries: []string{"curl"},
		Policy: bbox.NetworkPolicy{
			AllowHostRegex: []*regexp.Regexp{regexp.MustCompile(`^github[.]com$`)},
			AllowHTTPMethods: []string{"GET"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()

	okRes, err := allowed.Run(ctx, []string{"/usr/bin/curl", "-sS", "http://example.com"}, bbox.RunOptions{})
	if err != nil || okRes.ExitCode != 0 {
		t.Fatalf("expected allowed sandbox to succeed, got result=%+v err=%v", okRes, err)
	}

	badRes, err := denied.Run(ctx, []string{"/usr/bin/curl", "-sS", "http://example.com"}, bbox.RunOptions{})
	if err == nil && badRes.ExitCode == 0 {
		t.Fatalf("expected denied sandbox to fail, got result=%+v err=%v", badRes, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./integration -run TestTwoSandboxesUseDifferentPolicies -v`
Expected: FAIL because the manager/sandbox/helper do not yet coordinate multiple persistent sessions correctly

- [ ] **Step 3: Write minimal implementation**

Fill the remaining gaps needed for the end-to-end contract:

- stable sandbox IDs
- helper ready handshake
- per-sandbox policy registration and deregistration
- one active command at a time per sandbox
- predictable denial propagation back to the caller

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./integration -run TestTwoSandboxesUseDifferentPolicies -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add integration/multi_sandbox_test.go manager.go sandbox.go internal/helperruntime/runtime.go
git commit -m "test: cover multiple sandboxes with per-sandbox policy"
```

### Task 7: Add the demo CLI and final verification path

**Files:**
- Create: `cmd/demo/main.go`
- Create: `README.md`
- Modify: `api.go`
- Modify: `types.go`

- [ ] **Step 1: Write the failing smoke expectation**

Document the desired demo shape in a small smoke test or command expectation:

```text
go run ./cmd/demo \
  --sandbox alpha --allow-host '^example[.]com$' --bin curl \
  --sandbox beta --allow-host '^github[.]com$' --bin curl

Expected:
- alpha can fetch example.com
- beta is denied fetching example.com
```

- [ ] **Step 2: Run demo to verify it is not ready yet**

Run: `go run ./cmd/demo`
Expected: FAIL with missing CLI or incomplete library wiring

- [ ] **Step 3: Write minimal implementation**

Implement:

- a thin demo CLI that creates one `ProxyManager`
- two sandboxes with different policies
- one successful and one denied `curl` run
- concise human-readable output

README example core:

```go
manager, _ := bbox.NewProxyManager(bbox.ProxyOptions{})
sb, _ := manager.NewSandbox(ctx, bbox.SandboxOptions{
	Name:     "demo",
	Binaries: []string{"curl"},
	Policy: bbox.NetworkPolicy{
		AllowHostPatterns: []string{`^example[.]com$`},
		AllowHTTPMethods:  []string{"GET"},
	},
})
```

- [ ] **Step 4: Run final verification**

Run: `go test ./...`
Expected: PASS

Run: `go test ./integration -run TestTwoSandboxesUseDifferentPolicies -v`
Expected: PASS

Run: `go run ./cmd/demo`
Expected: demo shows one allowed request and one denied request using the shared host proxy

- [ ] **Step 5: Commit**

```bash
git add cmd/demo/main.go README.md api.go types.go
git commit -m "feat: add bbox demo cli and usage docs"
```
