# Sandbox Network Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten the default sandbox network boundary, bind transparent HTTPS policy to the real upstream authority, and cap proxy/MITM buffering.

**Architecture:** The change stays within the existing helper-manager split. Tests define the desired behavior first, then the runtime and policy layers are updated to reject host/authority mismatches, enforce bounded buffering, and ship a stricter default seccomp baseline.

**Tech Stack:** Go, bubblewrap, libseccomp, Go `net/http`, Go integration/unit tests

---

### Task 1: Tighten The Default Seccomp Baseline

**Files:**
- Modify: `seccomp.go`
- Modify: `seccomp_test.go`
- Modify: `README.md`

- [ ] **Step 1: Write the failing test**

Add assertions in `seccomp_test.go` that the baseline profile now includes `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, and `kcmp`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestBuiltInSeccompProfiles -count=1`
Expected: FAIL because the baseline profile does not yet contain the new rules.

- [ ] **Step 3: Write minimal implementation**

Move those syscall denials into `baselineSeccompRuleSpecs` and keep `restricted` focused on seccomp-installation restrictions.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestBuiltInSeccompProfiles -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add seccomp.go seccomp_test.go README.md
git commit -m "fix: harden baseline seccomp defaults"
```

### Task 2: Bind Transparent HTTPS Authorization To Upstream Authority

**Files:**
- Modify: `internal/helperproto/messages.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `manager.go`
- Modify: `manager_test.go`
- Modify: `integration/transparent_https_test.go`

- [ ] **Step 1: Write the failing tests**

Add a unit test showing that a MITM request is denied when the request host disagrees with the upstream authority, and an integration test proving transparent HTTPS rejects an SNI/`Host` mismatch.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestProxyManagerMITMRejectsHostAuthorityMismatch|TestTransparentHTTPSRejectsAuthorityMismatch' -count=1`
Expected: FAIL because the mismatch is currently accepted.

- [ ] **Step 3: Write minimal implementation**

Carry the real upstream host/authority through the helper MITM request, validate it in the manager, and reject mismatches before dialing upstream.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestProxyManagerMITMRejectsHostAuthorityMismatch|TestTransparentHTTPSRejectsAuthorityMismatch' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/helperproto/messages.go internal/helperruntime/runtime.go manager.go manager_test.go integration/transparent_https_test.go
git commit -m "fix: bind transparent https policy to authority"
```

### Task 3: Cap Proxy And MITM Buffering

**Files:**
- Modify: `types.go`
- Modify: `api.go`
- Modify: `manager.go`
- Modify: `internal/helperruntime/runtime.go`
- Modify: `manager_test.go`
- Modify: `README.md`

- [ ] **Step 1: Write the failing tests**

Add tests that large proxy request bodies, large MITM request bodies, and large upstream responses now fail deterministically under default limits.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run 'TestProxyManagerRejectsOversizedResponseBody|TestHandleProxyRequestRejectsOversizedRequestBody|TestProxyManagerUsesDefaultBodyLimits' -count=1`
Expected: FAIL because the runtime still buffers bodies without effective defaults.

- [ ] **Step 3: Write minimal implementation**

Add default body size limits to manager options, teach the helper to enforce request caps for proxy and MITM flows, and teach the manager to bound response body reads.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestProxyManagerRejectsOversizedResponseBody|TestHandleProxyRequestRejectsOversizedRequestBody|TestProxyManagerUsesDefaultBodyLimits' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add types.go api.go manager.go internal/helperruntime/runtime.go manager_test.go README.md
git commit -m "fix: cap sandbox proxy body buffering"
```

### Task 4: Final Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run focused coverage**

Run: `go test ./... -run 'TestBuiltInSeccompProfiles|TestProxyManagerMITMRejectsHostAuthorityMismatch|TestTransparentHTTPSRejectsAuthorityMismatch|TestProxyManagerRejectsOversizedResponseBody|TestHandleProxyRequestRejectsOversizedRequestBody|TestProxyManagerUsesDefaultBodyLimits' -count=1`
Expected: PASS

- [ ] **Step 2: Run full test suite**

Run: `go test ./...`
Expected: PASS, or clearly identified environment-dependent integration skips only

- [ ] **Step 3: Commit final docs touch-ups if needed**

```bash
git add README.md
git commit -m "docs: describe sandbox hardening changes"
```
