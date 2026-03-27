# Proxy Listen Address Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add host proxy listen-address configuration while ensuring each sandbox exports the helper-reported proxy address instead of a hardcoded default, and document the CONNECT behavior.

**Architecture:** Extend `ProxyOptions` with a `ListenAddr` field, validate/default it in the manager constructor, and persist the effective address in the manager for helper startup. Keep the sandbox-side environment dynamic by assembling the proxy env after helper readiness using the `Ready.ProxyAddr` value. Update README language so CONNECT support and bind-address configuration are accurately documented without widening scope into MITM or protocol interception.

**Tech Stack:** Go, bubblewrap, standard library networking and testing

---

### Task 1: Constructor and Sandbox Contract Tests

**Files:**
- Modify: `api_test.go`
- Modify: `sandbox_test.go`

- [ ] **Step 1: Write the failing constructor test**

Add a test proving `NewProxyManager(ProxyOptions{ListenAddr: "127.0.0.1:0"})` succeeds and records the configured listen address.

- [ ] **Step 2: Run the constructor test to verify it fails**

Run: `go test ./... -run 'TestNewProxyManagerAcceptsListenAddr|TestSandbox'`
Expected: FAIL because `ProxyOptions.ListenAddr` and manager state do not exist yet.

- [ ] **Step 3: Write the failing sandbox env test**

Add a unit test proving the sandbox run env uses a helper-reported proxy address rather than the old constant.

- [ ] **Step 4: Run the sandbox test to verify it fails**

Run: `go test ./... -run 'TestNewProxyManagerAcceptsListenAddr|TestSandboxUsesHelperReportedProxyEnv'`
Expected: FAIL because the sandbox still bakes in `127.0.0.1:31111`.

### Task 2: Minimal Implementation

**Files:**
- Modify: `types.go`
- Modify: `api.go`
- Modify: `manager.go`
- Modify: `sandbox.go`
- Modify: `helper_client.go`
- Modify: `mounts.go`

- [ ] **Step 1: Add `ProxyOptions.ListenAddr` and defaulting**

Introduce the option, keep the default `127.0.0.1:31111`, and store the effective listen address on `ProxyManager`.

- [ ] **Step 2: Thread the configured listen address into helper startup**

Ensure helper startup receives the manager-configured listen address and that the helper-reported `Ready.ProxyAddr` remains the source of truth for sandbox runtime env.

- [ ] **Step 3: Move sandbox proxy env assembly behind helper readiness**

Replace the hardcoded env assembly with a helper-aware function so both `buildBwrapArgs` and runtime env generation can use a shared formatter.

- [ ] **Step 4: Run the targeted tests**

Run: `go test ./... -run 'TestNewProxyManagerAcceptsListenAddr|TestSandboxUsesHelperReportedProxyEnv'`
Expected: PASS

### Task 3: Documentation and Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Document CONNECT support, `AllowConnectPorts`, tunneling-only CONNECT behavior, and `ProxyOptions.ListenAddr`.

- [ ] **Step 2: Run full verification**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md api.go api_test.go docs/superpowers/plans/2026-03-27-proxy-listen-addr.md helper_client.go manager.go mounts.go sandbox.go sandbox_test.go types.go
git commit -m "feat: configure proxy listen address"
```
