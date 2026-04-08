# bbox --config Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--config` flag to `bbox` that loads an explicit config file and disables upward discovery for that invocation.

**Architecture:** Keep config loading in `cmd/bbox` and reuse the existing YAML loader. Introduce a small selector that chooses explicit config loading when `--config` is set and otherwise preserves current `bbox.yaml` discovery, then keep the existing defaults < file < flags < `--audit` merge order intact.

**Tech Stack:** Go, Cobra, `go test`, existing `cmd/bbox` config helpers

---

### Task 1: Add Explicit Config Selection Tests

**Files:**
- Modify: `cmd/bbox/config_test.go`
- Modify: `cmd/bbox/main_test.go`

- [ ] **Step 1: Write the failing test for explicit config selection**

Add a test in `cmd/bbox/config_test.go` that builds a discovered `bbox.yaml` and a separate explicit config file, then asserts the explicit file wins.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `go test ./cmd/bbox -run 'TestLoadEffectiveCLIConfigUsesExplicitConfigPath' -count=1`
Expected: FAIL because the CLI cannot select an explicit config file yet.

- [ ] **Step 3: Write the failing error-path tests**

Add tests for a missing explicit config path and for a directory passed through `--config`.

- [ ] **Step 4: Run the focused tests to verify they fail**

Run: `go test ./cmd/bbox -run 'TestLoadEffectiveCLIConfigUsesExplicitConfigPath|TestLoadEffectiveCLIConfigExplicitPathErrorsWhenMissing|TestLoadEffectiveCLIConfigExplicitPathErrorsForDirectory' -count=1`
Expected: FAIL because the selector does not exist yet.

- [ ] **Step 5: Write the CLI override test**

Add a test in `cmd/bbox/main_test.go` that uses `--config` plus a changed CLI flag and asserts the flag still overrides the loaded file value.

- [ ] **Step 6: Run the focused test to verify it fails**

Run: `go test ./cmd/bbox -run 'TestRootCommandConfigFlagLoadsExplicitConfigAndStillAllowsFlagOverrides' -count=1`
Expected: FAIL because `--config` is not registered yet.

### Task 2: Implement Explicit Config Loading

**Files:**
- Modify: `cmd/bbox/root_command.go`
- Modify: `cmd/bbox/effective_config.go`
- Modify: `cmd/bbox/config_file.go`

- [ ] **Step 1: Write the minimal implementation**

Add `cliOptions.configPath`, register `--config`, and implement a helper that resolves and loads an explicit config path when present or falls back to discovery when absent.

- [ ] **Step 2: Run the focused tests to verify they pass**

Run: `go test ./cmd/bbox -run 'TestLoadEffectiveCLIConfigUsesExplicitConfigPath|TestLoadEffectiveCLIConfigExplicitPathErrorsWhenMissing|TestLoadEffectiveCLIConfigExplicitPathErrorsForDirectory|TestRootCommandConfigFlagLoadsExplicitConfigAndStillAllowsFlagOverrides' -count=1`
Expected: PASS

### Task 3: Final Verification

**Files:**
- Modify: `cmd/bbox/config_test.go`
- Modify: `cmd/bbox/main_test.go`

- [ ] **Step 1: Run targeted bbox CLI tests**

Run: `go test ./cmd/bbox -count=1`
Expected: PASS

- [ ] **Step 2: Run full verification**

Run: `go test ./...`
Expected: PASS
