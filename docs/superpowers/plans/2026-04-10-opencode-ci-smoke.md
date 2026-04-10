# OpenCode CI Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repo-owned CI smoke suite that installs `opencode`, runs it inside `bbox` across key config permutations, and treats missing-credential failures as the expected success condition.

**Architecture:** Keep orchestration in a single shell script under `scripts/`, but make it testable from Go by supporting command-path and mode overrides that a Go test can drive with fake tools. Then wire the existing Ubuntu CI workflow to install prerequisites, install `opencode`, and invoke the script.

**Tech Stack:** Shell, Go tests, GitHub Actions, bbox CLI, bubblewrap, rootless BuildKit tooling

---

## File Structure

### Existing files to modify

- `.github/workflows/ci.yml`
  - Install any extra Linux prerequisites, install `opencode`, and run the repo-owned smoke entrypoint.

### New files to create

- `scripts/opencode-smoke.sh`
  - Real smoke runner that creates per-case temp workspaces/config, runs `bbox -- opencode run ...`, and classifies output.
- `opencode_smoke_test.go`
  - Go tests that execute the shell runner against fake `bbox`, `opencode`, and builder tools to verify classification and config coverage.

## Task 1: Write The Failing Smoke Runner Tests

**Files:**
- Create: `opencode_smoke_test.go`

- [ ] **Step 1: Add a test that proves the runner accepts expected auth failures**

```go
func TestOpenCodeSmokeAcceptsCredentialFailure(t *testing.T) {
	out := runSmokeScript(t, fakeCase{
		bboxBehavior: "auth-failure",
	})
	if !strings.Contains(out, "PASS expected auth failure") {
		t.Fatalf("expected auth-failure classification, got %q", out)
	}
}
```

- [ ] **Step 2: Add a test that proves unexpected success fails the script**

```go
func TestOpenCodeSmokeRejectsUnexpectedSuccess(t *testing.T) {
	err, out := runSmokeScriptExpectError(t, fakeCase{
		bboxBehavior: "success",
	})
	if err == nil || !strings.Contains(out, "unexpected success") {
		t.Fatalf("expected unexpected-success failure, err=%v out=%q", err, out)
	}
}
```

- [ ] **Step 3: Add a test that proves builder-enabled cases require tool paths**

```go
func TestOpenCodeSmokeBuilderCaseWritesDockerBuildConfig(t *testing.T) {
	out := runSmokeScript(t, fakeCase{
		bboxBehavior: "auth-failure",
		checkBuilderConfig: true,
	})
	if !strings.Contains(out, "proxy-enforce-docker-build") {
		t.Fatalf("expected builder case to run, got %q", out)
	}
}
```

- [ ] **Step 4: Run the focused tests to verify they fail**

Run: `go test . -run 'TestOpenCodeSmoke' -count=1`

Expected: FAIL because the script does not exist yet.

- [ ] **Step 5: Commit the red tests**

```bash
git add opencode_smoke_test.go
git commit -m "test: cover opencode smoke runner"
```

## Task 2: Implement The Repo-Owned Smoke Runner

**Files:**
- Create: `scripts/opencode-smoke.sh`
- Test: `opencode_smoke_test.go`

- [ ] **Step 1: Implement prerequisite checks and command overrides**

```sh
BBOX_BIN="${BBOX_BIN:-./bin/bbox}"
OPENCODE_BIN="${OPENCODE_BIN:-opencode}"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
```

- [ ] **Step 2: Implement per-case temp workspace creation and config rendering**

```sh
write_case_config() {
  case_name="$1"
  case_dir="$2"
  # Write bbox.yaml with traffic_mode, policy_mode, env/copy_env,
  # and docker_build settings when requested.
}
```

- [ ] **Step 3: Implement result classification**

```sh
case "$combined_output_lower" in
  *auth*|*credential*|*"api key"*|*login*|*provider*|*missing*)
    echo "PASS expected auth failure: $case_name"
    ;;
  *)
    echo "FAIL unexpected runtime result: $case_name" >&2
    exit 1
    ;;
esac
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test . -run 'TestOpenCodeSmoke' -count=1`

Expected: PASS

- [ ] **Step 5: Run the smoke script locally with fake tooling to verify the real entrypoint**

Run: `go test . -run 'TestOpenCodeSmoke' -count=1 -v`

Expected: PASS with per-case output visible in test logs

- [ ] **Step 6: Commit the runner implementation**

```bash
git add scripts/opencode-smoke.sh opencode_smoke_test.go
git commit -m "feat: add opencode smoke runner"
```

## Task 3: Wire The Smoke Runner Into CI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Test: `opencode_smoke_test.go`

- [ ] **Step 1: Add CI steps to install any missing rootless builder prerequisites and install `opencode`**

```yaml
- name: Install OpenCode
  run: npm install -g opencode-ai

- name: Run OpenCode smoke suite
  run: ./scripts/opencode-smoke.sh
```
```

- [ ] **Step 2: Keep the Ubuntu workflow building `./bin/bbox` before the smoke step**

```yaml
- name: Build bbox
  run: go build -o ./bin/bbox ./cmd/bbox
```

- [ ] **Step 3: Re-run the focused Go tests**

Run: `go test . -run 'TestOpenCodeSmoke' -count=1`

Expected: PASS

- [ ] **Step 4: Build the bbox CLI and run the smoke script in the real local environment**

Run: `go build -o ./bin/bbox ./cmd/bbox && ./scripts/opencode-smoke.sh`

Expected: non-builder cases reach expected auth-failure classification; builder cases either pass under installed prerequisites or fail with explicit missing-prerequisite diagnostics that guide the CI package list.

- [ ] **Step 5: Commit the CI wiring**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run opencode smoke suite"
```

## Task 4: Push, Observe CI, And Fix Follow-Up Issues

**Files:**
- Modify as needed based on CI results: `scripts/opencode-smoke.sh`, `.github/workflows/ci.yml`, `opencode_smoke_test.go`

- [ ] **Step 1: Push the feature branch**

```bash
git push -u origin feature/opencode-ci-smoke
```

- [ ] **Step 2: Inspect the GitHub Actions run and identify the first failing step if any**

Run: `git rev-parse --abbrev-ref HEAD`

Expected: `feature/opencode-ci-smoke`

- [ ] **Step 3: Apply the smallest fix that addresses the observed CI failure**

Typical fixes:
- install an additional Ubuntu package needed by builder-enabled cases
- adjust the `opencode` install command if upstream packaging differs
- widen auth-failure matching if the upstream CLI wording is valid but not yet recognized
- fix temp-home/env handling if `opencode` expects a different writable path

- [ ] **Step 4: Re-run local verification for the touched surface**

Run: `go test . -run 'TestOpenCodeSmoke' -count=1 && go build -o ./bin/bbox ./cmd/bbox`

Expected: PASS

- [ ] **Step 5: Commit each CI-driven fix and push again until the workflow is green**

```bash
git add <touched-files>
git commit -m "fix: stabilize opencode smoke ci"
git push
```
