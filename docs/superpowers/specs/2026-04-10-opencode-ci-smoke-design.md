# OpenCode CI Smoke Design

## Goal

Extend CI with a repo-owned smoke suite that installs `opencode`, runs it inside a Linux `bbox` sandbox, and proves the end-to-end launch path works across key bbox configuration permutations.

The expected outcome is a controlled `opencode` failure because CI does not provide model credentials. The suite should treat that missing-auth failure as success and treat sandbox/setup failures as regressions.

## Current State

The repository already has:

- a GitHub Actions CI workflow on `ubuntu-latest`
- Linux smoke coverage for `bbox` itself
- repo-owned shell scripts under `scripts/`
- CLI config support for:
  - `traffic_mode`
  - `policy_mode`
  - `copy_env`
  - explicit `env`
  - rootless in-sandbox `docker build`

There is no existing CI smoke coverage for running an external AI CLI such as `opencode` inside `bbox`.

## Requirements

### Functional

- CI must install `opencode`
- CI must build `./bin/bbox`
- the smoke suite must run `opencode run "<prompt>"` inside `bbox`
- the suite must cover multiple bbox config permutations rather than a single default case
- each case must reach `opencode` execution and fail because credentials are absent

### Classification

- a missing-auth, missing-credential, missing-API-key, missing-login, or provider-selection failure from `opencode` counts as success
- a successful `opencode` completion counts as failure because CI is not expected to have credentials
- bbox/config/runtime failures count as failure
- hangs count as failure

### CI Operability

- the orchestration should live in the repository rather than inline workflow YAML
- the workflow should stay thin and invoke a single repo-owned entrypoint
- failures must print enough per-case output to debug directly from CI logs

## Recommended Approach

Add a single shell entrypoint under `scripts/` and keep the workflow changes small.

The script should:

1. validate host prerequisites
2. create an isolated temp workspace and temp home per case
3. write a case-specific `bbox.yaml`
4. run `timeout ... ./bin/bbox -- opencode run "<prompt>"`
5. capture stdout/stderr
6. classify the result as:
   - expected auth failure
   - unexpected success
   - unexpected runtime/setup failure

This keeps the smoke behavior easy to run locally and avoids burying orchestration logic inside GitHub Actions YAML.

## Case Matrix

### 1. Proxy + Enforce + Copied PATH

- `traffic_mode: proxy`
- `policy_mode: enforce`
- `copy_env: ["PATH"]`

Purpose:

- prove baseline CLI resolution through copied host `PATH`
- prove the default bbox proxy-mode launch path works for `opencode`

### 2. Transparent + Enforce + Explicit Env

- `traffic_mode: transparent`
- `policy_mode: enforce`
- explicit `env` entries for:
  - `PATH`
  - `HOME`

Purpose:

- prove `opencode` launches without relying on `copy_env`
- exercise the transparent-mode sandbox path with the same payload

### 3. Proxy + Audit + Copied PATH

- `traffic_mode: proxy`
- `policy_mode: audit`
- `copy_env: ["PATH"]`
- reporting left enabled

Purpose:

- exercise audit mode during a real external CLI launch
- ensure audit/reporting paths do not prevent `opencode` from reaching its expected auth failure

### 4. Proxy + Enforce + Docker Build Shim Enabled

- `traffic_mode: proxy`
- `policy_mode: enforce`
- `copy_env: ["PATH"]`
- `docker_build.enabled: true`
- explicit builder tool paths in config

Purpose:

- exercise the heavier sandbox path that stages the in-sandbox `docker` shim and rootless builder toolchain
- verify that enabling the docker-build path does not break unrelated payload execution such as `opencode`

### 5. Transparent + Audit + Explicit Env + Docker Build Shim Enabled

- `traffic_mode: transparent`
- `policy_mode: audit`
- explicit `env` entries for `PATH` and `HOME`
- `docker_build.enabled: true`
- explicit builder tool paths in config

Purpose:

- provide one maximal configuration to catch interactions between traffic mode, audit mode, explicit env injection, and builder-tool staging

## Prompt And Runtime Contract

The smoke prompt should stay short and deterministic, for example:

`Reply with exactly the word OK.`

The suite should not validate model output. The real contract is:

- `bbox` must start successfully
- `opencode` must start inside the sandbox
- `opencode` must attempt a real non-interactive run
- the run must terminate quickly with a credential/auth-related failure

Every case should run under a fixed timeout so CI cannot hang indefinitely.

## Output Classification

The script should inspect combined stdout/stderr with case-insensitive substring matching.

Treat as expected auth failure when output includes indicators such as:

- `auth`
- `credential`
- `api key`
- `login`
- `provider`
- `missing`

This matching should stay intentionally loose because upstream CLI wording can change.

Treat as hard failure when output indicates:

- bbox config parsing failed
- sandbox creation failed
- binary resolution failed
- rootless builder prerequisites are missing for a builder-enabled case
- the command timed out
- `opencode` exited successfully

## CI Workflow Changes

Keep `.github/workflows/ci.yml` narrow:

1. install Linux prerequisites
2. build `./bin/bbox`
3. install `opencode`
4. run the repo-owned smoke script

Builder-enabled cases require the same rootless build prerequisites already used elsewhere in the repository:

- `buildkitd`
- `buildctl`
- `runc`
- `podman`
- `newuidmap`
- `newgidmap`
- subordinate ID mappings for the current user

If GitHub-hosted Ubuntu does not provide those prerequisites reliably, the workflow should install them explicitly or the builder-enabled cases should be downgraded from required coverage. The default design assumes CI should hard-require them so this path remains exercised.

## Local Execution

The script should also be runnable locally on Linux after `./bin/bbox` is built.

Local behavior may skip builder-enabled cases when builder prerequisites are unavailable, but CI should treat those prerequisites as required and fail if they are missing.

## Testing Strategy

### Script-Level Verification

- run the smoke script locally against a built `./bin/bbox`
- confirm that each non-builder case reports an expected auth failure
- confirm that builder-enabled cases either pass under required prerequisites or fail clearly with missing-prerequisite diagnostics

### CI Verification

- wire the script into the existing Ubuntu CI job
- after merge or branch push, inspect the CI logs for:
  - per-case start markers
  - per-case classification
  - timeout-free completion

## Limitations

- the suite cannot assert an exact `opencode` error string because upstream wording can drift
- the suite proves launch, sandboxing, and error classification, not successful model execution
- builder-enabled cases depend on rootless BuildKit host prerequisites that may vary by CI image

These limitations are acceptable because the goal is smoke coverage for bbox-plus-opencode startup behavior, not provider integration testing.

## Acceptance Criteria

The change is complete when:

- CI installs `opencode`
- CI invokes a repo-owned `opencode` smoke script
- the script exercises the defined bbox configuration permutations
- every required case passes only when `opencode` fails for missing credentials
- the script fails fast on sandbox/setup regressions and hangs
- CI logs clearly identify which case failed and why
