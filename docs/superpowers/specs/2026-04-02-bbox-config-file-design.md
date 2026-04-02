# bbox Config File Design

## Goal

Add `bbox.yaml` as the primary CLI configuration source, discovered by walking upward from the current directory, so users can define sandbox and policy behavior in a file instead of composing policy from flags.

## Scope

This change covers:

- config file discovery from the current directory upward
- flat YAML schema with a nested `policy:` section
- translation from file config into `bbox.ProxyOptions` and `bbox.SandboxOptions`
- removal of policy-shaping CLI flags
- removal of the `--mitm` CLI flag
- sane no-config defaults that audit traffic instead of denying it
- retention of `--audit` as a CLI override

This change does not cover:

- automatic staging of every binary on `$PATH`
- changes to the public library API

## User Experience

### Config Discovery

`bbox` should look for `bbox.yaml` in the current working directory. If it is not present there, it should walk up parent directories until it finds one or reaches the filesystem root. The first file found wins.

If no config file is found, `bbox` should continue with built-in defaults and not fail.

If a config file is found but cannot be parsed or contains invalid values, `bbox` should fail fast with a path-qualified error message.

### Precedence

Configuration precedence should be:

1. Built-in defaults
2. `bbox.yaml`
3. Supported CLI runtime flags
4. `--audit` as a final override for policy/reporting behavior

CLI flags that remain supported should override the config file directly. Removed flags should no longer exist.

### Default Behavior Without Config

When no `bbox.yaml` exists, the CLI should choose a UX-first default posture:

- empty `NetworkPolicy`
- `PolicyMode = audit`
- `Reporting.PolicyViolations = true`
- `Reporting.AccessSummary = true`
- `Reporting.RequestSummary = true`
- `TrafficMode = proxy`
- existing non-policy defaults remain unless explicitly changed elsewhere

This ensures a first run reports mediated network activity instead of denying it.

## YAML Schema

The config file should be flat for top-level runtime settings, with `policy:` as the only nested object.

Example:

```yaml
name: my-sandbox
workdir: .
bin:
  - node
mount_ro:
  - /etc/ssl/certs:/etc/ssl/certs
mount_rw:
  - .:/workspace
env:
  - FOO=bar
clear_env: false
traffic_mode: proxy
max_request_body_bytes: 65536
access_log: json
report_policy_violations: true
report_access_summary: true
report_request_summary: true

policy:
  allow_host_patterns:
    - "^api[.]openai[.]com$"
  deny_host_patterns:
    - "^metadata[.]google[.]internal$"
  allow_http_methods:
    - GET
    - POST
  allow_connect: true
  allow_connect_ports:
    - "443"
  allow_path_patterns:
    - "^/v1/.*$"
  deny_path_patterns:
    - "^/admin"
  allow_ip_cidrs: []
  deny_ip_cidrs: []
  allow_header_patterns: {}
  deny_header_patterns: {}
  allow_body_patterns: []
  deny_body_patterns: []
```

### Supported Top-Level Keys

- `name`
- `workdir`
- `bin`
- `mount_ro`
- `mount_rw`
- `env`
- `clear_env`
- `traffic_mode`
- `max_request_body_bytes`
- `access_log`
- `report_policy_violations`
- `report_access_summary`
- `report_request_summary`
- `policy`

### Supported Policy Keys

The `policy:` object should map directly onto `bbox.NetworkPolicy` using YAML-friendly snake_case names:

- `allow_host_patterns`
- `deny_host_patterns`
- `allow_ip_cidrs`
- `deny_ip_cidrs`
- `allow_http_methods`
- `allow_connect`
- `allow_connect_ports`
- `allow_path_patterns`
- `deny_path_patterns`
- `allow_header_patterns`
- `deny_header_patterns`
- `allow_body_patterns`
- `deny_body_patterns`

## CLI Surface Changes

The following flags should be removed:

- `--allowed-domain`
- `--allowed-domains-file`
- `--deny-domain`
- `--allow-http-method`
- `--allow-connect`
- `--allow-connect-port`
- `--allow-path`
- `--deny-path`
- `--policy-mode`
- `--mitm`

The following flag should remain:

- `--audit`

Existing non-policy runtime flags should remain and override config-file values where applicable, including:

- `--name`
- `--workdir`
- `--bin`
- `--mount-ro`
- `--mount-rw`
- `--env`
- `--clear-env`
- `--traffic-mode`
- reporting flags
- `--access-log`
- `--print-policy`

## Path Resolution

Relative paths from the config file should resolve relative to the directory containing the discovered `bbox.yaml`, not relative to the process launch directory.

This applies to:

- `workdir`
- `mount_ro` source/target entries when relative paths are allowed by the existing CLI rules
- `mount_rw` source/target entries when relative paths are allowed by the existing CLI rules

CLI flag values should continue to use current CLI semantics.

## MITM And Transparent Mode

Because `--mitm` is removed, transparent mode should imply MITM internally. The CLI should no longer require an explicit MITM switch to make transparent mode valid.

Proxy mode should also enable MITM internally for the CLI so that HTTPS mediation remains available without extra user configuration. This is a CLI default choice and does not require changing the library API or its validation rules.

## Architecture

Add a CLI-owned config loading layer in `cmd/bbox` with three responsibilities:

1. Discover `bbox.yaml`
2. Decode YAML into a flat CLI config struct
3. Merge defaults, file values, and CLI overrides into the existing `runConfig`

The existing library types should remain unchanged. The CLI remains responsible for translating config into:

- `bbox.ProxyOptions`
- `bbox.SandboxOptions`

This keeps library semantics stable while allowing the CLI to evolve independently.

### Proposed Internal Structure

- add a config discovery helper in `cmd/bbox`
- add YAML decoding helpers in `cmd/bbox`
- add merge helpers that combine defaults, file config, and CLI options
- simplify `buildConfig` so it no longer constructs policy from individual flags

The future `$PATH` binary auto-staging work should be treated as a separate follow-up and should plug into this same CLI translation layer.

## Error Handling

- Missing `bbox.yaml`: no error, use defaults
- Invalid YAML: fail with the config path in the error
- Invalid config values: fail with a descriptive validation error including the config path
- Invalid merged CLI plus file state: fail from existing config/build validation paths

## Testing

### Unit Tests

- config discovery finds `bbox.yaml` in the current directory
- config discovery finds `bbox.yaml` in a parent directory
- config discovery returns no file when none exists
- YAML decoding populates the flat config struct correctly
- relative path resolution uses the config directory
- merge order is defaults < file < CLI < `--audit`

### CLI Tests

- removed policy flags are no longer registered
- `--audit` still forces audit mode and reporting
- no-config execution defaults to audit mode instead of enforce
- config file policy values populate `NetworkPolicy`
- runtime flags override config file values
- `traffic_mode: transparent` succeeds without a `--mitm` flag

### Regression Coverage

- `--print-policy` shows the merged effective config
- proxy-mode HTTPS behavior still works with the CLI defaults
- empty or omitted `policy:` still results in audit-mode reporting rather than deny behavior

## Follow-Up

The next change after this implementation should be automatic staging of binaries from `$PATH`. That should be designed and implemented separately from the config-file work.
