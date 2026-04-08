# bbox --config Flag Design

## Goal

Add a `--config` flag to the `bbox` CLI so callers can point to a specific config file instead of relying on upward `bbox.yaml` discovery.

## Behavior

When `--config <path>` is provided, `bbox` should:

- skip upward config discovery entirely
- resolve `<path>` relative to the process working directory
- load that exact file with the existing YAML config loader
- resolve config-relative paths from the selected file's directory
- fail immediately if the path does not exist, is a directory, cannot be read, or cannot be decoded

When `--config` is not provided, existing upward discovery behavior should remain unchanged.

## Precedence

Config precedence stays:

1. built-in defaults
2. chosen config file
3. changed CLI flags
4. `--audit`

An explicit `--config` only changes how the config file is selected. It does not change merge semantics.

## Architecture

Keep the change narrow inside `cmd/bbox`.

- extend `cliOptions` with a `configPath` field
- register a root-level `--config` flag
- add a small helper that chooses between explicit config loading and existing discovery
- keep using `loadCLIFileConfig` so YAML decoding and config-relative path handling stay centralized

## Testing

Add focused coverage for:

- explicit config path wins over discovered `bbox.yaml`
- missing explicit config path returns an error
- explicit config path pointing at a directory returns an error
- CLI flags still override values loaded through `--config`
