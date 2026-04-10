#!/bin/sh
set -eu

repo_root=$(
  CDPATH= cd -- "$(dirname "$0")/.." && pwd
)

BBOX_BIN=${BBOX_BIN:-./bin/bbox}
OPENCODE_BIN=${OPENCODE_BIN:-opencode}
TIMEOUT_BIN=${TIMEOUT_BIN:-timeout}
PROMPT=${OPENCODE_SMOKE_PROMPT:-Reply with exactly the word OK.}
RUN_TIMEOUT=${OPENCODE_SMOKE_TIMEOUT:-90s}
MODEL_ID=${OPENCODE_SMOKE_MODEL:-openai/gpt-5}

case_filter=${OPENCODE_SMOKE_CASES:-}

resolve_repo_path() {
  path="$1"
  case "$path" in
    */* )
      CDPATH= cd -- "$repo_root" && CDPATH= cd -- "$(dirname "$path")" && printf '%s/%s\n' "$(pwd)" "$(basename "$path")"
      ;;
    * )
      command -v "$path"
      ;;
  esac
}

bbox_bin=$(resolve_repo_path "$BBOX_BIN")
timeout_bin=$(resolve_repo_path "$TIMEOUT_BIN")

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_path() {
  [ -x "$1" ] || {
    echo "required executable not found: $1" >&2
    exit 1
  }
}

require_path "$bbox_bin"
require_path "$timeout_bin"
require_command dirname
require_command mktemp
require_command awk
require_command tr
require_command sed

run_case() {
  case_name=$1
  traffic_mode=$2
  policy_mode=$3
  env_mode=$4
  docker_build_enabled=$5

  if [ -n "$case_filter" ]; then
    case ",$case_filter," in
      *,"$case_name",* ) ;;
      * ) return 0 ;;
    esac
  fi

  echo "RUN $case_name"

  case_dir=$(mktemp -d)
  case_home="$case_dir/home"
  mkdir -p "$case_home" "$case_home/.config/opencode" "$case_dir/.local/share/opencode" "$case_dir/.config/opencode"
  chmod 700 "$case_home"

  opencode_config="$case_dir/opencode.json"
  cat >"$opencode_config" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "$MODEL_ID"
}
EOF

  builder_paths=""
  if [ "$docker_build_enabled" = "true" ]; then
    for tool in buildkitd buildctl runc podman newuidmap newgidmap; do
      if ! tool_path=$(command -v "$tool" 2>/dev/null); then
        if [ -n "${CI:-}" ]; then
          echo "FAIL missing builder prerequisite for $case_name: $tool" >&2
          rm -rf "$case_dir"
          exit 1
        fi
        echo "SKIP missing builder prerequisite for $case_name: $tool"
        rm -rf "$case_dir"
        return 0
      fi
      builder_paths="${builder_paths}${tool}=${tool_path}
"
    done
  fi

  bbox_config="$case_dir/bbox.yaml"
  {
    echo "name: $case_name"
    echo "workdir: $case_dir"
    echo "traffic_mode: $traffic_mode"
    echo "policy_mode: $policy_mode"
    echo "mounts:"
    echo "  - type: bind"
    echo "    source: $case_dir"
    echo "    target: $case_dir"
    echo "    read_only: false"
    echo "env:"
    echo "  - HOME=$case_home"
    echo "  - OPENAI_API_KEY="
    echo "  - ANTHROPIC_API_KEY="
    echo "  - GEMINI_API_KEY="
    echo "  - GOOGLE_API_KEY="
    echo "  - OPENCODE_CONFIG=$opencode_config"
    if [ "$env_mode" = "copy" ]; then
      echo "copy_env:"
      echo "  - PATH"
    else
      echo "  - PATH=${PATH:-/usr/bin:/bin}"
    fi
    if [ "$docker_build_enabled" = "true" ]; then
      echo "docker_build:"
      echo "  enabled: true"
      printf '%s' "$builder_paths" | while IFS='=' read -r tool tool_path; do
        [ -n "$tool" ] || continue
        echo "  ${tool}_path: $tool_path"
      done
    fi
  } >"$bbox_config"

  output_file="$case_dir/output.log"
  status=0
  (
    cd "$case_dir"
    "$timeout_bin" "$RUN_TIMEOUT" "$bbox_bin" -- "$OPENCODE_BIN" run "$PROMPT"
  ) >"$output_file" 2>&1 || status=$?

  output=$(cat "$output_file")
  output_lc=$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]')

  if [ "$status" -eq 0 ]; then
    echo "FAIL unexpected success: $case_name" >&2
    printf '%s\n' "$output" >&2
    rm -rf "$case_dir"
    exit 1
  fi

  if [ "$status" -eq 124 ]; then
    echo "FAIL timeout: $case_name" >&2
    printf '%s\n' "$output" >&2
    rm -rf "$case_dir"
    exit 1
  fi

  case "$output_lc" in
    *auth*|*credential*|*"api key"*|*login*|*provider*|*missing*)
      echo "PASS expected auth failure: $case_name"
      ;;
    *)
      echo "FAIL unexpected runtime result: $case_name" >&2
      printf '%s\n' "$output" >&2
      rm -rf "$case_dir"
      exit 1
      ;;
  esac

  rm -rf "$case_dir"
}

run_case "proxy-enforce-copy-env" "proxy" "enforce" "copy" "false"
run_case "transparent-enforce-explicit-env" "transparent" "enforce" "explicit" "false"
run_case "proxy-audit-copy-env" "proxy" "audit" "copy" "false"
run_case "proxy-enforce-docker-build" "proxy" "enforce" "copy" "true"
run_case "transparent-audit-docker-build" "transparent" "audit" "explicit" "true"
