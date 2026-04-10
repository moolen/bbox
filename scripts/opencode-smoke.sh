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
MODEL_ID=${OPENCODE_SMOKE_MODEL:-openai/gpt-4.1-mini}
SANDBOX_ROOT=${OPENCODE_SMOKE_SANDBOX_ROOT:-/workspace}

case_filter=${OPENCODE_SMOKE_CASES:-}
total_cases=0
passed_cases=0
skipped_cases=0

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
require_command "$OPENCODE_BIN"
require_command dirname
require_command mktemp
require_command awk
require_command grep
require_command tr
require_command sed

require_subid_mapping() {
  user_name=$(id -un)
  for path in /etc/subuid /etc/subgid; do
    [ -f "$path" ] || {
      echo "missing required subordinate id file: $path" >&2
      return 1
    }
    grep -q "^${user_name}:" "$path" || {
      echo "missing subordinate id entry for $user_name in $path" >&2
      return 1
    }
  done
}

write_executable() {
  path=$1
  contents=$2
  printf '%s' "$contents" >"$path"
  chmod 755 "$path"
}

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
  total_cases=$((total_cases + 1))

  echo "RUN $case_name"

  case_dir=$(mktemp -d)
  case_home="$case_dir/home"
  sandbox_home="$SANDBOX_ROOT/home"
  mkdir -p "$case_home/.config/opencode" "$case_home/.local/share/opencode"
  chmod 700 "$case_home"
  cat >"$case_home/.config/opencode/opencode.json" <<EOF
{
  "provider": {
    "openai": {
      "npm": "@ai-sdk/openai",
      "env": ["OPENAI_API_KEY"]
    }
  },
  "model": "$MODEL_ID"
}
EOF

  builder_paths=""
  if [ "$docker_build_enabled" = "true" ]; then
    if [ -z "${OPENCODE_SMOKE_SKIP_SUBID_CHECK:-}" ] && ! require_subid_mapping; then
      echo "SKIP missing subordinate id mapping for $case_name"
      rm -rf "$case_dir"
      return 0
    fi
    builder_tools_dir="$case_dir/builder-tools"
    mkdir -p "$builder_tools_dir"
    write_executable "$builder_tools_dir/buildkitd" '#!/bin/sh
exit 0
'
    write_executable "$builder_tools_dir/buildctl" '#!/bin/sh
exit 0
'
    write_executable "$builder_tools_dir/runc" '#!/bin/sh
exit 0
'
    write_executable "$builder_tools_dir/newuidmap" '#!/bin/sh
exit 0
'
    write_executable "$builder_tools_dir/newgidmap" '#!/bin/sh
exit 0
'
    write_executable "$builder_tools_dir/podman" '#!/bin/sh
set -eu
[ "$#" -ge 1 ] && [ "$1" = "unshare" ] || {
  echo "unexpected podman invocation: $*" >&2
  exit 64
}
shift
exec "$@"
'
    builder_paths="buildkitd=$builder_tools_dir/buildkitd
buildctl=$builder_tools_dir/buildctl
runc=$builder_tools_dir/runc
podman=$builder_tools_dir/podman
newuidmap=$builder_tools_dir/newuidmap
newgidmap=$builder_tools_dir/newgidmap
"
  fi

  bbox_config="$case_dir/bbox.yaml"
  {
    echo "name: $case_name"
    echo "workdir: $SANDBOX_ROOT"
    echo "traffic_mode: $traffic_mode"
    echo "policy_mode: $policy_mode"
    echo "mounts:"
    echo "  - type: bind"
    echo "    source: $case_dir"
    echo "    target: $SANDBOX_ROOT"
    echo "    read_only: false"
    echo "env:"
    echo "  - HOME=$sandbox_home"
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
    cd "$repo_root"
    "$timeout_bin" "$RUN_TIMEOUT" "$bbox_bin" --config "$bbox_config" -- "$OPENCODE_BIN" run --pure --print-logs --model "$MODEL_ID" "$PROMPT"
  ) >"$output_file" 2>&1 || status=$?

  output=$(cat "$output_file")
  output_lc=$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]')

  case "$output_lc" in
    *"loopback: failed rtm_newaddr: operation not permitted"*)
      echo "SKIP loopback setup unsupported: $case_name"
      skipped_cases=$((skipped_cases + 1))
      rm -rf "$case_dir"
      return 0
      ;;
  esac

  if [ "$status" -eq 124 ]; then
    echo "FAIL timeout: $case_name" >&2
    printf '%s\n' "$output" >&2
    rm -rf "$case_dir"
    exit 1
  fi

  case "$output_lc" in
    *auth*|*credential*|*"api key"*|*login*|*provider*|*missing*)
      echo "PASS expected auth failure: $case_name"
      passed_cases=$((passed_cases + 1))
      ;;
    *)
      if [ "$status" -eq 0 ]; then
        echo "FAIL unexpected success: $case_name" >&2
      else
        echo "FAIL unexpected runtime result: $case_name" >&2
      fi
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

if [ "$total_cases" -eq 0 ]; then
  echo "FAIL no opencode smoke cases selected" >&2
  exit 1
fi

if [ "$passed_cases" -eq 0 ]; then
  echo "FAIL all selected opencode smoke cases skipped" >&2
  exit 1
fi
