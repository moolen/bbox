#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

fail() {
	echo "architecture check failed: $*" >&2
	exit 1
}

assert_pkg_does_not_depend_on() {
	local pkg=$1
	local dep=$2

	if go list -deps "$pkg" | grep -Fxq "$dep"; then
		fail "$pkg must not depend on $dep"
	fi
}

assert_direct_import_only_in() {
	local import_path=$1
	local expected_file=$2
	local actual

	actual=$(rg -l --glob '*.go' "\"$import_path\"" . | sort || true)
	if [[ "$actual" != "$expected_file" ]]; then
		fail "expected $import_path to be imported only by $expected_file, got: ${actual:-<none>}"
	fi
}

assert_pkg_does_not_depend_on github.com/moolen/bbox github.com/moolen/bbox/internal/dockerbuild
assert_pkg_does_not_depend_on github.com/moolen/bbox github.com/moolen/bbox/internal/helperentrypoint
assert_pkg_does_not_depend_on github.com/moolen/bbox github.com/moolen/bbox/internal/launcherentrypoint
assert_pkg_does_not_depend_on github.com/moolen/bbox/internal/dockerbuild github.com/moolen/bbox

assert_direct_import_only_in github.com/moolen/bbox/internal/dockerbuild ./cmd/bbox/main.go
assert_direct_import_only_in github.com/moolen/bbox/internal/helperentrypoint ./cmd/bbox/main.go
assert_direct_import_only_in github.com/moolen/bbox/internal/launcherentrypoint ./cmd/bbox/main.go

echo "architecture checks passed"
