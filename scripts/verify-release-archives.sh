#!/bin/sh
set -eu

native_arch=""

usage() {
  echo "usage: $0 [--run-native amd64|arm64] linux_amd64 [linux_arm64 ...]" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --run-native)
      [ $# -ge 2 ] || usage
      native_arch="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage
      ;;
    *)
      break
      ;;
  esac
done

[ $# -gt 0 ] || usage

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

expect_members() {
  archive="$1"
  members="$(tar -tzf "$archive" | sort)"
  expected="$(printf '%s\n' bbox bbox-helper bbox-seccomp-launcher)"
  if [ "$members" != "$expected" ]; then
    echo "unexpected archive contents for $archive" >&2
    echo "got:" >&2
    printf '%s\n' "$members" >&2
    echo "want:" >&2
    printf '%s\n' "$expected" >&2
    exit 1
  fi
}

expect_file_arch() {
  path="$1"
  arch="$2"
  info="$(file "$path")"
  case "$arch" in
    amd64)
      printf '%s' "$info" | grep -Eq 'x86-64|x86_64' || {
        echo "expected amd64 binary for $path, got: $info" >&2
        exit 1
      }
      ;;
    arm64)
      printf '%s' "$info" | grep -Eq 'aarch64|ARM aarch64' || {
        echo "expected arm64 binary for $path, got: $info" >&2
        exit 1
      }
      ;;
    *)
      echo "unsupported arch check: $arch" >&2
      exit 1
      ;;
  esac
}

for target in "$@"; do
  archive="$(find dist -maxdepth 1 -type f -name "bbox_*_${target}.tar.gz" | head -n 1)"
  [ -n "$archive" ] || {
    echo "missing archive for target $target" >&2
    exit 1
  }

  target_dir="$tmpdir/$target"
  mkdir -p "$target_dir"
  expect_members "$archive"
  tar -xzf "$archive" -C "$target_dir"

  arch="${target#linux_}"
  expect_file_arch "$target_dir/bbox" "$arch"
  expect_file_arch "$target_dir/bbox-helper" "$arch"
  expect_file_arch "$target_dir/bbox-seccomp-launcher" "$arch"

  if [ -n "$native_arch" ] && [ "$arch" = "$native_arch" ]; then
    "$target_dir/bbox" --help >/dev/null
  fi
done
