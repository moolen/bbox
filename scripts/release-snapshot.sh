#!/bin/sh
set -eu

goarch="${GOARCH:-$(go env GOARCH)}"
config=".goreleaser.yaml"

case "$goarch" in
  amd64)
    config=".goreleaser.yaml"
    ;;
  arm64)
    config=".goreleaser.arm64.yaml"
    ;;
  *)
    echo "unsupported local release architecture: $goarch" >&2
    exit 1
    ;;
esac

exec go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish --config "$config" "$@"

