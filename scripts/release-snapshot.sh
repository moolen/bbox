#!/bin/sh
set -eu

goarch="${GOARCH:-$(go env GOARCH)}"
config=".goreleaser.yaml"
goreleaser_version="${GORELEASER_VERSION:-v2.12.0}"

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

exec go run github.com/goreleaser/goreleaser/v2@"$goreleaser_version" release --snapshot --clean --skip=publish --config "$config" "$@"
