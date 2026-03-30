#!/bin/sh
set -eu

goreleaser_version="${GORELEASER_VERSION:-v2.12.0}"

exec env PROJECT_ROOT="${PWD}" go run github.com/goreleaser/goreleaser/v2@"$goreleaser_version" release --snapshot --clean --skip=publish --config .goreleaser.release.yaml "$@"
