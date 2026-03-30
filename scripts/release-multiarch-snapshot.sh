#!/bin/sh
set -eu

exec env PROJECT_ROOT="${PWD}" go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish --config .goreleaser.release.yaml "$@"
