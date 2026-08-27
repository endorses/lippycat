#!/usr/bin/env bash
set -euo pipefail

readonly role_tags=(all hunter processor tap cli tui)

echo '==> building supported non-CUDA binaries'
go build -tags all .
go build -tags 'all,li' .

echo '==> testing supported package partitions'
for tags in "${role_tags[@]}"; do
    go test -tags "$tags" ./...
done
go test -tags li ./internal/pkg/li/...

echo '==> vetting supported package partitions'
for tags in "${role_tags[@]}"; do
    go vet -tags "$tags" ./...
done
go vet -tags li ./internal/pkg/li/...

if [[ "${CUDA:-0}" == 1 ]]; then
    echo '==> building CUDA variants'
    CGO_ENABLED=1 go build -tags 'all,cuda' .
    CGO_ENABLED=1 go build -tags 'tap,li,cuda' .
else
    echo '==> skipping CUDA link builds (set CUDA=1 on a configured CUDA builder)'
fi
