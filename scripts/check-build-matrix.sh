#!/usr/bin/env bash
set -euo pipefail

readonly role_tags=(all hunter processor tap cli tui)
readonly li_tags=(all,li processor,li tap,li)
matrix_dir="$(mktemp -d)"
trap 'rm -rf -- "$matrix_dir"' EXIT

echo '==> building supported non-CUDA binaries'
for tags in "${role_tags[@]}" "${li_tags[@]}"; do
    go build -tags "$tags" -o "$matrix_dir/lippycat-$tags" .
done

echo '==> testing supported package partitions'
for tags in "${role_tags[@]}"; do
    # Compile all test packages without running integration tests. The latter
    # need loopback sockets and belong to the normal/integration test jobs.
    go test -run '^$' -tags "$tags" ./...
done
go test -run '^$' -tags li ./internal/pkg/li/...

echo '==> vetting supported package partitions'
for tags in "${role_tags[@]}"; do
    go vet -tags "$tags" ./...
done
for tags in "${li_tags[@]}"; do
    go vet -tags "$tags" ./...
done
go vet -tags li ./internal/pkg/li/...

if [[ "${CUDA:-0}" == 1 ]]; then
    echo '==> building CUDA variants'
    CGO_ENABLED=1 go build -tags 'all,cuda' -o "$matrix_dir/lippycat-all-cuda" .
    CGO_ENABLED=1 go build -tags 'all,li,cuda' -o "$matrix_dir/lippycat-all-li-cuda" .
    CGO_ENABLED=1 go build -tags 'tap,li,cuda' -o "$matrix_dir/lippycat-tap-li-cuda" .
    CGO_ENABLED=1 go test -tags 'all,cuda' ./internal/pkg/gpuaccel
    CGO_ENABLED=1 go vet -tags 'all,cuda' ./...
    CGO_ENABLED=1 go vet -tags 'all,li,cuda' ./...
    CGO_ENABLED=1 go vet -tags 'tap,li,cuda' ./...
else
    echo '==> skipping CUDA link builds (set CUDA=1 on a configured CUDA builder)'
fi
