#!/usr/bin/env bash
# Isolated kernel, libpcap and command integration. Docker --privileged applies
# only to this disposable container; interfaces/maps are not created on the host.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/../.." && pwd)
toolchain_image=lippycat-ebpf-toolchain:local
go mod download
docker build -t "$toolchain_image" "$project_dir/internal/pkg/capture/ebpfadmission"
docker run --rm --privileged \
  -v "$(go env GOROOT):/usr/local/go:ro" \
  -v "$(go env GOMODCACHE):/gomod:ro" \
  -v "$project_dir:/work:ro" -w /work \
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/gomod -e GOTOOLCHAIN=local \
  -e PATH=/usr/local/go/bin:/usr/bin:/bin -e CC=clang-18 -e GOFLAGS=-mod=readonly \
  -e LIPPYCAT_EBPF_MEASURE="${LIPPYCAT_EBPF_MEASURE:-0}" \
  -e LIPPYCAT_EBPF_TEST=1 -e LIPPYCAT_EBPF_BINARY=/tmp/lc \
  "$toolchain_image" bash -euo pipefail -c '
    go build -tags all -o /tmp/lc .
    go test -count=1 -v ./internal/pkg/capture/ebpfadmission ./internal/pkg/capture/admissionintegration
    go test -tags all -count=1 -v ./test -run "^TestVoIPEBPF" -timeout 12m
  '
