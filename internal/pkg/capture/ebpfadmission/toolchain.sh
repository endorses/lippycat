#!/usr/bin/env bash
# Build-time generation and isolated privileged kernel tests. No host BPF changes.
set -euo pipefail
package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$package_dir/../../../.." && pwd)
image=lippycat-ebpf-toolchain:local
mode=${1:-test}
case "$mode" in generate|test) ;; *) echo 'usage: toolchain.sh [generate|test]' >&2; exit 2;; esac
docker build -t "$image" "$package_dir"
arguments=(--rm -v "$(go env GOROOT):/usr/local/go:ro" -v "$(go env GOMODCACHE):/gomod:ro"
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/gomod -e GOTOOLCHAIN=local
  -e PATH=/usr/local/go/bin:/usr/bin:/bin -e CC=clang-18 -e GOFLAGS=-mod=readonly)
if [[ "$mode" == generate ]]; then
  docker run "${arguments[@]}" --user "$(id -u):$(id -g)" -v "$project_dir:/work" \
    -w /work/internal/pkg/capture/ebpfadmission -e BPF2GO_CFLAGS=-I/usr/include/x86_64-linux-gnu \
    "$image" go generate .
else
  docker run "${arguments[@]}" --privileged -v "$project_dir:/work:ro" -w /work \
    -e LIPPYCAT_EBPF_TEST=1 "$image" go test -count=1 -v ./internal/pkg/capture/ebpfadmission
fi
