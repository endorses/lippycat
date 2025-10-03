#!/bin/bash

set -e

# echo "=== Building CUDA kernels ==="
# cd internal/pkg/voip
# make -f Makefile.cuda clean
# make -f Makefile.cuda
# cd ../../..

echo "=== Building Go binary without debug symbols ==="
go build -ldflags="-s -w" -o lippycat
echo "=== Build complete ==="

echo "=== Compressing with upx ==="
upx --best --lzma lippycat
echo "=== Done ==="
