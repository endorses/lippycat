#!/bin/bash
# Build script for CUDA-enabled lippycat

set -e

echo "=== Building CUDA kernels ==="
cd internal/pkg/voip
make -f Makefile.cuda clean
make -f Makefile.cuda
cd ../../..

echo "=== Building Go binary with CUDA support ==="
# Build with CUDA tag
CGO_ENABLED=1 go build -tags cuda -o lippycat-cuda

echo "=== Build complete ==="
echo "Run with: ./lippycat-cuda"
echo ""
echo "To build without CUDA:"
echo "  go build -o lippycat"