.PHONY: build build-pgo build-release build-cuda cuda-kernels install install-system dev profile pgo-prepare clean clean-cuda test test-verbose test-coverage test-race bench fmt vet lint gosec gosec-verbose tidy version help all hunter processor cli tui tap binaries clean-binaries

# Build variables
BINARY_NAME=lc
CUDA_BINARY_NAME=lc-cuda
PGO_PROFILE=default.pgo
PROFILE_DATA=cpu.prof
CUDA_DIR=internal/pkg/voip

# Version information
# Try git tag first, then VERSION file, then git commit, finally "dev"
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || cat VERSION 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go build variables
GO = go
GOFLAGS = -trimpath
LDFLAGS = -X github.com/endorses/lippycat/internal/pkg/version.Version=$(VERSION) \
          -X github.com/endorses/lippycat/internal/pkg/version.GitCommit=$(GIT_COMMIT) \
          -X github.com/endorses/lippycat/internal/pkg/version.BuildDate=$(BUILD_DATE)

# Standard build (complete suite with all tags)
build:
	@echo "Building $(BINARY_NAME) $(VERSION) (complete suite)..."
	$(GO) build $(GOFLAGS) -tags all -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)

# Build complete suite (explicit all tag)
all:
	@echo "Building complete suite $(BINARY_NAME) $(VERSION)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags all -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)

# Build hunter-only binary (stripped, no metrics)
hunter:
	@echo "Building hunter binary $(VERSION) (stripped, minimal)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags hunter -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)-hunt

# Build processor-only binary (stripped, no metrics)
processor:
	@echo "Building processor binary $(VERSION) (stripped, minimal)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags processor -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)-process

# Build CLI-only binary (stripped, no metrics)
cli:
	@echo "Building CLI binary $(VERSION) (stripped, minimal)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags cli -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)-cli

# Build TUI-only binary (stripped, no metrics)
tui:
	@echo "Building TUI binary $(VERSION) (stripped, minimal)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags tui -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)-tui

# Build tap-only binary (standalone capture + processor capabilities)
tap:
	@echo "Building tap binary $(VERSION) (stripped, standalone capture)..."
	@mkdir -p bin
	$(GO) build $(GOFLAGS) -tags tap -ldflags "$(LDFLAGS) -s -w" -o bin/$(BINARY_NAME)-tap

# Build all binary variants
binaries: all hunter processor cli tui tap
	@echo "All binary variants built successfully:"
	@ls -lh bin/

# Build with Profile-Guided Optimization
build-pgo: $(PGO_PROFILE)
	@echo "Building $(BINARY_NAME) $(VERSION) with PGO..."
	$(GO) build $(GOFLAGS) -tags all -ldflags "$(LDFLAGS)" -pgo=$(PGO_PROFILE) -o $(BINARY_NAME)

# Build release (optimized, stripped)
build-release:
	@echo "Building release $(BINARY_NAME) $(VERSION)..."
	$(GO) build $(GOFLAGS) -tags all -ldflags "$(LDFLAGS) -s -w" -o $(BINARY_NAME)

# Build CUDA kernels
cuda-kernels:
	@echo "Building CUDA kernels..."
	cd $(CUDA_DIR) && $(MAKE) -f Makefile.cuda

# Build with CUDA support
build-cuda: cuda-kernels
	@echo "Building $(CUDA_BINARY_NAME) $(VERSION) with CUDA support..."
	CGO_ENABLED=1 $(GO) build $(GOFLAGS) -tags cuda -ldflags "$(LDFLAGS)" -o $(CUDA_BINARY_NAME)

# Install to GOPATH/bin or /usr/local/bin
install: build-release
	@echo "Installing $(BINARY_NAME) $(VERSION) to $(shell go env GOPATH)/bin/..."
	@mkdir -p $(shell go env GOPATH)/bin
	@cp $(BINARY_NAME) $(shell go env GOPATH)/bin/$(BINARY_NAME)
	@echo "Installed as: $(BINARY_NAME)"
	@echo "Make sure $(shell go env GOPATH)/bin is in your PATH"

# Install to system-wide location (requires sudo)
install-system: build-release
	@echo "Installing $(BINARY_NAME) $(VERSION) to /usr/local/bin/..."
	sudo cp $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed system-wide as: $(BINARY_NAME)"

# Quick dev build without version info
dev:
	@echo "Building development version..."
	$(GO) build -tags all -o $(BINARY_NAME)

# Generate CPU profile for PGO
# Run this with a realistic workload to capture production behavior
profile:
	@echo "Generating CPU profile..."
	@echo "Run your realistic workload, then the profile will be saved to $(PROFILE_DATA)"
	@echo "Example: ./$(BINARY_NAME) sniff -i eth0 & sleep 60 && pkill $(BINARY_NAME)"
	@echo "Then run: make pgo-prepare"

# Convert profile to PGO format
pgo-prepare: $(PROFILE_DATA)
	@echo "Converting profile to PGO format..."
	cp $(PROFILE_DATA) $(PGO_PROFILE)
	@echo "PGO profile ready. Run 'make build-pgo' to build with optimizations."

# Run tests
test:
	$(GO) test -tags all ./...

# Run tests with verbose output
test-verbose:
	$(GO) test -tags all -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -tags all -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Run tests with race detector
test-race:
	$(GO) test -tags all -race ./...

# Run benchmarks and generate profile
bench:
	$(GO) test -tags all -bench=. -cpuprofile=$(PROFILE_DATA) -memprofile=mem.prof ./...

# Format code
fmt:
	$(GO) fmt ./...

# Run go vet
vet:
	$(GO) vet ./...

# Security scanning with gosec (clean output, SSA errors filtered)
# The Golang SSA analysis errors are expected - see .gosec.yaml for details
lint: gosec

gosec:
	@echo "Running gosec security scan..."
	@gosec -tags=all -exclude-generated -quiet ./... 2>&1 | grep -v "^Golang errors" | grep -v "^\s*>" | grep -v "could not import" | grep -v "undefined:" | grep -v "missing function body" || true
	@echo ""
	@gosec -tags=all -exclude-generated ./... 2>&1 | tail -7

# Security scanning with full output (includes SSA analysis details)
gosec-verbose:
	@echo "Running gosec with full diagnostic output..."
	@echo "Note: Golang import errors are from gosec's SSA type checker,"
	@echo "      not actual build issues. See .gosec.yaml for details."
	@echo ""
	@gosec -tags=all -exclude-generated ./...

# Tidy modules
tidy:
	$(GO) mod tidy

# Show version info
version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f $(PGO_PROFILE)
	rm -f $(PROFILE_DATA)
	rm -f mem.prof
	rm -f coverage.out coverage.html
	$(GO) clean

# Clean all binary variants
clean-binaries:
	@echo "Cleaning all binary variants..."
	rm -rf bin/

# Clean CUDA artifacts
clean-cuda:
	@echo "Cleaning CUDA artifacts..."
	cd $(CUDA_DIR) && $(MAKE) -f Makefile.cuda clean
	rm -f $(CUDA_BINARY_NAME)

# Help
help:
	@echo "lippycat Makefile - Current version: $(VERSION)"
	@echo ""
	@echo "Build targets:"
	@echo "  make build          - Build complete suite (all commands)"
	@echo "  make build-release  - Build optimized release binary"
	@echo "  make build-pgo      - Build with Profile-Guided Optimization"
	@echo "  make build-cuda     - Build with CUDA GPU acceleration"
	@echo "  make cuda-kernels   - Build only CUDA kernels"
	@echo "  make dev            - Quick build without version info"
	@echo ""
	@echo "Binary variants (built to bin/ directory):"
	@echo "  make all            - Build complete suite (all commands)"
	@echo "  make hunter         - Build hunter node only"
	@echo "  make processor      - Build processor node only"
	@echo "  make cli            - Build CLI commands only"
	@echo "  make tui            - Build TUI interface only"
	@echo "  make tap            - Build tap node (standalone capture + processor)"
	@echo "  make binaries       - Build all variants"
	@echo ""
	@echo "Installation:"
	@echo "  make install        - Install to GOPATH/bin as 'lc'"
	@echo "  make install-system - Install to /usr/local/bin as 'lc' (requires sudo)"
	@echo ""
	@echo "Development:"
	@echo "  make test           - Run tests"
	@echo "  make test-verbose   - Run tests with verbose output"
	@echo "  make test-coverage  - Generate coverage report"
	@echo "  make test-race      - Run tests with race detector"
	@echo "  make bench          - Run benchmarks"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
	@echo "  make lint / gosec   - Run gosec security scanner (clean output)"
	@echo "  make gosec-verbose  - Run gosec with full diagnostic output"
	@echo "  make tidy           - Tidy module dependencies"
	@echo ""
	@echo "PGO Workflow:"
	@echo "  1. make build          - Build standard binary"
	@echo "  2. Run realistic workload with profiling"
	@echo "  3. make pgo-prepare    - Convert profile to PGO format"
	@echo "  4. make build-pgo      - Build optimized binary"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make clean-binaries - Remove all binary variants"
	@echo "  make clean-cuda     - Remove CUDA build artifacts"
	@echo "  make version        - Show version information"
	@echo "  make help           - Show this help message"
