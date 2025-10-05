.PHONY: build build-pgo build-release install dev profile pgo-prepare clean test test-verbose test-coverage bench fmt vet tidy version help

# Build variables
BINARY_NAME=lc
PGO_PROFILE=default.pgo
PROFILE_DATA=cpu.prof

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

# Standard build
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)

# Build with Profile-Guided Optimization
build-pgo: $(PGO_PROFILE)
	@echo "Building $(BINARY_NAME) $(VERSION) with PGO..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -pgo=$(PGO_PROFILE) -o $(BINARY_NAME)

# Build release (optimized, stripped)
build-release:
	@echo "Building release $(BINARY_NAME) $(VERSION)..."
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS) -s -w" -o $(BINARY_NAME)

# Install to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME) $(VERSION)..."
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)"

# Quick dev build without version info
dev:
	@echo "Building development version..."
	$(GO) build -o $(BINARY_NAME)

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
	$(GO) test ./...

# Run tests with verbose output
test-verbose:
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Run benchmarks and generate profile
bench:
	$(GO) test -bench=. -cpuprofile=$(PROFILE_DATA) -memprofile=mem.prof ./...

# Format code
fmt:
	$(GO) fmt ./...

# Run go vet
vet:
	$(GO) vet ./...

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

# Help
help:
	@echo "lippycat Makefile - Current version: $(VERSION)"
	@echo ""
	@echo "Build targets:"
	@echo "  make build          - Build with version info"
	@echo "  make build-release  - Build optimized release binary"
	@echo "  make build-pgo      - Build with Profile-Guided Optimization"
	@echo "  make install        - Install to GOPATH/bin"
	@echo "  make dev            - Quick build without version info"
	@echo ""
	@echo "Development:"
	@echo "  make test           - Run tests"
	@echo "  make test-verbose   - Run tests with verbose output"
	@echo "  make test-coverage  - Generate coverage report"
	@echo "  make bench          - Run benchmarks"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
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
	@echo "  make version        - Show version information"
	@echo "  make help           - Show this help message"
