.PHONY: build build-pgo profile clean test bench

# Build variables
BINARY_NAME=lippycat
PGO_PROFILE=default.pgo
PROFILE_DATA=cpu.prof

# Standard build
build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME)

# Build with Profile-Guided Optimization
build-pgo: $(PGO_PROFILE)
	@echo "Building $(BINARY_NAME) with PGO..."
	go build -pgo=$(PGO_PROFILE) -o $(BINARY_NAME)

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
	go test ./...

# Run benchmarks and generate profile
bench:
	go test -bench=. -cpuprofile=$(PROFILE_DATA) -memprofile=mem.prof ./...

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f $(PGO_PROFILE)
	rm -f $(PROFILE_DATA)
	rm -f mem.prof

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Standard build"
	@echo "  build-pgo   - Build with Profile-Guided Optimization (requires default.pgo)"
	@echo "  profile     - Instructions for generating production profile"
	@echo "  pgo-prepare - Convert cpu.prof to default.pgo"
	@echo "  test        - Run tests"
	@echo "  bench       - Run benchmarks and generate profiles"
	@echo "  clean       - Remove build artifacts"
	@echo ""
	@echo "PGO Workflow:"
	@echo "  1. make build          # Build standard binary"
	@echo "  2. Run realistic workload with profiling enabled"
	@echo "  3. make pgo-prepare    # Convert profile to PGO format"
	@echo "  4. make build-pgo      # Build optimized binary"
