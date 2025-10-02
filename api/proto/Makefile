# Makefile for generating Go code from protobuf definitions

# Protobuf compiler
PROTOC = protoc

# Protobuf files
PROTO_FILES = data.proto management.proto

# Output directory for generated Go files
OUT_DIR = ../gen

# Go package paths
DATA_PKG = github.com/endorses/lippycat/api/gen/data
MGMT_PKG = github.com/endorses/lippycat/api/gen/management

.PHONY: all clean check-deps

all: check-deps $(OUT_DIR)/data $(OUT_DIR)/management
	@echo "Generating Go code from protobuf definitions..."
	$(PROTOC) --go_out=$(OUT_DIR)/data --go_opt=paths=source_relative \
		--go-grpc_out=$(OUT_DIR)/data --go-grpc_opt=paths=source_relative \
		data.proto
	$(PROTOC) --go_out=$(OUT_DIR)/management --go_opt=paths=source_relative \
		--go-grpc_out=$(OUT_DIR)/management --go-grpc_opt=paths=source_relative \
		management.proto
	@echo "✅ Protobuf generation complete"

$(OUT_DIR)/data:
	mkdir -p $(OUT_DIR)/data

$(OUT_DIR)/management:
	mkdir -p $(OUT_DIR)/management

check-deps:
	@which protoc > /dev/null || (echo "❌ protoc not found. Install with: sudo apt install protobuf-compiler" && exit 1)
	@which protoc-gen-go > /dev/null || (echo "❌ protoc-gen-go not found. Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && exit 1)
	@which protoc-gen-go-grpc > /dev/null || (echo "❌ protoc-gen-go-grpc not found. Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" && exit 1)
	@echo "✅ All protobuf dependencies found"

clean:
	rm -rf $(OUT_DIR)/data/*.pb.go
	rm -rf $(OUT_DIR)/management/*.pb.go
	@echo "✅ Cleaned generated files"

install-deps:
	@echo "Installing protobuf dependencies..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "✅ Dependencies installed"
	@echo "Note: You still need to install protoc compiler:"
	@echo "  Ubuntu/Debian: sudo apt install protobuf-compiler"
	@echo "  Arch Linux: sudo pacman -S protobuf"
	@echo "  macOS: brew install protobuf"
