.PHONY: build build-debug build-all test test-coverage test-race test-short lint format clean install dev help deps check proto version run docker-build docker-run benchmark

# Default target
all: build

# Build variables
BINARY_NAME := xray
MAIN_PACKAGE := ./main
BUILD_DIR := build
COVERAGE_DIR := coverage

# Build flags (matching project's existing build process)
BUILD_FLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -buildid=
DEBUG_LDFLAGS := -buildid=

# Get git commit for version info
COMMIT := $(shell git describe --always --dirty)
VERSION_LDFLAGS := -X github.com/xtls/xray-core/core.build=$(COMMIT)

# Cross-compilation targets (matching their release workflow)
PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	linux/386 \
	linux/arm/v6 \
	linux/arm/v7 \
	linux/mips \
	linux/mipsle \
	windows/amd64 \
	windows/386

## Development Commands

# Build the project (production build matching their style)
build:
	@echo "Building Xray..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME) $(BUILD_FLAGS) -ldflags="$(VERSION_LDFLAGS) $(LDFLAGS)" -v $(MAIN_PACKAGE)
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build with debug information
build-debug:
	@echo "Building Xray with debug info..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME)-debug $(BUILD_FLAGS) -ldflags="$(VERSION_LDFLAGS) $(DEBUG_LDFLAGS)" -gcflags="-N -l" -v $(MAIN_PACKAGE)
	@echo "✅ Debug build complete: $(BUILD_DIR)/$(BINARY_NAME)-debug"

# Cross-platform builds (matching their release process)
build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		ARM=$$(echo $$platform | cut -d'/' -f3); \
		echo "Building for $$OS/$$ARCH$$ARM..."; \
		if [ "$$OS" = "windows" ]; then \
			EXT=".exe"; \
		else \
			EXT=""; \
		fi; \
		if [ "$$ARM" != "" ]; then \
			GOARM=$$(echo $$ARM | sed 's/v//'); \
			GOOS=$$OS GOARCH=$$ARCH GOARM=$$GOARM CGO_ENABLED=0 go build \
				-o $(BUILD_DIR)/$(BINARY_NAME)-$$OS-$$ARCH$$ARM$$EXT \
				$(BUILD_FLAGS) -ldflags="$(VERSION_LDFLAGS) $(LDFLAGS)" $(MAIN_PACKAGE); \
		else \
			GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 go build \
				-o $(BUILD_DIR)/$(BINARY_NAME)-$$OS-$$ARCH$$EXT \
				$(BUILD_FLAGS) -ldflags="$(VERSION_LDFLAGS) $(LDFLAGS)" $(MAIN_PACKAGE); \
		fi; \
		if [ $$? -eq 0 ]; then \
			echo "✅ Built $(BUILD_DIR)/$(BINARY_NAME)-$$OS-$$ARCH$$ARM$$EXT"; \
		else \
			echo "❌ Failed to build for $$OS/$$ARCH$$ARM"; \
		fi; \
	done
	@echo "🎉 Cross-platform build complete!"

## Testing Commands

# Run all tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "📊 Coverage report: $(COVERAGE_DIR)/coverage.html"
	@go tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	go test -v -race ./...

# Run short tests only
test-short:
	@echo "Running short tests..."
	go test -v -short ./...

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./...

## Code Quality Commands

# Lint the code
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed. Install with: brew install golangci-lint"; \
		go vet ./...; \
	fi

# Format the code
format:
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "⚠️  goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# Run security checks
security:
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "⚠️  gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "⚠️  govulncheck not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

## Dependency Management

# Download and tidy dependencies
deps:
	@echo "Managing dependencies..."
	go mod download
	go mod tidy
	go mod verify

# Install development tools
install:
	@echo "Installing development tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "✅ Development tools installed"

## Utility Commands

# Show version information
version:
	@echo "Version Information:"
	@echo "Git Commit: $(COMMIT)"
	@echo "Go Version: $$(go version)"
	@if [ -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "Binary Version: $$( $(BUILD_DIR)/$(BINARY_NAME) version 2>/dev/null || echo 'Not available' )"; \
	fi

# Check code quality and run tests
check: format lint test
	@echo "🎉 All checks passed!"

# Development workflow: format, lint, test, build
dev: format lint test build
	@echo "🚀 Development build complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	@go clean -cache
	@go clean -testcache
	@echo "✅ Clean complete"

## Docker Commands

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t xray-core .

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run --rm -p 1080:1080 xray-core

## Protocol Buffer Commands (if needed)

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@if command -v protoc >/dev/null 2>&1; then \
		find . -name "*.proto" -exec protoc --go_out=. --go_opt=paths=source_relative {} \;; \
		echo "✅ Protobuf generation complete"; \
	else \
		echo "⚠️  protoc not installed. Please install Protocol Buffers compiler"; \
	fi

## Run Commands

# Run with default config (create if not exists)
run:
	@if [ ! -f "config.json" ]; then \
		echo "Creating default config.json..."; \
		echo '{"log":{"loglevel":"info"},"inbounds":[{"tag":"socks","port":1080,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}' | jq . > config.json 2>/dev/null || echo '{"log":{"loglevel":"info"},"inbounds":[{"tag":"socks","port":1080,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}' > config.json; \
	fi
	@echo "Starting Xray with config.json..."
	@if [ -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		$(BUILD_DIR)/$(BINARY_NAME) -config config.json; \
	else \
		echo "❌ Binary not found. Run 'make build' first."; \
	fi

# Help target
help:
	@echo "🚀 Xray-core Development Makefile"
	@echo ""
	@echo "📦 Build Commands:"
	@echo "  build         - Build production binary"
	@echo "  build-debug   - Build with debug symbols"
	@echo "  build-all     - Cross-platform builds for all targets"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo "  test          - Run all tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  test-race     - Run tests with race detection"
	@echo "  test-short    - Run short tests only"
	@echo "  benchmark     - Run benchmark tests"
	@echo ""
	@echo "🔍 Code Quality:"
	@echo "  lint          - Lint code with golangci-lint"
	@echo "  format        - Format code with go fmt and goimports"
	@echo "  security      - Run security checks (gosec, govulncheck)"
	@echo "  check         - Run format, lint, and test"
	@echo ""
	@echo "📚 Dependencies:"
	@echo "  deps          - Download and tidy dependencies"
	@echo "  install       - Install development tools"
	@echo ""
	@echo "🚀 Development:"
	@echo "  dev           - Full development workflow (format, lint, test, build)"
	@echo "  run           - Run Xray with default config"
	@echo "  version       - Show version information"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run in Docker container"
	@echo ""
	@echo "🧹 Utilities:"
	@echo "  clean         - Clean build artifacts and caches"
	@echo "  proto         - Generate protobuf files"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "💡 Quick start: make dev"
	@echo "🏗️  Production build: make build"
	@echo "🧪 Test everything: make check"