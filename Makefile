gen:
	@echo "Installing protobuf..."
	@brew install protobuf || true
	@echo "Installing protoc-gen-go and protoc-gen-go-grpc..."
	@go install -v google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Generating independent API client module (only generates required files)..."
	@cd api-client && ./generate.sh || echo "Note: generate.sh may need manual execution"
	@echo "Formatting API client code only..."
	@go install -v github.com/daixiang0/gci@latest || true
	@go install -v mvdan.cc/gofumpt@latest || true
	@find api-client -name "*.go" ! -name "*.pb.go" ! -path "*/generated/*" -type f -exec gofumpt -s -l -e -w {} \; 2>/dev/null || true
	@find api-client -name "*.go" ! -name "*.pb.go" ! -path "*/generated/*" -type f -exec gci write {} \; 2>/dev/null || true
	@echo "Building API client..."
	@if [ -f api-client/main.go ]; then \
		cd api-client && go build -o xray-api-client .; \
	else \
		echo "Note: api-client/main.go not found, skipping build"; \
	fi
	@echo "Done! Independent API client is ready in api-client/"

