# NOTE: This MAKEFILE can be used to build Xray-core locally and in Automatic workflows. It is \
	provided for convenience in automatic building and functions as a part of it.
# NOTE: If you need to modify this file, please be aware that:\
	- This file is not the main Makefile; it only accepts environment variables and builds the \
	binary.\
	- Automatic building expects the correct binaries to be built by this Makefile. If you \
	intend to propose a change to this Makefile, carefully review the file below and ensure \
	that the change will not accidentally break the automatic building:\
		.github/workflows/release.yml \
	Otherwise it is recommended to contact the project maintainers.

# Define the name of the output binary
NAME = xray

# Define the version using the latest git commit description
VERSION = $(shell git describe --always --dirty)

# Linker flags and build parameters
LDFLAGS = -X github.com/xtls/xray-core/core.build=$(VERSION) -s -w -buildid=
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v

# Main package to build
MAIN = ./main

# Determine the output file name based on the OS
ifeq ($(GOOS),windows)
	OUTPUT = $(NAME).exe
	WXOUTPUT = w$(NAME).exe
else
	OUTPUT = $(NAME)
endif

# Handle MIPS architectures separately
ifeq ($(GOARCH),mips)
	OUTPUT = $(NAME)_softfloat
endif

# Phony targets to avoid conflicts with files named 'clean', 'build', 'test', or 'deps'
.PHONY: clean build test deps

# Install dependencies
deps:
	go mod download

# Build target to compile the binary
build: deps
	go build -o $(OUTPUT) $(PARAMS) $(MAIN)
ifneq ($(WXOUTPUT),)
	go build -o $(WXOUTPUT) $(PARAMS) $(MAIN)
endif
ifeq ($(GOARCH),mips)
	GOMIPS=softfloat go build -o $(NAME)_softfloat $(PARAMS) $(MAIN)
endif

# Run tests
test:
	go test ./...

# Clean target to remove generated files
clean:
	go clean -v -i $(PWD)
	rm -f $(NAME) $(NAME).exe w$(NAME).exe $(NAME)_softfloat

# Default target
default: build
