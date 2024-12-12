NAME = xray
VERSION = $(shell git describe --always --dirty)

# NOTE: This Makefile is used to build Xray-core locally and in automatic workflows.
# Ensure that any modifications do not break the automatic building process.

LDFLAGS = -X github.com/xtls/xray-core/core.build=$(VERSION) -s -w -buildid=
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v
MAIN = ./main
PREFIX ?= $(shell go env GOPATH)

# Determine output filename based on the operating system
ifeq ($(GOOS),windows)
    OUTPUT = $(NAME).exe
    ADDITIONAL_BUILD_CMD = go build -o w$(NAME).exe -trimpath -ldflags "-H windowsgui $(LDFLAGS)" -v $(MAIN)
else
    OUTPUT = $(NAME)
endif

# Handle specific architecture builds (e.g., mips)
ifeq ($(GOARCH),mips)
    ADDITIONAL_BUILD_CMD = GOMIPS=softfloat go build -o $(NAME)_softfloat -trimpath -ldflags "$(LDFLAGS)" -v $(MAIN)
endif

.PHONY: clean build

build: 
	@echo "Building $(OUTPUT)..."
	go build -o $(OUTPUT) $(PARAMS) $(MAIN)
	@if [ ! -z "$(ADDITIONAL_BUILD_CMD)" ]; then \
		echo "Running additional build command..."; \
		$(ADDITIONAL_BUILD_CMD); \
	fi

clean:
	@echo "Cleaning up..."
	go clean -v -i $(PWD)
	rm -f xray xray.exe wxray.exe xray_softfloat
