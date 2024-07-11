NAME = xray

VERSION=$(shell git describe --always --dirty)

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

LDFLAGS = -X github.com/xtls/xray-core/core.build=$(VERSION) -s -w -buildid=
PARAMS = -trimpath -ldflags "$(LDFLAGS)" -v
MAIN = ./main
PREFIX ?= $(shell go env GOPATH)
ifeq ($(GOOS),windows)
OUTPUT = $(NAME).exe
ADDITION = go build -o w$(NAME).exe -trimpath -ldflags "-H windowsgui $(LDFLAGS)" -v $(MAIN)
else
OUTPUT = $(NAME)
endif
ifeq ($(shell echo "$(GOARCH)" | grep -Eq "(mips|mipsle)" && echo true),true) # 
ADDITION = GOMIPS=softfloat go build -o $(NAME)_softfloat -trimpath -ldflags "$(LDFLAGS)" -v $(MAIN)
endif
.PHONY: clean build

build:
	go build -o $(OUTPUT) $(PARAMS) $(MAIN)
	$(ADDITION)

clean:
	go clean -v -i $(PWD)
	rm -f xray xray.exe wxray.exe xray_softfloat
