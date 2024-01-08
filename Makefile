NAME = xray

VERSION=$(shell git describe --always --dirty)

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
ifeq ($(shell echo "$(GOARCH)" | grep -Pq "(mips|mipsle)" && echo true),true) # 
ADDITION = GOMIPS=softfloat go build -o $(NAME)_softfloat -trimpath -ldflags "$(LDFLAGS)" -v $(MAIN)
endif
.PHONY: clean

build:
	go build -o $(OUTPUT) $(PARAMS) $(MAIN)
	$(ADDITION)

install:
	go build -o $(PREFIX)/bin/$(OUTPUT) $(PARAMS) $(MAIN)

clean:
	go clean -v -i $(PWD)
	rm -f xray xray.exe wxray.exe xray_softfloat