GO_CMD ?=go
BIN_NAME := xray
BUILD_OPTION := -trimpath -ldflags "-s -w -buildid=" -v ./main



build:
	${GO_CMD} build -o ${BIN_NAME} ${BUILD_OPTION}

install: build
	install -d /usr/local/bin/
	install -m 755 ./${BIN_NAME} /usr/local/bin/${BIN_NAME}

clean:
	rm -f ./${BIN_NAME}*



# Cross compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ${GO_CMD} build -o ${BIN_NAME} ${BUILD_OPTION}

build-osx:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 ${GO_CMD} build -o ${BIN_NAME}_osx ${BUILD_OPTION}

build-win:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ${GO_CMD} build -o ${BIN_NAME}.exe ${BUILD_OPTION}

build-all: build-linux build-osx build-win

help: 
	@sed -nr "s/^([a-z\-]*):(.*)/\1/p" Makefile

.PHONY: build install clean build-linux build-osx build-win build-all
